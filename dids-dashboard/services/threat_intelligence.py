"""
Threat Intelligence Service

Integrates with external threat intelligence feeds:
- IBM X-Force Exchange API
- AlienVault OTX (Open Threat Exchange) API

Provides IP reputation, URL analysis, malware hash lookup,
and threat indicators from multiple intelligence sources.
"""

import base64
import hashlib
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    """
    Service for querying external threat intelligence feeds.

    Supports:
    - IBM X-Force Exchange: IP reputation, URL analysis, malware hashes
    - AlienVault OTX: Pulse indicators, IP/domain reputation, file hashes
    """

    def __init__(self, config=None):
        """
        Initialize the Threat Intelligence Service.

        Args:
            config: Optional configuration object with API credentials
        """
        self.config = config

        # IBM X-Force credentials
        self.xforce_api_key = os.environ.get("XFORCE_API_KEY", "842c9565-1f2d-44d8-93b5-19c9e18cb6e1")
        self.xforce_api_password = os.environ.get("XFORCE_API_PASSWORD", "7667c28e-d88f-4db0-af77-cfe4ae806770")
        self.xforce_base_url = "https://api.xforce.ibmcloud.com"

        # AlienVault OTX credentials
        self.otx_api_key = os.environ.get("OTX_API_KEY", "7c7471b24cbd76b9ef0dbb5ba84b941e9f2b51337a6808dd57a9377ce5fea5a0")
        self.otx_base_url = "https://otx.alienvault.com/api/v1"

        # Cache for reducing API calls (TTL: 1 hour)
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl = 3600  # seconds

        # Rate limiting
        self._last_xforce_call = 0
        self._last_otx_call = 0
        self._rate_limit_delay = 1.0  # seconds between calls

        # Statistics
        self.stats = {
            "xforce_queries": 0,
            "otx_queries": 0,
            "cache_hits": 0,
            "malicious_ips_found": 0,
            "malicious_urls_found": 0,
            "malicious_hashes_found": 0,
        }

        # Known malicious indicators (local cache from feeds)
        self.malicious_ips: set = set()
        self.malicious_domains: set = set()
        self.malicious_hashes: set = set()

        logger.info("ThreatIntelligenceService initialized")
        self._log_api_status()

    def _log_api_status(self):
        """Log the status of configured APIs."""
        if self.xforce_api_key and self.xforce_api_password:
            logger.info("IBM X-Force Exchange API: Configured")
        else:
            logger.warning(
                "IBM X-Force Exchange API: Not configured "
                "(set XFORCE_API_KEY and XFORCE_API_PASSWORD)"
            )

        if self.otx_api_key:
            logger.info("AlienVault OTX API: Configured")
        else:
            logger.warning(
                "AlienVault OTX API: Not configured (set OTX_API_KEY)"
            )

    def _get_cache_key(self, provider: str, query_type: str, value: str) -> str:
        """Generate a cache key."""
        return f"{provider}:{query_type}:{value}"

    def _get_cached(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if not expired."""
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if time.time() - cached["timestamp"] < self._cache_ttl:
                self.stats["cache_hits"] += 1
                return cached["data"]
            else:
                del self._cache[cache_key]
        return None

    def _set_cached(self, cache_key: str, data: Dict[str, Any]):
        """Cache a result."""
        self._cache[cache_key] = {"timestamp": time.time(), "data": data}

    # =========================================================================
    # IBM X-Force Exchange API
    # =========================================================================

    def _xforce_request(
        self, endpoint: str, params: Dict[str, Any] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Make a request to IBM X-Force API.

        Args:
            endpoint: API endpoint path
            params: Optional query parameters

        Returns:
            JSON response or None on error
        """
        if not self.xforce_api_key or not self.xforce_api_password:
            logger.debug("X-Force API not configured, skipping request")
            return None

        # Rate limiting
        elapsed = time.time() - self._last_xforce_call
        if elapsed < self._rate_limit_delay:
            time.sleep(self._rate_limit_delay - elapsed)

        # Create basic auth header
        credentials = f"{self.xforce_api_key}:{self.xforce_api_password}"
        auth_header = base64.b64encode(credentials.encode()).decode()

        headers = {
            "Authorization": f"Basic {auth_header}",
            "Accept": "application/json",
        }

        url = f"{self.xforce_base_url}{endpoint}"

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            self._last_xforce_call = time.time()
            self.stats["xforce_queries"] += 1

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                logger.error("X-Force API authentication failed")
            elif response.status_code == 404:
                logger.debug(f"X-Force: No data found for {endpoint}")
            elif response.status_code == 429:
                logger.warning("X-Force API rate limit exceeded")
            else:
                logger.error(
                    f"X-Force API error: {response.status_code} - {response.text}"
                )
        except requests.exceptions.Timeout:
            logger.error("X-Force API request timeout")
        except requests.exceptions.RequestException as e:
            logger.error(f"X-Force API request failed: {e}")

        return None

    def xforce_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Get IP reputation from IBM X-Force.

        Args:
            ip: IP address to check

        Returns:
            Dictionary with reputation data
        """
        cache_key = self._get_cache_key("xforce", "ip", ip)
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        result = {
            "ip": ip,
            "provider": "IBM X-Force",
            "found": False,
            "risk_score": 0,
            "categories": [],
            "malware_associated": False,
            "history": [],
            "geo": {},
            "raw_response": None,
        }

        data = self._xforce_request(f"/ipr/{ip}")
        if data:
            result["found"] = True
            result["risk_score"] = data.get("score", 0)
            result["categories"] = data.get("cats", {})
            result["geo"] = data.get("geo", {})
            result["raw_response"] = data

            # Check for malware association
            if result["risk_score"] >= 5:
                result["malware_associated"] = True
                self.malicious_ips.add(ip)
                self.stats["malicious_ips_found"] += 1

            # Get history
            history_data = self._xforce_request(f"/ipr/history/{ip}")
            if history_data:
                result["history"] = history_data.get("history", [])

        self._set_cached(cache_key, result)
        return result

    def xforce_url_reputation(self, url: str) -> Dict[str, Any]:
        """
        Get URL reputation from IBM X-Force.

        Args:
            url: URL to check

        Returns:
            Dictionary with reputation data
        """
        cache_key = self._get_cache_key("xforce", "url", url)
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        result = {
            "url": url,
            "provider": "IBM X-Force",
            "found": False,
            "risk_score": 0,
            "categories": [],
            "malware_associated": False,
            "raw_response": None,
        }

        # URL encode the URL for the API
        encoded_url = requests.utils.quote(url, safe="")
        data = self._xforce_request(f"/url/{encoded_url}")

        if data:
            result["found"] = True
            url_result = data.get("result", {})
            result["risk_score"] = url_result.get("score", 0)
            result["categories"] = url_result.get("cats", {})
            result["raw_response"] = data

            if result["risk_score"] >= 5:
                result["malware_associated"] = True
                self.stats["malicious_urls_found"] += 1

        self._set_cached(cache_key, result)
        return result

    def xforce_malware_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check malware hash against IBM X-Force.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            Dictionary with malware data
        """
        cache_key = self._get_cache_key("xforce", "hash", file_hash)
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        result = {
            "hash": file_hash,
            "provider": "IBM X-Force",
            "found": False,
            "malware_family": None,
            "risk_score": 0,
            "first_seen": None,
            "last_seen": None,
            "raw_response": None,
        }

        data = self._xforce_request(f"/malware/{file_hash}")
        if data:
            result["found"] = True
            malware = data.get("malware", {})
            result["malware_family"] = malware.get("family", [])
            result["risk_score"] = malware.get("risk", 0)
            result["first_seen"] = malware.get("created")
            result["last_seen"] = malware.get("modified")
            result["raw_response"] = data

            if result["found"]:
                self.malicious_hashes.add(file_hash.lower())
                self.stats["malicious_hashes_found"] += 1

        self._set_cached(cache_key, result)
        return result

    # =========================================================================
    # AlienVault OTX API
    # =========================================================================

    def _otx_request(
        self, endpoint: str, params: Dict[str, Any] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Make a request to AlienVault OTX API.

        Args:
            endpoint: API endpoint path
            params: Optional query parameters

        Returns:
            JSON response or None on error
        """
        if not self.otx_api_key:
            logger.debug("OTX API not configured, skipping request")
            return None

        # Rate limiting
        elapsed = time.time() - self._last_otx_call
        if elapsed < self._rate_limit_delay:
            time.sleep(self._rate_limit_delay - elapsed)

        headers = {
            "X-OTX-API-KEY": self.otx_api_key,
            "Accept": "application/json",
        }

        url = f"{self.otx_base_url}{endpoint}"

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            self._last_otx_call = time.time()
            self.stats["otx_queries"] += 1

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                logger.error("OTX API authentication failed")
            elif response.status_code == 404:
                logger.debug(f"OTX: No data found for {endpoint}")
            elif response.status_code == 429:
                logger.warning("OTX API rate limit exceeded")
            else:
                logger.error(
                    f"OTX API error: {response.status_code} - {response.text}"
                )
        except requests.exceptions.Timeout:
            logger.error("OTX API request timeout")
        except requests.exceptions.RequestException as e:
            logger.error(f"OTX API request failed: {e}")

        return None

    def otx_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Get IP reputation from AlienVault OTX.

        Args:
            ip: IP address to check

        Returns:
            Dictionary with reputation data
        """
        cache_key = self._get_cache_key("otx", "ip", ip)
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        result = {
            "ip": ip,
            "provider": "AlienVault OTX",
            "found": False,
            "pulse_count": 0,
            "pulses": [],
            "reputation": 0,
            "malware_associated": False,
            "geo": {},
            "asn": None,
            "raw_response": None,
        }

        # Get general info
        data = self._otx_request(f"/indicators/IPv4/{ip}/general")
        if data:
            result["found"] = True
            result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
            result["pulses"] = data.get("pulse_info", {}).get("pulses", [])[:10]
            result["reputation"] = data.get("reputation", 0)
            result["asn"] = data.get("asn")
            result["raw_response"] = data

            # If IP appears in pulses, it's potentially malicious
            if result["pulse_count"] > 0:
                result["malware_associated"] = True
                self.malicious_ips.add(ip)
                self.stats["malicious_ips_found"] += 1

        # Get geo info
        geo_data = self._otx_request(f"/indicators/IPv4/{ip}/geo")
        if geo_data:
            result["geo"] = {
                "country": geo_data.get("country_name"),
                "country_code": geo_data.get("country_code"),
                "city": geo_data.get("city"),
                "latitude": geo_data.get("latitude"),
                "longitude": geo_data.get("longitude"),
            }

        self._set_cached(cache_key, result)
        return result

    def otx_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Get domain reputation from AlienVault OTX.

        Args:
            domain: Domain to check

        Returns:
            Dictionary with reputation data
        """
        cache_key = self._get_cache_key("otx", "domain", domain)
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        result = {
            "domain": domain,
            "provider": "AlienVault OTX",
            "found": False,
            "pulse_count": 0,
            "pulses": [],
            "malware_associated": False,
            "whois": {},
            "raw_response": None,
        }

        data = self._otx_request(f"/indicators/domain/{domain}/general")
        if data:
            result["found"] = True
            result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
            result["pulses"] = data.get("pulse_info", {}).get("pulses", [])[:10]
            result["whois"] = data.get("whois", {})
            result["raw_response"] = data

            if result["pulse_count"] > 0:
                result["malware_associated"] = True
                self.malicious_domains.add(domain.lower())

        self._set_cached(cache_key, result)
        return result

    def otx_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash against AlienVault OTX.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            Dictionary with malware data
        """
        cache_key = self._get_cache_key("otx", "hash", file_hash)
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        # Determine hash type
        hash_len = len(file_hash)
        if hash_len == 32:
            hash_type = "MD5"
        elif hash_len == 40:
            hash_type = "SHA1"
        elif hash_len == 64:
            hash_type = "SHA256"
        else:
            return {"error": "Invalid hash format", "hash": file_hash}

        result = {
            "hash": file_hash,
            "hash_type": hash_type,
            "provider": "AlienVault OTX",
            "found": False,
            "pulse_count": 0,
            "pulses": [],
            "malware_associated": False,
            "analysis": {},
            "raw_response": None,
        }

        data = self._otx_request(f"/indicators/file/{file_hash}/general")
        if data:
            result["found"] = True
            result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
            result["pulses"] = data.get("pulse_info", {}).get("pulses", [])[:10]
            result["raw_response"] = data

            if result["pulse_count"] > 0:
                result["malware_associated"] = True
                self.malicious_hashes.add(file_hash.lower())
                self.stats["malicious_hashes_found"] += 1

        # Get analysis data
        analysis_data = self._otx_request(f"/indicators/file/{file_hash}/analysis")
        if analysis_data:
            result["analysis"] = analysis_data.get("analysis", {})

        self._set_cached(cache_key, result)
        return result

    def otx_get_pulses(self, limit: int = 10, modified_since: str = None) -> List[Dict]:
        """
        Get recent OTX pulses (threat intelligence feeds).

        Args:
            limit: Maximum number of pulses to return
            modified_since: ISO date string to filter pulses

        Returns:
            List of pulse dictionaries
        """
        params = {"limit": limit}
        if modified_since:
            params["modified_since"] = modified_since

        data = self._otx_request("/pulses/subscribed", params=params)
        if data:
            return data.get("results", [])
        return []

    # =========================================================================
    # Combined Intelligence Methods
    # =========================================================================

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Check IP against all configured threat intelligence sources.

        Args:
            ip: IP address to check

        Returns:
            Combined reputation data from all sources
        """
        result = {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "is_malicious": False,
            "risk_score": 0,
            "sources": [],
            "categories": [],
            "geo": {},
            "recommendations": [],
        }

        # Check IBM X-Force
        xforce_result = self.xforce_ip_reputation(ip)
        if xforce_result.get("found"):
            result["sources"].append(xforce_result)
            result["risk_score"] = max(
                result["risk_score"], xforce_result.get("risk_score", 0)
            )
            if xforce_result.get("categories"):
                result["categories"].extend(
                    list(xforce_result.get("categories", {}).keys())
                )
            if xforce_result.get("geo"):
                result["geo"] = xforce_result["geo"]

        # Check AlienVault OTX
        otx_result = self.otx_ip_reputation(ip)
        if otx_result.get("found"):
            result["sources"].append(otx_result)
            # OTX doesn't have a direct score, use pulse count
            if otx_result.get("pulse_count", 0) > 0:
                result["risk_score"] = max(result["risk_score"], 7)
            if otx_result.get("geo"):
                result["geo"] = result["geo"] or otx_result["geo"]

        # Determine if malicious
        if result["risk_score"] >= 5 or any(
            s.get("malware_associated") for s in result["sources"]
        ):
            result["is_malicious"] = True
            result["recommendations"].append("Block this IP address")
            result["recommendations"].append("Investigate related network traffic")

        # Remove duplicates from categories
        result["categories"] = list(set(result["categories"]))

        return result

    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check URL against threat intelligence sources.

        Args:
            url: URL to check

        Returns:
            Combined reputation data
        """
        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "is_malicious": False,
            "risk_score": 0,
            "sources": [],
            "categories": [],
            "recommendations": [],
        }

        # Check IBM X-Force
        xforce_result = self.xforce_url_reputation(url)
        if xforce_result.get("found"):
            result["sources"].append(xforce_result)
            result["risk_score"] = max(
                result["risk_score"], xforce_result.get("risk_score", 0)
            )
            if xforce_result.get("categories"):
                result["categories"].extend(
                    list(xforce_result.get("categories", {}).keys())
                )

        # Extract domain and check OTX
        try:
            from urllib.parse import urlparse

            domain = urlparse(url).netloc
            if domain:
                otx_result = self.otx_domain_reputation(domain)
                if otx_result.get("found"):
                    result["sources"].append(otx_result)
                    if otx_result.get("pulse_count", 0) > 0:
                        result["risk_score"] = max(result["risk_score"], 7)
        except Exception as e:
            logger.debug(f"Error parsing URL domain: {e}")

        if result["risk_score"] >= 5 or any(
            s.get("malware_associated") for s in result["sources"]
        ):
            result["is_malicious"] = True
            result["recommendations"].append("Block access to this URL")
            result["recommendations"].append("Scan systems that accessed this URL")

        result["categories"] = list(set(result["categories"]))
        return result

    def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash against threat intelligence sources.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            Combined malware data
        """
        result = {
            "hash": file_hash,
            "timestamp": datetime.now().isoformat(),
            "is_malicious": False,
            "malware_families": [],
            "sources": [],
            "recommendations": [],
        }

        # Check IBM X-Force
        xforce_result = self.xforce_malware_hash(file_hash)
        if xforce_result.get("found"):
            result["sources"].append(xforce_result)
            result["is_malicious"] = True
            if xforce_result.get("malware_family"):
                result["malware_families"].extend(xforce_result["malware_family"])

        # Check AlienVault OTX
        otx_result = self.otx_file_hash(file_hash)
        if otx_result.get("found") and otx_result.get("pulse_count", 0) > 0:
            result["sources"].append(otx_result)
            result["is_malicious"] = True

        if result["is_malicious"]:
            result["recommendations"].append("Quarantine the file immediately")
            result["recommendations"].append("Scan all systems for this hash")
            result["recommendations"].append("Investigate the infection vector")

        result["malware_families"] = list(set(result["malware_families"]))
        return result

    def is_known_malicious(self, indicator: str, indicator_type: str = "ip") -> bool:
        """
        Quick check if indicator is in local malicious cache.

        Args:
            indicator: The indicator to check (IP, domain, or hash)
            indicator_type: Type of indicator ('ip', 'domain', 'hash')

        Returns:
            True if known malicious
        """
        if indicator_type == "ip":
            return indicator in self.malicious_ips
        elif indicator_type == "domain":
            return indicator.lower() in self.malicious_domains
        elif indicator_type == "hash":
            return indicator.lower() in self.malicious_hashes
        return False

    def bulk_check_ips(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Check multiple IPs against threat intelligence.

        Args:
            ips: List of IP addresses

        Returns:
            Dictionary mapping IPs to their reputation data
        """
        results = {}
        for ip in ips:
            try:
                results[ip] = self.check_ip(ip)
            except Exception as e:
                logger.error(f"Error checking IP {ip}: {e}")
                results[ip] = {"ip": ip, "error": str(e)}
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence service statistics."""
        return {
            **self.stats,
            "cache_size": len(self._cache),
            "malicious_ips_cached": len(self.malicious_ips),
            "malicious_domains_cached": len(self.malicious_domains),
            "malicious_hashes_cached": len(self.malicious_hashes),
            "xforce_configured": bool(
                self.xforce_api_key and self.xforce_api_password
            ),
            "otx_configured": bool(self.otx_api_key),
        }

    def clear_cache(self):
        """Clear the intelligence cache."""
        self._cache.clear()
        logger.info("Threat intelligence cache cleared")

    def export_indicators(self) -> Dict[str, List[str]]:
        """Export all known malicious indicators."""
        return {
            "malicious_ips": list(self.malicious_ips),
            "malicious_domains": list(self.malicious_domains),
            "malicious_hashes": list(self.malicious_hashes),
            "exported_at": datetime.now().isoformat(),
        }

    def import_indicators(
        self,
        ips: List[str] = None,
        domains: List[str] = None,
        hashes: List[str] = None,
    ):
        """
        Import indicators into local cache.

        Args:
            ips: List of malicious IPs
            domains: List of malicious domains
            hashes: List of malicious file hashes
        """
        if ips:
            self.malicious_ips.update(ips)
            logger.info(f"Imported {len(ips)} malicious IPs")

        if domains:
            self.malicious_domains.update(d.lower() for d in domains)
            logger.info(f"Imported {len(domains)} malicious domains")

        if hashes:
            self.malicious_hashes.update(h.lower() for h in hashes)
            logger.info(f"Imported {len(hashes)} malicious hashes")
