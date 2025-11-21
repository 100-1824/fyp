"""
Threat Intelligence Service - Integrated into Dashboard

Provides threat intelligence lookups from multiple sources:
- IBM X-Force Exchange API
- AlienVault OTX (Open Threat Exchange) API

Supports IP reputation, URL analysis, domain checks, and malware hash lookups.
"""

import base64
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# Cache for reducing API calls (TTL: 1 hour)
_cache: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = 3600

# Rate limiting
_last_xforce_call = 0
_last_otx_call = 0
RATE_LIMIT_DELAY = 1.0

# Statistics
_statistics = {
    "xforce_queries": 0,
    "otx_queries": 0,
    "cache_hits": 0,
    "total_lookups": 0,
    "malicious_found": 0,
    "errors": 0,
}

# Local threat indicator cache
_malicious_ips: set = set()
_malicious_domains: set = set()
_malicious_hashes: set = set()


class ThreatIntelService:
    """Threat Intelligence Service for IBM X-Force and AlienVault OTX."""

    def __init__(self, xforce_api_key: str = "", xforce_api_password: str = "", otx_api_key: str = ""):
        """Initialize the threat intel service with API credentials."""
        self.xforce_api_key = xforce_api_key
        self.xforce_api_password = xforce_api_password
        self.xforce_base_url = "https://api.xforce.ibmcloud.com"

        self.otx_api_key = otx_api_key
        self.otx_base_url = "https://otx.alienvault.com/api/v1"

    def _get_cache_key(self, provider: str, query_type: str, value: str) -> str:
        """Generate a cache key."""
        return f"{provider}:{query_type}:{value}"

    def _get_cached(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if not expired."""
        global _statistics
        if cache_key in _cache:
            cached = _cache[cache_key]
            if time.time() - cached["timestamp"] < CACHE_TTL:
                _statistics["cache_hits"] += 1
                return cached["data"]
            else:
                del _cache[cache_key]
        return None

    def _set_cached(self, cache_key: str, data: Dict[str, Any]):
        """Cache a result."""
        _cache[cache_key] = {"timestamp": time.time(), "data": data}

    # =========================================================================
    # IBM X-Force Exchange API Functions
    # =========================================================================

    def _xforce_request(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[Dict]:
        """Make a request to IBM X-Force API."""
        global _last_xforce_call, _statistics

        if not self.xforce_api_key or not self.xforce_api_password:
            logger.debug("X-Force API not configured, skipping request")
            return None

        # Rate limiting
        elapsed = time.time() - _last_xforce_call
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)

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
            _last_xforce_call = time.time()
            _statistics["xforce_queries"] += 1

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                logger.error("X-Force API authentication failed")
            elif response.status_code == 404:
                logger.debug(f"X-Force: No data found for {endpoint}")
            elif response.status_code == 429:
                logger.warning("X-Force API rate limit exceeded")
            else:
                logger.error(f"X-Force API error: {response.status_code}")
        except requests.exceptions.Timeout:
            logger.error("X-Force API request timeout")
            _statistics["errors"] += 1
        except requests.exceptions.RequestException as e:
            logger.error(f"X-Force API request failed: {e}")
            _statistics["errors"] += 1

        return None

    def xforce_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Get IP reputation from IBM X-Force."""
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
            "geo": {},
        }

        data = self._xforce_request(f"/ipr/{ip}")
        if data:
            result["found"] = True
            result["risk_score"] = data.get("score", 0)
            result["categories"] = list(data.get("cats", {}).keys())
            result["geo"] = data.get("geo", {})

            if result["risk_score"] >= 5:
                result["malware_associated"] = True
                _malicious_ips.add(ip)

        self._set_cached(cache_key, result)
        return result

    def xforce_url_reputation(self, url: str) -> Dict[str, Any]:
        """Get URL reputation from IBM X-Force."""
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
        }

        encoded_url = requests.utils.quote(url, safe="")
        data = self._xforce_request(f"/url/{encoded_url}")

        if data:
            result["found"] = True
            url_result = data.get("result", {})
            result["risk_score"] = url_result.get("score", 0)
            result["categories"] = list(url_result.get("cats", {}).keys())

            if result["risk_score"] >= 5:
                result["malware_associated"] = True

        self._set_cached(cache_key, result)
        return result

    def xforce_malware_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check malware hash against IBM X-Force."""
        cache_key = self._get_cache_key("xforce", "hash", file_hash)
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        result = {
            "hash": file_hash,
            "provider": "IBM X-Force",
            "found": False,
            "malware_family": [],
            "risk_score": 0,
        }

        data = self._xforce_request(f"/malware/{file_hash}")
        if data:
            result["found"] = True
            malware = data.get("malware", {})
            result["malware_family"] = malware.get("family", [])
            result["risk_score"] = malware.get("risk", 0)

            if result["found"]:
                _malicious_hashes.add(file_hash.lower())

        self._set_cached(cache_key, result)
        return result

    # =========================================================================
    # AlienVault OTX API Functions
    # =========================================================================

    def _otx_request(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[Dict]:
        """Make a request to AlienVault OTX API."""
        global _last_otx_call, _statistics

        if not self.otx_api_key:
            logger.debug("OTX API not configured, skipping request")
            return None

        # Rate limiting
        elapsed = time.time() - _last_otx_call
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)

        headers = {
            "X-OTX-API-KEY": self.otx_api_key,
            "Accept": "application/json",
        }

        url = f"{self.otx_base_url}{endpoint}"

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            _last_otx_call = time.time()
            _statistics["otx_queries"] += 1

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                logger.error("OTX API authentication failed")
            elif response.status_code == 404:
                logger.debug(f"OTX: No data found for {endpoint}")
            elif response.status_code == 429:
                logger.warning("OTX API rate limit exceeded")
            else:
                logger.error(f"OTX API error: {response.status_code}")
        except requests.exceptions.Timeout:
            logger.error("OTX API request timeout")
            _statistics["errors"] += 1
        except requests.exceptions.RequestException as e:
            logger.error(f"OTX API request failed: {e}")
            _statistics["errors"] += 1

        return None

    def otx_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Get IP reputation from AlienVault OTX."""
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
            "malware_associated": False,
            "geo": {},
        }

        data = self._otx_request(f"/indicators/IPv4/{ip}/general")
        if data:
            result["found"] = True
            result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
            result["pulses"] = data.get("pulse_info", {}).get("pulses", [])[:5]

            if result["pulse_count"] > 0:
                result["malware_associated"] = True
                _malicious_ips.add(ip)

        # Get geo info
        geo_data = self._otx_request(f"/indicators/IPv4/{ip}/geo")
        if geo_data:
            result["geo"] = {
                "country": geo_data.get("country_name"),
                "country_code": geo_data.get("country_code"),
                "city": geo_data.get("city"),
            }

        self._set_cached(cache_key, result)
        return result

    def otx_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Get domain reputation from AlienVault OTX."""
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
        }

        data = self._otx_request(f"/indicators/domain/{domain}/general")
        if data:
            result["found"] = True
            result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
            result["pulses"] = data.get("pulse_info", {}).get("pulses", [])[:5]

            if result["pulse_count"] > 0:
                result["malware_associated"] = True
                _malicious_domains.add(domain.lower())

        self._set_cached(cache_key, result)
        return result

    def otx_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash against AlienVault OTX."""
        cache_key = self._get_cache_key("otx", "hash", file_hash)
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        result = {
            "hash": file_hash,
            "provider": "AlienVault OTX",
            "found": False,
            "pulse_count": 0,
            "pulses": [],
            "malware_associated": False,
        }

        data = self._otx_request(f"/indicators/file/{file_hash}/general")
        if data:
            result["found"] = True
            result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
            result["pulses"] = data.get("pulse_info", {}).get("pulses", [])[:5]

            if result["pulse_count"] > 0:
                result["malware_associated"] = True
                _malicious_hashes.add(file_hash.lower())

        self._set_cached(cache_key, result)
        return result

    def otx_get_pulses(self, limit: int = 10) -> List[Dict]:
        """Get recent OTX pulses (threat intelligence feeds)."""
        data = self._otx_request("/pulses/subscribed", params={"limit": limit})
        if data:
            return data.get("results", [])
        return []

    # =========================================================================
    # Combined Intelligence Functions
    # =========================================================================

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP against all configured sources."""
        global _statistics
        _statistics["total_lookups"] += 1

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
        if self.xforce_api_key and self.xforce_api_password:
            xforce_result = self.xforce_ip_reputation(ip)
            if xforce_result.get("found"):
                result["sources"].append(xforce_result)
                result["risk_score"] = max(
                    result["risk_score"], xforce_result.get("risk_score", 0)
                )
                result["categories"].extend(xforce_result.get("categories", []))
                if xforce_result.get("geo"):
                    result["geo"] = xforce_result["geo"]

        # Check AlienVault OTX
        if self.otx_api_key:
            otx_result = self.otx_ip_reputation(ip)
            if otx_result.get("found"):
                result["sources"].append(otx_result)
                if otx_result.get("pulse_count", 0) > 0:
                    result["risk_score"] = max(result["risk_score"], 7)
                if otx_result.get("geo") and not result["geo"]:
                    result["geo"] = otx_result["geo"]

        # Determine if malicious
        if result["risk_score"] >= 5 or any(
            s.get("malware_associated") for s in result["sources"]
        ):
            result["is_malicious"] = True
            result["recommendations"].append("Block this IP address")
            result["recommendations"].append("Investigate related network traffic")
            _statistics["malicious_found"] += 1

        result["categories"] = list(set(result["categories"]))
        return result

    def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL against all configured sources."""
        global _statistics
        _statistics["total_lookups"] += 1

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
        if self.xforce_api_key and self.xforce_api_password:
            xforce_result = self.xforce_url_reputation(url)
            if xforce_result.get("found"):
                result["sources"].append(xforce_result)
                result["risk_score"] = max(
                    result["risk_score"], xforce_result.get("risk_score", 0)
                )
                result["categories"].extend(xforce_result.get("categories", []))

        # Extract domain and check OTX
        if self.otx_api_key:
            try:
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
            _statistics["malicious_found"] += 1

        result["categories"] = list(set(result["categories"]))
        return result

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation from OTX."""
        if self.otx_api_key:
            return self.otx_domain_reputation(domain)
        return {"error": "OTX API not configured", "domain": domain}

    def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash against all configured sources."""
        global _statistics
        _statistics["total_lookups"] += 1

        result = {
            "hash": file_hash,
            "timestamp": datetime.now().isoformat(),
            "is_malicious": False,
            "malware_families": [],
            "sources": [],
            "recommendations": [],
        }

        # Check IBM X-Force
        if self.xforce_api_key and self.xforce_api_password:
            xforce_result = self.xforce_malware_hash(file_hash)
            if xforce_result.get("found"):
                result["sources"].append(xforce_result)
                result["is_malicious"] = True
                result["malware_families"].extend(xforce_result.get("malware_family", []))

        # Check AlienVault OTX
        if self.otx_api_key:
            otx_result = self.otx_file_hash(file_hash)
            if otx_result.get("found") and otx_result.get("pulse_count", 0) > 0:
                result["sources"].append(otx_result)
                result["is_malicious"] = True

        if result["is_malicious"]:
            result["recommendations"].append("Quarantine the file immediately")
            result["recommendations"].append("Scan all systems for this hash")
            _statistics["malicious_found"] += 1

        result["malware_families"] = list(set(result["malware_families"]))
        return result

    def bulk_check_ips(self, ips: List[str]) -> Dict[str, Any]:
        """Bulk lookup for multiple IPs."""
        if len(ips) > 100:
            return {"error": "Maximum 100 IPs per request"}

        results = {}
        for ip in ips:
            try:
                results[ip] = self.check_ip(ip)
            except Exception as e:
                results[ip] = {"ip": ip, "error": str(e)}

        malicious_count = sum(1 for r in results.values() if r.get("is_malicious"))

        return {
            "results": results,
            "total": len(ips),
            "malicious_count": malicious_count,
        }

    def quick_check_ip(self, ip: str) -> Dict[str, Any]:
        """Quick check if IP is in local malicious cache."""
        is_malicious = ip in _malicious_ips
        return {
            "ip": ip,
            "is_known_malicious": is_malicious,
            "cached": True,
        }

    def get_pulses(self, limit: int = 10) -> Dict[str, Any]:
        """Get recent OTX threat intelligence pulses."""
        if not self.otx_api_key:
            return {"error": "OTX API not configured"}

        pulses = self.otx_get_pulses(limit)
        return {"pulses": pulses, "count": len(pulses)}

    def get_indicators(self) -> Dict[str, Any]:
        """Get all cached malicious indicators."""
        return {
            "malicious_ips": list(_malicious_ips),
            "malicious_domains": list(_malicious_domains),
            "malicious_hashes": list(_malicious_hashes),
            "total_ips": len(_malicious_ips),
            "total_domains": len(_malicious_domains),
            "total_hashes": len(_malicious_hashes),
        }

    def import_indicators(self, ips: List[str] = None, domains: List[str] = None, hashes: List[str] = None) -> Dict[str, Any]:
        """Import indicators into local cache."""
        ips = ips or []
        domains = domains or []
        hashes = hashes or []

        _malicious_ips.update(ips)
        _malicious_domains.update(d.lower() for d in domains)
        _malicious_hashes.update(h.lower() for h in hashes)

        return {
            "message": "Indicators imported successfully",
            "imported": {
                "ips": len(ips),
                "domains": len(domains),
                "hashes": len(hashes),
            },
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get service statistics."""
        return {
            **_statistics,
            "cache_size": len(_cache),
            "malicious_ips_cached": len(_malicious_ips),
            "malicious_domains_cached": len(_malicious_domains),
            "malicious_hashes_cached": len(_malicious_hashes),
            "xforce_configured": bool(self.xforce_api_key and self.xforce_api_password),
            "otx_configured": bool(self.otx_api_key),
        }

    def get_health(self) -> Dict[str, Any]:
        """Get service health status."""
        return {
            "service": "threat-intel",
            "status": "healthy",
            "xforce_configured": bool(self.xforce_api_key and self.xforce_api_password),
            "otx_configured": bool(self.otx_api_key),
            "cache_size": len(_cache),
        }

    def clear_cache(self) -> Dict[str, Any]:
        """Clear the intelligence cache."""
        _cache.clear()
        return {"message": "Cache cleared successfully"}


# Global instance - will be initialized with config
_threat_intel_service: Optional[ThreatIntelService] = None


def get_threat_intel_service() -> ThreatIntelService:
    """Get or create the global threat intel service instance."""
    global _threat_intel_service
    if _threat_intel_service is None:
        from flask import current_app
        _threat_intel_service = ThreatIntelService(
            xforce_api_key=current_app.config.get("XFORCE_API_KEY", ""),
            xforce_api_password=current_app.config.get("XFORCE_API_PASSWORD", ""),
            otx_api_key=current_app.config.get("OTX_API_KEY", ""),
        )
    return _threat_intel_service


def init_threat_intel_service(app):
    """Initialize the threat intel service with app config."""
    global _threat_intel_service
    _threat_intel_service = ThreatIntelService(
        xforce_api_key=app.config.get("XFORCE_API_KEY", ""),
        xforce_api_password=app.config.get("XFORCE_API_PASSWORD", ""),
        otx_api_key=app.config.get("OTX_API_KEY", ""),
    )
    return _threat_intel_service
