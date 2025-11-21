"""
Threat Intelligence Microservice

Provides threat intelligence lookups from multiple sources:
- IBM X-Force Exchange API
- AlienVault OTX (Open Threat Exchange) API

Supports IP reputation, URL analysis, domain checks, and malware hash lookups.
"""

import base64
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent))

from shared.config import get_config

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(get_config())
CORS(app)

# Configure logging
logging.basicConfig(
    level=getattr(logging, app.config["LOG_LEVEL"]), format=app.config["LOG_FORMAT"]
)
logger = logging.getLogger(__name__)

# API Configuration
XFORCE_API_KEY = os.environ.get("XFORCE_API_KEY", "")
XFORCE_API_PASSWORD = os.environ.get("XFORCE_API_PASSWORD", "")
XFORCE_BASE_URL = "https://api.xforce.ibmcloud.com"

OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# Cache for reducing API calls (TTL: 1 hour)
cache: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = 3600

# Rate limiting
last_xforce_call = 0
last_otx_call = 0
RATE_LIMIT_DELAY = 1.0

# Statistics
statistics = {
    "xforce_queries": 0,
    "otx_queries": 0,
    "cache_hits": 0,
    "total_lookups": 0,
    "malicious_found": 0,
    "errors": 0,
}

# Local threat indicator cache
malicious_ips: set = set()
malicious_domains: set = set()
malicious_hashes: set = set()


def get_cache_key(provider: str, query_type: str, value: str) -> str:
    """Generate a cache key."""
    return f"{provider}:{query_type}:{value}"


def get_cached(cache_key: str) -> Optional[Dict[str, Any]]:
    """Get cached result if not expired."""
    if cache_key in cache:
        cached = cache[cache_key]
        if time.time() - cached["timestamp"] < CACHE_TTL:
            statistics["cache_hits"] += 1
            return cached["data"]
        else:
            del cache[cache_key]
    return None


def set_cached(cache_key: str, data: Dict[str, Any]):
    """Cache a result."""
    cache[cache_key] = {"timestamp": time.time(), "data": data}


# =============================================================================
# IBM X-Force Exchange API Functions
# =============================================================================


def xforce_request(endpoint: str, params: Dict[str, Any] = None) -> Optional[Dict]:
    """Make a request to IBM X-Force API."""
    global last_xforce_call

    if not XFORCE_API_KEY or not XFORCE_API_PASSWORD:
        logger.debug("X-Force API not configured, skipping request")
        return None

    # Rate limiting
    elapsed = time.time() - last_xforce_call
    if elapsed < RATE_LIMIT_DELAY:
        time.sleep(RATE_LIMIT_DELAY - elapsed)

    # Create basic auth header
    credentials = f"{XFORCE_API_KEY}:{XFORCE_API_PASSWORD}"
    auth_header = base64.b64encode(credentials.encode()).decode()

    headers = {
        "Authorization": f"Basic {auth_header}",
        "Accept": "application/json",
    }

    url = f"{XFORCE_BASE_URL}{endpoint}"

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        last_xforce_call = time.time()
        statistics["xforce_queries"] += 1

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
        statistics["errors"] += 1
    except requests.exceptions.RequestException as e:
        logger.error(f"X-Force API request failed: {e}")
        statistics["errors"] += 1

    return None


def xforce_ip_reputation(ip: str) -> Dict[str, Any]:
    """Get IP reputation from IBM X-Force."""
    cache_key = get_cache_key("xforce", "ip", ip)
    cached = get_cached(cache_key)
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

    data = xforce_request(f"/ipr/{ip}")
    if data:
        result["found"] = True
        result["risk_score"] = data.get("score", 0)
        result["categories"] = list(data.get("cats", {}).keys())
        result["geo"] = data.get("geo", {})

        if result["risk_score"] >= 5:
            result["malware_associated"] = True
            malicious_ips.add(ip)

    set_cached(cache_key, result)
    return result


def xforce_url_reputation(url: str) -> Dict[str, Any]:
    """Get URL reputation from IBM X-Force."""
    cache_key = get_cache_key("xforce", "url", url)
    cached = get_cached(cache_key)
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
    data = xforce_request(f"/url/{encoded_url}")

    if data:
        result["found"] = True
        url_result = data.get("result", {})
        result["risk_score"] = url_result.get("score", 0)
        result["categories"] = list(url_result.get("cats", {}).keys())

        if result["risk_score"] >= 5:
            result["malware_associated"] = True

    set_cached(cache_key, result)
    return result


def xforce_malware_hash(file_hash: str) -> Dict[str, Any]:
    """Check malware hash against IBM X-Force."""
    cache_key = get_cache_key("xforce", "hash", file_hash)
    cached = get_cached(cache_key)
    if cached:
        return cached

    result = {
        "hash": file_hash,
        "provider": "IBM X-Force",
        "found": False,
        "malware_family": [],
        "risk_score": 0,
    }

    data = xforce_request(f"/malware/{file_hash}")
    if data:
        result["found"] = True
        malware = data.get("malware", {})
        result["malware_family"] = malware.get("family", [])
        result["risk_score"] = malware.get("risk", 0)

        if result["found"]:
            malicious_hashes.add(file_hash.lower())

    set_cached(cache_key, result)
    return result


# =============================================================================
# AlienVault OTX API Functions
# =============================================================================


def otx_request(endpoint: str, params: Dict[str, Any] = None) -> Optional[Dict]:
    """Make a request to AlienVault OTX API."""
    global last_otx_call

    if not OTX_API_KEY:
        logger.debug("OTX API not configured, skipping request")
        return None

    # Rate limiting
    elapsed = time.time() - last_otx_call
    if elapsed < RATE_LIMIT_DELAY:
        time.sleep(RATE_LIMIT_DELAY - elapsed)

    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
        "Accept": "application/json",
    }

    url = f"{OTX_BASE_URL}{endpoint}"

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        last_otx_call = time.time()
        statistics["otx_queries"] += 1

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
        statistics["errors"] += 1
    except requests.exceptions.RequestException as e:
        logger.error(f"OTX API request failed: {e}")
        statistics["errors"] += 1

    return None


def otx_ip_reputation(ip: str) -> Dict[str, Any]:
    """Get IP reputation from AlienVault OTX."""
    cache_key = get_cache_key("otx", "ip", ip)
    cached = get_cached(cache_key)
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

    data = otx_request(f"/indicators/IPv4/{ip}/general")
    if data:
        result["found"] = True
        result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
        result["pulses"] = data.get("pulse_info", {}).get("pulses", [])[:5]

        if result["pulse_count"] > 0:
            result["malware_associated"] = True
            malicious_ips.add(ip)

    # Get geo info
    geo_data = otx_request(f"/indicators/IPv4/{ip}/geo")
    if geo_data:
        result["geo"] = {
            "country": geo_data.get("country_name"),
            "country_code": geo_data.get("country_code"),
            "city": geo_data.get("city"),
        }

    set_cached(cache_key, result)
    return result


def otx_domain_reputation(domain: str) -> Dict[str, Any]:
    """Get domain reputation from AlienVault OTX."""
    cache_key = get_cache_key("otx", "domain", domain)
    cached = get_cached(cache_key)
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

    data = otx_request(f"/indicators/domain/{domain}/general")
    if data:
        result["found"] = True
        result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
        result["pulses"] = data.get("pulse_info", {}).get("pulses", [])[:5]

        if result["pulse_count"] > 0:
            result["malware_associated"] = True
            malicious_domains.add(domain.lower())

    set_cached(cache_key, result)
    return result


def otx_file_hash(file_hash: str) -> Dict[str, Any]:
    """Check file hash against AlienVault OTX."""
    cache_key = get_cache_key("otx", "hash", file_hash)
    cached = get_cached(cache_key)
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

    data = otx_request(f"/indicators/file/{file_hash}/general")
    if data:
        result["found"] = True
        result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
        result["pulses"] = data.get("pulse_info", {}).get("pulses", [])[:5]

        if result["pulse_count"] > 0:
            result["malware_associated"] = True
            malicious_hashes.add(file_hash.lower())

    set_cached(cache_key, result)
    return result


def otx_get_pulses(limit: int = 10) -> List[Dict]:
    """Get recent OTX pulses (threat intelligence feeds)."""
    data = otx_request("/pulses/subscribed", params={"limit": limit})
    if data:
        return data.get("results", [])
    return []


# =============================================================================
# Combined Intelligence Functions
# =============================================================================


def check_ip_combined(ip: str) -> Dict[str, Any]:
    """Check IP against all configured sources."""
    statistics["total_lookups"] += 1

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
    if XFORCE_API_KEY and XFORCE_API_PASSWORD:
        xforce_result = xforce_ip_reputation(ip)
        if xforce_result.get("found"):
            result["sources"].append(xforce_result)
            result["risk_score"] = max(
                result["risk_score"], xforce_result.get("risk_score", 0)
            )
            result["categories"].extend(xforce_result.get("categories", []))
            if xforce_result.get("geo"):
                result["geo"] = xforce_result["geo"]

    # Check AlienVault OTX
    if OTX_API_KEY:
        otx_result = otx_ip_reputation(ip)
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
        statistics["malicious_found"] += 1

    result["categories"] = list(set(result["categories"]))
    return result


def check_url_combined(url: str) -> Dict[str, Any]:
    """Check URL against all configured sources."""
    statistics["total_lookups"] += 1

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
    if XFORCE_API_KEY and XFORCE_API_PASSWORD:
        xforce_result = xforce_url_reputation(url)
        if xforce_result.get("found"):
            result["sources"].append(xforce_result)
            result["risk_score"] = max(
                result["risk_score"], xforce_result.get("risk_score", 0)
            )
            result["categories"].extend(xforce_result.get("categories", []))

    # Extract domain and check OTX
    if OTX_API_KEY:
        try:
            from urllib.parse import urlparse

            domain = urlparse(url).netloc
            if domain:
                otx_result = otx_domain_reputation(domain)
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
        statistics["malicious_found"] += 1

    result["categories"] = list(set(result["categories"]))
    return result


def check_hash_combined(file_hash: str) -> Dict[str, Any]:
    """Check file hash against all configured sources."""
    statistics["total_lookups"] += 1

    result = {
        "hash": file_hash,
        "timestamp": datetime.now().isoformat(),
        "is_malicious": False,
        "malware_families": [],
        "sources": [],
        "recommendations": [],
    }

    # Check IBM X-Force
    if XFORCE_API_KEY and XFORCE_API_PASSWORD:
        xforce_result = xforce_malware_hash(file_hash)
        if xforce_result.get("found"):
            result["sources"].append(xforce_result)
            result["is_malicious"] = True
            result["malware_families"].extend(xforce_result.get("malware_family", []))

    # Check AlienVault OTX
    if OTX_API_KEY:
        otx_result = otx_file_hash(file_hash)
        if otx_result.get("found") and otx_result.get("pulse_count", 0) > 0:
            result["sources"].append(otx_result)
            result["is_malicious"] = True

    if result["is_malicious"]:
        result["recommendations"].append("Quarantine the file immediately")
        result["recommendations"].append("Scan all systems for this hash")
        statistics["malicious_found"] += 1

    result["malware_families"] = list(set(result["malware_families"]))
    return result


# =============================================================================
# API Endpoints
# =============================================================================


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return (
        jsonify(
            {
                "service": "threat-intel",
                "status": "healthy",
                "xforce_configured": bool(XFORCE_API_KEY and XFORCE_API_PASSWORD),
                "otx_configured": bool(OTX_API_KEY),
                "cache_size": len(cache),
            }
        ),
        200,
    )


@app.route("/lookup/ip/<ip>", methods=["GET"])
def lookup_ip(ip: str):
    """Look up IP reputation from all sources."""
    try:
        result = check_ip_combined(ip)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error looking up IP {ip}: {e}")
        statistics["errors"] += 1
        return jsonify({"error": str(e)}), 500


@app.route("/lookup/url", methods=["POST"])
def lookup_url():
    """Look up URL reputation from all sources."""
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL required"}), 400

    try:
        result = check_url_combined(url)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error looking up URL: {e}")
        statistics["errors"] += 1
        return jsonify({"error": str(e)}), 500


@app.route("/lookup/domain/<domain>", methods=["GET"])
def lookup_domain(domain: str):
    """Look up domain reputation from OTX."""
    try:
        if OTX_API_KEY:
            result = otx_domain_reputation(domain)
            return jsonify(result), 200
        else:
            return jsonify({"error": "OTX API not configured"}), 503
    except Exception as e:
        logger.error(f"Error looking up domain {domain}: {e}")
        statistics["errors"] += 1
        return jsonify({"error": str(e)}), 500


@app.route("/lookup/hash/<file_hash>", methods=["GET"])
def lookup_hash(file_hash: str):
    """Look up file hash from all sources."""
    try:
        result = check_hash_combined(file_hash)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error looking up hash {file_hash}: {e}")
        statistics["errors"] += 1
        return jsonify({"error": str(e)}), 500


@app.route("/lookup/bulk/ips", methods=["POST"])
def bulk_lookup_ips():
    """Bulk lookup for multiple IPs."""
    data = request.get_json()
    ips = data.get("ips", [])

    if not ips:
        return jsonify({"error": "IPs list required"}), 400

    if len(ips) > 100:
        return jsonify({"error": "Maximum 100 IPs per request"}), 400

    results = {}
    for ip in ips:
        try:
            results[ip] = check_ip_combined(ip)
        except Exception as e:
            results[ip] = {"ip": ip, "error": str(e)}

    malicious_count = sum(1 for r in results.values() if r.get("is_malicious"))

    return (
        jsonify(
            {
                "results": results,
                "total": len(ips),
                "malicious_count": malicious_count,
            }
        ),
        200,
    )


@app.route("/check/quick/<ip>", methods=["GET"])
def quick_check(ip: str):
    """Quick check if IP is in local malicious cache."""
    is_malicious = ip in malicious_ips
    return (
        jsonify(
            {
                "ip": ip,
                "is_known_malicious": is_malicious,
                "cached": True,
            }
        ),
        200,
    )


@app.route("/pulses", methods=["GET"])
def get_pulses():
    """Get recent OTX threat intelligence pulses."""
    limit = request.args.get("limit", 10, type=int)

    if not OTX_API_KEY:
        return jsonify({"error": "OTX API not configured"}), 503

    try:
        pulses = otx_get_pulses(limit)
        return jsonify({"pulses": pulses, "count": len(pulses)}), 200
    except Exception as e:
        logger.error(f"Error fetching pulses: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/indicators", methods=["GET"])
def get_indicators():
    """Get all cached malicious indicators."""
    return (
        jsonify(
            {
                "malicious_ips": list(malicious_ips),
                "malicious_domains": list(malicious_domains),
                "malicious_hashes": list(malicious_hashes),
                "total_ips": len(malicious_ips),
                "total_domains": len(malicious_domains),
                "total_hashes": len(malicious_hashes),
            }
        ),
        200,
    )


@app.route("/indicators/import", methods=["POST"])
def import_indicators():
    """Import indicators into local cache."""
    data = request.get_json()

    ips = data.get("ips", [])
    domains = data.get("domains", [])
    hashes = data.get("hashes", [])

    malicious_ips.update(ips)
    malicious_domains.update(d.lower() for d in domains)
    malicious_hashes.update(h.lower() for h in hashes)

    return (
        jsonify(
            {
                "message": "Indicators imported successfully",
                "imported": {
                    "ips": len(ips),
                    "domains": len(domains),
                    "hashes": len(hashes),
                },
            }
        ),
        200,
    )


@app.route("/statistics", methods=["GET"])
def get_statistics():
    """Get service statistics."""
    return (
        jsonify(
            {
                **statistics,
                "cache_size": len(cache),
                "malicious_ips_cached": len(malicious_ips),
                "malicious_domains_cached": len(malicious_domains),
                "malicious_hashes_cached": len(malicious_hashes),
                "xforce_configured": bool(XFORCE_API_KEY and XFORCE_API_PASSWORD),
                "otx_configured": bool(OTX_API_KEY),
            }
        ),
        200,
    )


@app.route("/cache/clear", methods=["POST"])
def clear_cache():
    """Clear the intelligence cache."""
    cache.clear()
    return jsonify({"message": "Cache cleared successfully"}), 200


if __name__ == "__main__":
    port = app.config.get("THREAT_INTEL_PORT", 5005)
    logger.info(f"Starting Threat Intelligence Service on port {port}")
    logger.info(f"X-Force API configured: {bool(XFORCE_API_KEY and XFORCE_API_PASSWORD)}")
    logger.info(f"OTX API configured: {bool(OTX_API_KEY)}")

    app.run(host="0.0.0.0", port=port, debug=app.config.get("DEBUG", False))
