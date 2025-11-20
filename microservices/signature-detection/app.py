"""
Signature Detection Microservice
Handles pattern-based threat detection
"""

import logging
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent))

from shared.config import get_config
from shared.models import ThreatDetection

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(get_config())
CORS(app)

# Configure logging
logging.basicConfig(
    level=getattr(logging, app.config["LOG_LEVEL"]), format=app.config["LOG_FORMAT"]
)
logger = logging.getLogger(__name__)

# Threat signatures
SIGNATURES = {
    "ET MALWARE Reverse Shell": {
        "ports": [4444, 5555, 6666, 7777, 31337],
        "severity": "critical",
        "action": "block",
    },
    "ET SCAN Aggressive Port Scan": {
        "pattern": "port_scan",
        "severity": "high",
        "action": "alert",
    },
    "ET WEB SQL Injection Attempt": {
        "pattern": "sql_injection",
        "severity": "high",
        "action": "block",
    },
    "ET WEB XSS Attack": {"pattern": "xss", "severity": "medium", "action": "alert"},
    "ET DNS Excessive Queries": {
        "pattern": "dns_flood",
        "severity": "medium",
        "action": "alert",
    },
}

# Malicious payload patterns
PAYLOAD_PATTERNS = {
    "sql_injection": [
        rb"union.*select",
        rb"or\s*1\s*=\s*1",
        rb"drop\s+table",
        rb"\'\s*or\s*\'",
    ],
    "xss": [
        rb"<script",
        rb"javascript:",
        rb"onerror=",
        rb"onload=",
    ],
    "command_injection": [
        rb";.*rm\s+-rf",
        rb"\|\s*nc\s+",
        rb"/bin/bash",
        rb"wget.*http",
    ],
}

# Detection tracking
detections = []
port_scan_tracker = defaultdict(lambda: {"ports": set(), "count": 0, "last_seen": None})
dns_query_tracker = defaultdict(int)
whitelist = set(["127.0.0.1", "::1"])

statistics = {
    "total_checks": 0,
    "threats_detected": 0,
    "by_signature": defaultdict(int),
    "errors": 0,
}


def is_whitelisted(ip: str) -> bool:
    """Check if IP is whitelisted"""
    return ip in whitelist


def check_port_scan(src_ip: str, dst_port: int) -> bool:
    """Detect port scanning behavior"""
    tracker = port_scan_tracker[src_ip]
    tracker["ports"].add(dst_port)
    tracker["count"] += 1
    tracker["last_seen"] = datetime.now()

    # Port scan detected if accessing >10 different ports in short time
    if len(tracker["ports"]) > 10:
        return True

    return False


def check_dns_flood(src_ip: str) -> bool:
    """Detect DNS query flooding"""
    dns_query_tracker[src_ip] += 1

    # DNS flood if >50 queries from same source
    if dns_query_tracker[src_ip] > 50:
        return True

    return False


def check_payload_signatures(payload: bytes) -> list:
    """Check payload against known attack patterns"""
    matches = []

    for attack_type, patterns in PAYLOAD_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                matches.append(attack_type)
                break

    return matches


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return (
        jsonify(
            {
                "service": "signature-detection",
                "status": "healthy",
                "signatures_loaded": len(SIGNATURES),
            }
        ),
        200,
    )


@app.route("/detect", methods=["POST"])
def detect_threats():
    """Detect threats in packet data"""
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data provided"}), 400

    statistics["total_checks"] += 1

    try:
        src_ip = data.get("source")
        dst_ip = data.get("destination")
        src_port = data.get("src_port", 0)
        dst_port = data.get("dst_port", 0)
        protocol = data.get("protocol", "TCP")
        payload = data.get("payload", b"")

        threats = []

        # Skip whitelisted IPs
        if is_whitelisted(src_ip) or is_whitelisted(dst_ip):
            return jsonify({"threats": [], "count": 0}), 200

        # Check suspicious ports
        for sig_name, sig_data in SIGNATURES.items():
            if "ports" in sig_data and dst_port in sig_data["ports"]:
                threat = ThreatDetection(
                    timestamp=datetime.now().isoformat(),
                    source=src_ip,
                    destination=dst_ip,
                    protocol=protocol,
                    threat_type=sig_name,
                    severity=sig_data["severity"],
                    signature=sig_name,
                    confidence=100.0,
                    action=sig_data["action"],
                    description=f"Suspicious connection to port {dst_port}",
                    detector="signature",
                )
                threats.append(threat.to_dict())
                statistics["by_signature"][sig_name] += 1

        # Check for port scan
        if protocol == "TCP" and check_port_scan(src_ip, dst_port):
            threat = ThreatDetection(
                timestamp=datetime.now().isoformat(),
                source=src_ip,
                destination=dst_ip,
                protocol=protocol,
                threat_type="Port Scan",
                severity="high",
                signature="ET SCAN Aggressive Port Scan",
                confidence=95.0,
                action="alert",
                description=f"Port scan detected from {src_ip}",
                detector="signature",
            )
            threats.append(threat.to_dict())
            statistics["by_signature"]["ET SCAN Aggressive Port Scan"] += 1

        # Check for DNS flood
        if dst_port == 53 and check_dns_flood(src_ip):
            threat = ThreatDetection(
                timestamp=datetime.now().isoformat(),
                source=src_ip,
                destination=dst_ip,
                protocol=protocol,
                threat_type="DNS Flood",
                severity="medium",
                signature="ET DNS Excessive Queries",
                confidence=90.0,
                action="alert",
                description=f"DNS flood detected from {src_ip}",
                detector="signature",
            )
            threats.append(threat.to_dict())
            statistics["by_signature"]["ET DNS Excessive Queries"] += 1

        # Check payload patterns
        if payload and isinstance(payload, (bytes, str)):
            if isinstance(payload, str):
                payload = payload.encode()

            matches = check_payload_signatures(payload)
            for attack_type in matches:
                threat = ThreatDetection(
                    timestamp=datetime.now().isoformat(),
                    source=src_ip,
                    destination=dst_ip,
                    protocol=protocol,
                    threat_type=attack_type,
                    severity="high",
                    signature=f"ET WEB {attack_type.upper()}",
                    confidence=85.0,
                    action="block",
                    description=f"{attack_type} pattern detected in payload",
                    detector="signature",
                )
                threats.append(threat.to_dict())
                statistics["by_signature"][f"ET WEB {attack_type}"] += 1

        # Store detections
        if threats:
            detections.extend(threats)
            statistics["threats_detected"] += len(threats)

            # Keep only recent detections
            if len(detections) > 1000:
                del detections[:500]

        return jsonify({"threats": threats, "count": len(threats)}), 200

    except Exception as e:
        logger.error(f"Error detecting threats: {e}")
        statistics["errors"] += 1
        return jsonify({"error": str(e)}), 500


@app.route("/detections/recent", methods=["GET"])
def get_recent_detections():
    """Get recent threat detections"""
    limit = request.args.get("limit", 20, type=int)
    return (
        jsonify({"detections": detections[-limit:], "count": len(detections[-limit:])}),
        200,
    )


@app.route("/statistics", methods=["GET"])
def get_statistics():
    """Get detection statistics"""
    return (
        jsonify(
            {
                "total_checks": statistics["total_checks"],
                "threats_detected": statistics["threats_detected"],
                "by_signature": dict(statistics["by_signature"]),
                "errors": statistics["errors"],
            }
        ),
        200,
    )


@app.route("/signatures", methods=["GET"])
def get_signatures():
    """Get loaded signatures"""
    return (
        jsonify({"signatures": list(SIGNATURES.keys()), "count": len(SIGNATURES)}),
        200,
    )


@app.route("/whitelist", methods=["GET"])
def get_whitelist():
    """Get whitelisted IPs"""
    return jsonify({"whitelist": list(whitelist)}), 200


@app.route("/whitelist", methods=["POST"])
def add_to_whitelist():
    """Add IP to whitelist"""
    data = request.get_json()
    ip = data.get("ip")

    if not ip:
        return jsonify({"error": "IP address required"}), 400

    whitelist.add(ip)
    return jsonify({"message": f"Added {ip} to whitelist"}), 200


if __name__ == "__main__":
    port = app.config["SIGNATURE_DETECTION_PORT"]
    logger.info(f"Starting Signature Detection Service on port {port}")
    logger.info(f"Loaded {len(SIGNATURES)} threat signatures")

    app.run(host="0.0.0.0", port=port, debug=app.config["DEBUG"])
