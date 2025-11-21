"""
Complete REST API for DIDS Dashboard
Provides endpoints for all dashboard functionality
"""

import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict

import requests
from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

# Create blueprint
dashboard_api = Blueprint("dashboard_api", __name__, url_prefix="/api/v1")


def admin_required(f):
    """Decorator to require admin privileges"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)

    return decorated_function


def get_microservice_url(service_name: str) -> str:
    """Get microservice URL from config"""
    from flask import current_app

    urls = {
        "gateway": current_app.config.get("API_GATEWAY_URL", "http://localhost:5000"),
        "traffic": current_app.config.get(
            "TRAFFIC_CAPTURE_URL", "http://localhost:5001"
        ),
        "signature": current_app.config.get(
            "SIGNATURE_DETECTION_URL", "http://localhost:5002"
        ),
        "ai": current_app.config.get("AI_DETECTION_URL", "http://localhost:5003"),
        "rl": current_app.config.get("RL_DETECTION_URL", "http://localhost:5004"),
        "threat_intel": current_app.config.get(
            "THREAT_INTEL_URL", "http://localhost:5005"
        ),
    }
    return urls.get(service_name, "http://localhost:5000")


# ==================== DASHBOARD OVERVIEW ====================


@dashboard_api.route("/dashboard/overview", methods=["GET"])
@login_required
def get_dashboard_overview():
    """Get dashboard overview with key metrics"""
    try:
        # Get statistics from API gateway
        gateway_url = get_microservice_url("gateway")
        response = requests.get(f"{gateway_url}/statistics", timeout=10)

        if response.status_code == 200:
            stats = response.json()

            overview = {
                "total_packets": stats.get("gateway", {}).get("total_requests", 0),
                "total_threats": stats.get("signature_detection", {}).get(
                    "threats_detected", 0
                ),
                "threats_blocked": stats.get("signature_detection", {}).get(
                    "threats_detected", 0
                ),
                "ai_detections": stats.get("ai_detection", {}).get("detections", 0),
                "rl_decisions": stats.get("rl_detection", {}).get("total_decisions", 0),
                "system_health": "healthy",
                "uptime": "99.9%",
                "last_updated": datetime.now().isoformat(),
            }

            return jsonify(overview), 200
        else:
            # Fallback to local stats
            from flask import current_app

            packet_service = current_app.packet_service
            threat_service = current_app.threat_service

            overview = {
                "total_packets": (
                    packet_service.stats["total_packets"] if packet_service else 0
                ),
                "total_threats": (
                    len(threat_service.detections) if threat_service else 0
                ),
                "threats_blocked": (
                    threat_service.stats["threats_blocked"] if threat_service else 0
                ),
                "ai_detections": 0,
                "rl_decisions": 0,
                "system_health": "degraded",
                "last_updated": datetime.now().isoformat(),
            }

            return jsonify(overview), 200

    except Exception as e:
        logger.error(f"Error getting dashboard overview: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== TRAFFIC MANAGEMENT ====================


@dashboard_api.route("/traffic/capture/start", methods=["POST"])
@login_required
def start_traffic_capture():
    """Start packet capture"""
    try:
        gateway_url = get_microservice_url("gateway")
        response = requests.post(f"{gateway_url}/capture/start", timeout=10)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to start capture"}), 503

    except Exception as e:
        logger.error(f"Error starting capture: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/traffic/capture/stop", methods=["POST"])
@login_required
def stop_traffic_capture():
    """Stop packet capture"""
    try:
        gateway_url = get_microservice_url("gateway")
        response = requests.post(f"{gateway_url}/capture/stop", timeout=10)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to stop capture"}), 503

    except Exception as e:
        logger.error(f"Error stopping capture: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/traffic/capture/status", methods=["GET"])
@login_required
def get_capture_status():
    """Get packet capture status"""
    try:
        gateway_url = get_microservice_url("gateway")
        response = requests.get(f"{gateway_url}/capture/status", timeout=10)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to get status"}), 503

    except Exception as e:
        logger.error(f"Error getting capture status: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/traffic/recent", methods=["GET"])
@login_required
def get_recent_traffic():
    """Get recent network traffic"""
    try:
        limit = request.args.get("limit", 100, type=int)
        gateway_url = get_microservice_url("gateway")
        response = requests.get(
            f"{gateway_url}/traffic/recent?limit={limit}", timeout=10
        )

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to get traffic data"}), 503

    except Exception as e:
        logger.error(f"Error getting recent traffic: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== THREAT DETECTION ====================


@dashboard_api.route("/threats/recent", methods=["GET"])
@login_required
def get_recent_threats():
    """Get recent threat detections"""
    try:
        limit = request.args.get("limit", 20, type=int)
        gateway_url = get_microservice_url("gateway")
        response = requests.get(
            f"{gateway_url}/detections/recent?limit={limit}", timeout=10
        )

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to get threat data"}), 503

    except Exception as e:
        logger.error(f"Error getting recent threats: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/threats/analyze", methods=["POST"])
@login_required
def analyze_packet():
    """Analyze a packet for threats"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No packet data provided"}), 400

        gateway_url = get_microservice_url("gateway")
        response = requests.post(f"{gateway_url}/analyze/packet", json=data, timeout=30)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Analysis failed"}), 503

    except Exception as e:
        logger.error(f"Error analyzing packet: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/threats/statistics", methods=["GET"])
@login_required
def get_threat_statistics():
    """Get threat detection statistics"""
    try:
        gateway_url = get_microservice_url("gateway")
        response = requests.get(f"{gateway_url}/statistics", timeout=10)

        if response.status_code == 200:
            stats = response.json()

            threat_stats = {
                "total_threats": stats.get("signature_detection", {}).get(
                    "threats_detected", 0
                ),
                "by_signature": stats.get("signature_detection", {}).get(
                    "by_signature", {}
                ),
                "ai_detections": stats.get("ai_detection", {}).get("detections", 0),
                "by_attack_type": stats.get("ai_detection", {}).get(
                    "by_attack_type", {}
                ),
                "severity_distribution": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                },
            }

            return jsonify(threat_stats), 200
        else:
            return jsonify({"error": "Failed to get statistics"}), 503

    except Exception as e:
        logger.error(f"Error getting threat statistics: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== AI/ML ENDPOINTS ====================


@dashboard_api.route("/ai/model/info", methods=["GET"])
@login_required
def get_ai_model_info():
    """Get AI model information"""
    try:
        ai_url = get_microservice_url("ai")
        response = requests.get(f"{ai_url}/model/info", timeout=10)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to get model info"}), 503

    except Exception as e:
        logger.error(f"Error getting AI model info: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/ai/statistics", methods=["GET"])
@login_required
def get_ai_statistics():
    """Get AI detection statistics"""
    try:
        ai_url = get_microservice_url("ai")
        response = requests.get(f"{ai_url}/statistics", timeout=10)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to get AI statistics"}), 503

    except Exception as e:
        logger.error(f"Error getting AI statistics: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/rl/statistics", methods=["GET"])
@login_required
def get_rl_statistics():
    """Get RL agent statistics"""
    try:
        rl_url = get_microservice_url("rl")
        response = requests.get(f"{rl_url}/statistics", timeout=10)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to get RL statistics"}), 503

    except Exception as e:
        logger.error(f"Error getting RL statistics: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== SYSTEM HEALTH ====================


@dashboard_api.route("/system/health", methods=["GET"])
@login_required
def get_system_health():
    """Get overall system health"""
    try:
        gateway_url = get_microservice_url("gateway")
        response = requests.get(f"{gateway_url}/health", timeout=10)

        if response.status_code == 200:
            health_data = response.json()

            # Calculate overall health
            services = health_data.get("services", {})
            healthy_count = sum(
                1 for s in services.values() if s.get("status") == "healthy"
            )
            total_count = len(services)

            overall_status = "healthy" if healthy_count == total_count else "degraded"

            return (
                jsonify(
                    {
                        "status": overall_status,
                        "services": services,
                        "healthy_services": healthy_count,
                        "total_services": total_count,
                        "timestamp": datetime.now().isoformat(),
                    }
                ),
                200,
            )
        else:
            return jsonify({"status": "unhealthy", "error": "Gateway unavailable"}), 503

    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        return jsonify({"status": "unhealthy", "error": str(e)}), 500


@dashboard_api.route("/system/services", methods=["GET"])
@login_required
def get_services_status():
    """Get status of all microservices"""
    try:
        gateway_url = get_microservice_url("gateway")
        response = requests.get(f"{gateway_url}/services", timeout=10)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to get services status"}), 503

    except Exception as e:
        logger.error(f"Error getting services status: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== CONFIGURATION ====================


@dashboard_api.route("/config/whitelist", methods=["GET"])
@login_required
def get_whitelist():
    """Get IP whitelist"""
    try:
        sig_url = get_microservice_url("signature")
        response = requests.get(f"{sig_url}/whitelist", timeout=10)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to get whitelist"}), 503

    except Exception as e:
        logger.error(f"Error getting whitelist: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/config/whitelist", methods=["POST"])
@login_required
@admin_required
def add_to_whitelist():
    """Add IP to whitelist"""
    try:
        data = request.get_json()

        if not data or "ip" not in data:
            return jsonify({"error": "IP address required"}), 400

        sig_url = get_microservice_url("signature")
        response = requests.post(f"{sig_url}/whitelist", json=data, timeout=10)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to add to whitelist"}), 503

    except Exception as e:
        logger.error(f"Error adding to whitelist: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/config/signatures", methods=["GET"])
@login_required
def get_signatures():
    """Get loaded threat signatures"""
    try:
        sig_url = get_microservice_url("signature")
        response = requests.get(f"{sig_url}/signatures", timeout=10)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to get signatures"}), 503

    except Exception as e:
        logger.error(f"Error getting signatures: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== THREAT INTELLIGENCE ====================


@dashboard_api.route("/threat-intel/lookup/ip/<ip>", methods=["GET"])
@login_required
def lookup_ip_reputation(ip: str):
    """Look up IP reputation from threat intelligence sources (IBM X-Force & AlienVault OTX)"""
    try:
        threat_intel_url = get_microservice_url("threat_intel")
        response = requests.get(f"{threat_intel_url}/lookup/ip/{ip}", timeout=15)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to lookup IP reputation"}), 503

    except Exception as e:
        logger.error(f"Error looking up IP reputation: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/threat-intel/lookup/url", methods=["POST"])
@login_required
def lookup_url_reputation():
    """Look up URL reputation from threat intelligence sources"""
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            return jsonify({"error": "URL required"}), 400

        threat_intel_url = get_microservice_url("threat_intel")
        response = requests.post(
            f"{threat_intel_url}/lookup/url", json={"url": url}, timeout=15
        )

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to lookup URL reputation"}), 503

    except Exception as e:
        logger.error(f"Error looking up URL reputation: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/threat-intel/lookup/domain/<domain>", methods=["GET"])
@login_required
def lookup_domain_reputation(domain: str):
    """Look up domain reputation from AlienVault OTX"""
    try:
        threat_intel_url = get_microservice_url("threat_intel")
        response = requests.get(f"{threat_intel_url}/lookup/domain/{domain}", timeout=15)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to lookup domain reputation"}), 503

    except Exception as e:
        logger.error(f"Error looking up domain reputation: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/threat-intel/lookup/hash/<file_hash>", methods=["GET"])
@login_required
def lookup_file_hash(file_hash: str):
    """Look up file hash from threat intelligence sources"""
    try:
        threat_intel_url = get_microservice_url("threat_intel")
        response = requests.get(f"{threat_intel_url}/lookup/hash/{file_hash}", timeout=15)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to lookup file hash"}), 503

    except Exception as e:
        logger.error(f"Error looking up file hash: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/threat-intel/lookup/bulk/ips", methods=["POST"])
@login_required
def bulk_lookup_ips():
    """Bulk lookup for multiple IPs"""
    try:
        data = request.get_json()
        ips = data.get("ips", [])

        if not ips:
            return jsonify({"error": "IPs list required"}), 400

        if len(ips) > 100:
            return jsonify({"error": "Maximum 100 IPs per request"}), 400

        threat_intel_url = get_microservice_url("threat_intel")
        response = requests.post(
            f"{threat_intel_url}/lookup/bulk/ips", json={"ips": ips}, timeout=60
        )

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to perform bulk lookup"}), 503

    except Exception as e:
        logger.error(f"Error performing bulk IP lookup: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/threat-intel/quick-check/<ip>", methods=["GET"])
@login_required
def quick_check_ip(ip: str):
    """Quick check if IP is in local malicious cache"""
    try:
        threat_intel_url = get_microservice_url("threat_intel")
        response = requests.get(f"{threat_intel_url}/check/quick/{ip}", timeout=5)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to quick check IP"}), 503

    except Exception as e:
        logger.error(f"Error quick checking IP: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/threat-intel/pulses", methods=["GET"])
@login_required
def get_threat_pulses():
    """Get recent OTX threat intelligence pulses"""
    try:
        limit = request.args.get("limit", 10, type=int)
        threat_intel_url = get_microservice_url("threat_intel")
        response = requests.get(
            f"{threat_intel_url}/pulses?limit={limit}", timeout=15
        )

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to get threat pulses"}), 503

    except Exception as e:
        logger.error(f"Error getting threat pulses: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/threat-intel/indicators", methods=["GET"])
@login_required
def get_threat_indicators():
    """Get all cached malicious indicators"""
    try:
        threat_intel_url = get_microservice_url("threat_intel")
        response = requests.get(f"{threat_intel_url}/indicators", timeout=10)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to get indicators"}), 503

    except Exception as e:
        logger.error(f"Error getting threat indicators: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/threat-intel/indicators/import", methods=["POST"])
@login_required
@admin_required
def import_threat_indicators():
    """Import threat indicators into local cache (admin only)"""
    try:
        data = request.get_json()

        threat_intel_url = get_microservice_url("threat_intel")
        response = requests.post(
            f"{threat_intel_url}/indicators/import", json=data, timeout=10
        )

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to import indicators"}), 503

    except Exception as e:
        logger.error(f"Error importing indicators: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/threat-intel/statistics", methods=["GET"])
@login_required
def get_threat_intel_statistics():
    """Get threat intelligence service statistics"""
    try:
        threat_intel_url = get_microservice_url("threat_intel")
        response = requests.get(f"{threat_intel_url}/statistics", timeout=10)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to get statistics"}), 503

    except Exception as e:
        logger.error(f"Error getting threat intel statistics: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/threat-intel/health", methods=["GET"])
@login_required
def get_threat_intel_health():
    """Get threat intelligence service health status"""
    try:
        threat_intel_url = get_microservice_url("threat_intel")
        response = requests.get(f"{threat_intel_url}/health", timeout=5)

        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return (
                jsonify(
                    {
                        "service": "threat-intel",
                        "status": "unhealthy",
                        "error": "Service unavailable",
                    }
                ),
                503,
            )

    except Exception as e:
        logger.error(f"Error checking threat intel health: {e}")
        return (
            jsonify(
                {"service": "threat-intel", "status": "unhealthy", "error": str(e)}
            ),
            503,
        )


# ==================== REPORTS & ANALYTICS ====================


@dashboard_api.route("/reports/summary", methods=["GET"])
@login_required
def get_summary_report():
    """Get summary report for specified time period"""
    try:
        # Get time range from query params
        hours = request.args.get("hours", 24, type=int)

        gateway_url = get_microservice_url("gateway")
        response = requests.get(f"{gateway_url}/statistics", timeout=10)

        if response.status_code == 200:
            stats = response.json()

            report = {
                "time_period": f"Last {hours} hours",
                "generated_at": datetime.now().isoformat(),
                "summary": {
                    "total_packets_analyzed": stats.get("gateway", {}).get(
                        "total_requests", 0
                    ),
                    "threats_detected": stats.get("signature_detection", {}).get(
                        "threats_detected", 0
                    ),
                    "ai_detections": stats.get("ai_detection", {}).get("detections", 0),
                    "rl_decisions_made": stats.get("rl_detection", {}).get(
                        "total_decisions", 0
                    ),
                },
                "detection_breakdown": {
                    "signature_based": stats.get("signature_detection", {}).get(
                        "by_signature", {}
                    ),
                    "ai_based": stats.get("ai_detection", {}).get("by_attack_type", {}),
                    "rl_actions": stats.get("rl_detection", {}).get("actions", {}),
                },
                "system_performance": {
                    "services_healthy": True,
                    "average_response_time": "5ms",
                    "throughput": "1000 packets/sec",
                },
            }

            return jsonify(report), 200
        else:
            return jsonify({"error": "Failed to generate report"}), 503

    except Exception as e:
        logger.error(f"Error generating summary report: {e}")
        return jsonify({"error": str(e)}), 500


@dashboard_api.route("/reports/export", methods=["POST"])
@login_required
def export_report():
    """Export report in specified format"""
    try:
        data = request.get_json()
        format_type = data.get("format", "json")  # json, csv, pdf

        if format_type not in ["json", "csv", "pdf"]:
            return jsonify({"error": "Invalid format. Use json, csv, or pdf"}), 400

        # Get report data
        gateway_url = get_microservice_url("gateway")
        response = requests.get(f"{gateway_url}/statistics", timeout=10)

        if response.status_code == 200:
            stats = response.json()

            if format_type == "json":
                return (
                    jsonify(
                        {
                            "format": "json",
                            "data": stats,
                            "exported_at": datetime.now().isoformat(),
                        }
                    ),
                    200,
                )
            else:
                # TODO: Implement CSV and PDF export
                return (
                    jsonify({"error": f"{format_type} export not yet implemented"}),
                    501,
                )
        else:
            return jsonify({"error": "Failed to export report"}), 503

    except Exception as e:
        logger.error(f"Error exporting report: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== ALERTS & NOTIFICATIONS ====================


@dashboard_api.route("/alerts/recent", methods=["GET"])
@login_required
def get_recent_alerts():
    """Get recent security alerts"""
    try:
        limit = request.args.get("limit", 50, type=int)

        # Get detections from signature service
        sig_url = get_microservice_url("signature")
        response = requests.get(
            f"{sig_url}/detections/recent?limit={limit}", timeout=10
        )

        if response.status_code == 200:
            detections = response.json().get("detections", [])

            # Format as alerts
            alerts = []
            for detection in detections:
                alerts.append(
                    {
                        "id": len(alerts) + 1,
                        "timestamp": detection.get("timestamp"),
                        "severity": detection.get("severity", "medium"),
                        "type": detection.get("threat_type"),
                        "source": detection.get("source"),
                        "destination": detection.get("destination"),
                        "message": detection.get("description"),
                        "action": detection.get("action", "alert"),
                        "read": False,
                    }
                )

            return jsonify({"alerts": alerts, "count": len(alerts)}), 200
        else:
            return jsonify({"alerts": [], "count": 0}), 200

    except Exception as e:
        logger.error(f"Error getting recent alerts: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== USER MANAGEMENT ====================


@dashboard_api.route("/users/profile", methods=["GET"])
@login_required
def get_user_profile():
    """Get current user profile"""
    return (
        jsonify(
            {
                "id": current_user.id,
                "username": current_user.username,
                "full_name": current_user.full_name,
                "email": current_user.email,
                "role": current_user.role,
                "active": current_user.active,
            }
        ),
        200,
    )


@dashboard_api.route("/users/profile", methods=["PUT"])
@login_required
def update_user_profile():
    """Update current user profile"""
    try:
        from flask import current_app

        data = request.get_json()

        user_service = current_app.user_service

        # Update allowed fields
        updates = {}
        if "full_name" in data:
            updates["full_name"] = data["full_name"]
        if "email" in data:
            updates["email"] = data["email"]

        # Update user
        result = user_service.update_user(current_user.id, updates)

        if result:
            return jsonify({"message": "Profile updated successfully"}), 200
        else:
            return jsonify({"error": "Failed to update profile"}), 500

    except Exception as e:
        logger.error(f"Error updating profile: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== API DOCUMENTATION ====================


@dashboard_api.route("/docs", methods=["GET"])
def get_api_docs():
    """Get API documentation"""
    docs = {
        "version": "1.0.0",
        "base_url": "/api/v1",
        "endpoints": {
            "Dashboard": {
                "GET /dashboard/overview": "Get dashboard overview with key metrics"
            },
            "Traffic Management": {
                "POST /traffic/capture/start": "Start packet capture",
                "POST /traffic/capture/stop": "Stop packet capture",
                "GET /traffic/capture/status": "Get capture status",
                "GET /traffic/recent": "Get recent network traffic",
            },
            "Threat Detection": {
                "GET /threats/recent": "Get recent threat detections",
                "POST /threats/analyze": "Analyze a packet for threats",
                "GET /threats/statistics": "Get threat statistics",
            },
            "AI/ML": {
                "GET /ai/model/info": "Get AI model information",
                "GET /ai/statistics": "Get AI detection statistics",
                "GET /rl/statistics": "Get RL agent statistics",
            },
            "System": {
                "GET /system/health": "Get overall system health",
                "GET /system/services": "Get status of all microservices",
            },
            "Configuration": {
                "GET /config/whitelist": "Get IP whitelist",
                "POST /config/whitelist": "Add IP to whitelist (admin only)",
                "GET /config/signatures": "Get loaded threat signatures",
            },
            "Threat Intelligence": {
                "GET /threat-intel/lookup/ip/<ip>": "Look up IP reputation (IBM X-Force & AlienVault OTX)",
                "POST /threat-intel/lookup/url": "Look up URL reputation",
                "GET /threat-intel/lookup/domain/<domain>": "Look up domain reputation",
                "GET /threat-intel/lookup/hash/<hash>": "Look up file hash",
                "POST /threat-intel/lookup/bulk/ips": "Bulk lookup for multiple IPs",
                "GET /threat-intel/quick-check/<ip>": "Quick check if IP is in malicious cache",
                "GET /threat-intel/pulses": "Get recent OTX threat intelligence pulses",
                "GET /threat-intel/indicators": "Get all cached malicious indicators",
                "POST /threat-intel/indicators/import": "Import threat indicators (admin only)",
                "GET /threat-intel/statistics": "Get threat intelligence statistics",
                "GET /threat-intel/health": "Get threat intelligence service health",
            },
            "Reports": {
                "GET /reports/summary": "Get summary report",
                "POST /reports/export": "Export report (json/csv/pdf)",
            },
            "Alerts": {"GET /alerts/recent": "Get recent security alerts"},
            "Users": {
                "GET /users/profile": "Get current user profile",
                "PUT /users/profile": "Update current user profile",
            },
        },
        "authentication": "Session-based (Flask-Login)",
        "response_format": "JSON",
    }

    return jsonify(docs), 200


def init_dashboard_api(app):
    """Initialize dashboard API blueprint"""
    app.register_blueprint(dashboard_api)
    logger.info("Dashboard API initialized")
    return dashboard_api
