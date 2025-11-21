from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

api_bp = Blueprint("api", __name__, url_prefix="/api")


def init_api_routes(app, packet_service, threat_service, ai_service=None, rl_service=None):
    """Initialize API routes with dependencies including AI and RL services"""

    # Get RL service from app context if not passed directly
    if rl_service is None:
        rl_service = getattr(app, 'rl_service', None)

    @api_bp.route("/current_user")
    @login_required
    def current_user_info():
        return jsonify(
            {
                "name": (
                    current_user.full_name
                    if hasattr(current_user, "full_name")
                    else current_user.username
                ),
                "username": current_user.username,
                "role": current_user.role,
            }
        )

    @api_bp.route("/traffic")
    @login_required
    def traffic():
        """Get recent traffic data with AI detections"""
        return jsonify(packet_service.get_traffic_data(limit=100))

    @api_bp.route("/stats")
    @login_required
    def stats():
        """Get network statistics including AI detections"""
        stats_data = packet_service.get_stats()
        traffic_data = packet_service.get_traffic_data(limit=100)

        # Calculate packets per second
        now = datetime.now()
        pps = 0
        try:
            pps = sum(
                1
                for p in traffic_data
                if (now - datetime.strptime(p["timestamp"], "%H:%M:%S.%f"))
                < timedelta(seconds=1)
            )
        except Exception as e:
            app.logger.error(f"Error calculating PPS: {e}")

        stats_data["pps"] = pps
        stats_data["flow_count"] = packet_service.get_flow_count()
        return jsonify(stats_data)

    @api_bp.route("/threats")
    @login_required
    def threats():
        """Get recent threat detections (signature-based)"""
        limit = request.args.get("limit", 100, type=int)
        return jsonify(threat_service.get_recent_threats(limit=limit))

    @api_bp.route("/threat-stats")
    @login_required
    def threat_stats():
        """Get threat statistics"""
        return jsonify(threat_service.get_threat_statistics())

    @api_bp.route("/ai-detections")
    @login_required
    def ai_detections():
        """Get recent AI-based threat detections"""
        if ai_service and ai_service.is_ready():
            return jsonify(ai_service.get_recent_detections(limit=20))
        return jsonify([])

    @api_bp.route("/ai-stats")
    @login_required
    def ai_stats():
        """Get AI detection statistics"""
        if ai_service and ai_service.is_ready():
            return jsonify(ai_service.get_detection_statistics())
        return jsonify(
            {
                "total_detections": 0,
                "by_attack_type": {},
                "by_severity": {},
                "by_action": {},
                "average_confidence": 0.0,
                "high_confidence_count": 0,
            }
        )

    @api_bp.route("/ai-model-info")
    @login_required
    def ai_model_info():
        """Get AI model information"""
        if ai_service:
            return jsonify(ai_service.get_model_info())
        return jsonify({"model_loaded": False, "error": "AI service not available"})

    @api_bp.route("/rl-stats")
    @login_required
    def rl_stats():
        """Get RL detection statistics"""
        if rl_service and rl_service.is_ready():
            return jsonify(rl_service.get_statistics())
        return jsonify({
            "total_decisions": 0,
            "threats_blocked": 0,
            "alerts_raised": 0,
            "actions_distribution": {"allow": 0, "alert": 0, "block": 0},
            "recent_detections": 0,
            "rl_model_loaded": False,
            "block_threshold": 0.70,
            "alert_threshold": 0.50,
        })

    @api_bp.route("/rl-decisions")
    @login_required
    def rl_decisions():
        """Get recent RL decisions"""
        if rl_service and rl_service.is_ready():
            limit = request.args.get("limit", 20, type=int)
            return jsonify(rl_service.get_recent_decisions(limit=limit))
        return jsonify([])

    @api_bp.route("/combined-threats")
    @login_required
    def combined_threats():
        """Get combined threats from signature, AI, and RL detection"""
        limit = request.args.get("limit", 100, type=int)
        combined = []

        # Get signature-based threats
        sig_threats = threat_service.get_recent_threats(limit=limit)
        for threat in sig_threats:
            threat["detection_method"] = "signature"
            combined.append(threat)

        # Get AI-based threats
        if ai_service and ai_service.is_ready():
            ai_threats = ai_service.get_recent_detections(limit=limit)
            for threat in ai_threats:
                threat["detection_method"] = "ai"
                combined.append(threat)

        # Get RL-based decisions (alerts and blocks)
        if rl_service and rl_service.is_ready():
            rl_decisions = rl_service.get_recent_decisions(limit=limit)
            for decision in rl_decisions:
                # Convert RL decision to threat format
                rl_threat = {
                    "timestamp": decision.get("timestamp", datetime.now().isoformat()),
                    "source": decision.get("source"),
                    "destination": decision.get("destination"),
                    "protocol": decision.get("protocol"),
                    "signature": f"RL Decision: {decision.get('action', 'unknown').upper()}",
                    "attack_type": decision.get("reason", "RL Adaptive Response"),
                    "confidence": decision.get("confidence", 0),
                    "action": decision.get("action", "alert"),
                    "detection_method": "rl",
                    "rl_based": True,
                    "q_values": decision.get("q_values", {})
                }
                combined.append(rl_threat)

        # Sort by timestamp (newest first)
        combined.sort(key=lambda x: x["timestamp"], reverse=True)

        return jsonify(combined[:limit])

    @api_bp.route("/capture/status")
    @login_required
    def capture_status():
        """Get packet capture status"""
        return jsonify(
            {
                "active": packet_service.get_capture_status(),
                "flow_count": packet_service.get_flow_count(),
            }
        )

    @api_bp.route("/capture/toggle", methods=["POST"])
    @login_required
    def toggle_capture():
        """Toggle packet capture on/off"""
        new_status = packet_service.toggle_capture()
        return jsonify({"success": True, "active": new_status})

    @api_bp.route("/network-health")
    @login_required
    def network_health():
        """Get network health metrics"""
        stats = packet_service.get_stats()
        threat_stats = threat_service.get_threat_statistics()

        # Include AI detection stats if available
        ai_detections = 0
        if ai_service and ai_service.is_ready():
            ai_stats = ai_service.get_detection_statistics()
            ai_detections = ai_stats.get("total_detections", 0)

        # Calculate health score (simple algorithm)
        total_packets = stats.get("total_packets", 0)
        threats_blocked = threat_stats.get("blocked_count", 0) + ai_detections

        if total_packets > 0:
            threat_ratio = threats_blocked / total_packets
            health_score = max(0, 100 - (threat_ratio * 1000))
        else:
            health_score = 100

        return jsonify(
            {
                "health_score": round(health_score, 2),
                "status": (
                    "healthy"
                    if health_score > 80
                    else "warning" if health_score > 50 else "critical"
                ),
                "total_packets": total_packets,
                "threats_detected": threat_stats.get("total_threats", 0)
                + ai_detections,
                "threats_blocked": threats_blocked,
                "ai_detections": ai_detections,
            }
        )

    @api_bp.route("/signatures")
    @login_required
    def signatures():
        """Get all threat signatures"""
        return jsonify(threat_service.get_all_signatures())

    @api_bp.route("/ai-threshold", methods=["POST"])
    @login_required
    def set_ai_threshold():
        """Set AI detection confidence threshold"""
        if not ai_service or not ai_service.is_ready():
            return jsonify({"success": False, "error": "AI service not available"}), 400

        try:
            data = request.get_json()
            threshold = float(data.get("threshold", 0.75))

            if ai_service.set_confidence_threshold(threshold):
                return jsonify({"success": True, "threshold": threshold})
            else:
                return (
                    jsonify({"success": False, "error": "Invalid threshold value"}),
                    400,
                )
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

    @api_bp.route("/rl-threshold", methods=["GET", "POST"])
    @login_required
    def rl_threshold():
        """Get or set RL detection confidence thresholds"""
        if not rl_service or not rl_service.is_ready():
            return jsonify({"success": False, "error": "RL service not available"}), 400

        if request.method == "GET":
            return jsonify({
                "success": True,
                "thresholds": rl_service.get_thresholds()
            })

        try:
            data = request.get_json()
            results = {"success": True, "updated": {}}

            # Update block threshold if provided
            if "block_threshold" in data:
                block_val = float(data["block_threshold"])
                if rl_service.set_block_threshold(block_val):
                    results["updated"]["block_threshold"] = block_val
                else:
                    return jsonify({"success": False, "error": "Invalid block threshold (must be 0.0-1.0)"}), 400

            # Update alert threshold if provided
            if "alert_threshold" in data:
                alert_val = float(data["alert_threshold"])
                if rl_service.set_alert_threshold(alert_val):
                    results["updated"]["alert_threshold"] = alert_val
                else:
                    return jsonify({"success": False, "error": "Invalid alert threshold (must be 0.0-1.0)"}), 400

            results["thresholds"] = rl_service.get_thresholds()
            return jsonify(results)

        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

    @api_bp.route("/detection-thresholds", methods=["GET"])
    @login_required
    def get_detection_thresholds():
        """Get all detection thresholds (AI and RL)"""
        thresholds = {
            "ai": {
                "enabled": ai_service is not None and ai_service.is_ready(),
                "confidence_threshold": ai_service.confidence_threshold if ai_service else 0.50,
            },
            "rl": {
                "enabled": rl_service is not None and rl_service.is_ready(),
                "block_threshold": rl_service.block_threshold if rl_service else 0.70,
                "alert_threshold": rl_service.alert_threshold if rl_service else 0.50,
            }
        }
        return jsonify(thresholds)

    @api_bp.route("/detection-overview")
    @login_required
    def detection_overview():
        """Get overview of all detection methods"""
        sig_stats = threat_service.get_threat_statistics()

        overview = {
            "signature_based": {
                "total": sig_stats.get("total_threats", 0),
                "blocked": sig_stats.get("blocked_count", 0),
                "by_severity": sig_stats.get("by_severity", {}),
            },
            "ai_based": {
                "enabled": ai_service is not None and ai_service.is_ready(),
                "total": 0,
                "high_confidence": 0,
                "by_attack_type": {},
            },
            "rl_based": {
                "enabled": rl_service is not None and rl_service.is_ready(),
                "total_decisions": 0,
                "threats_blocked": 0,
                "alerts_raised": 0,
                "actions_distribution": {"allow": 0, "alert": 0, "block": 0},
            },
        }

        if ai_service and ai_service.is_ready():
            ai_stats = ai_service.get_detection_statistics()
            overview["ai_based"] = {
                "enabled": True,
                "total": ai_stats.get("total_detections", 0),
                "high_confidence": ai_stats.get("high_confidence_count", 0),
                "by_attack_type": ai_stats.get("by_attack_type", {}),
                "average_confidence": ai_stats.get("average_confidence", 0),
            }

        if rl_service and rl_service.is_ready():
            rl_stats = rl_service.get_statistics()
            overview["rl_based"] = {
                "enabled": True,
                "total_decisions": rl_stats.get("total_decisions", 0),
                "threats_blocked": rl_stats.get("threats_blocked", 0),
                "alerts_raised": rl_stats.get("alerts_raised", 0),
                "actions_distribution": rl_stats.get("actions_distribution", {}),
            }

        return jsonify(overview)

    # =========================================================================
    # SIMULATION / TESTING ENDPOINTS
    # =========================================================================

    @api_bp.route("/inject-packet", methods=["POST"])
    @login_required
    def inject_packet():
        """
        Inject a simulated packet for testing detection capabilities.
        This endpoint allows testing the detection system without actual network traffic.

        Request body:
        {
            "source": "185.220.101.42",
            "destination": "10.0.0.50",
            "protocol": "TCP",
            "src_port": 54321,
            "dst_port": 80,
            "size": 512,
            "tcp_flags": {"syn": true, "ack": false},
            "payload": "hex-encoded-payload",
            "attack_type": "DDoS",
            "severity": "high"
        }
        """
        try:
            data = request.get_json()
            if not data:
                return jsonify({"success": False, "error": "No packet data provided"}), 400

            # Validate required fields
            required = ["source", "destination"]
            for field in required:
                if field not in data:
                    return jsonify({"success": False, "error": f"Missing required field: {field}"}), 400

            # Inject packet into detection pipeline
            result = packet_service.inject_simulated_packet(data)

            return jsonify(result)

        except Exception as e:
            app.logger.error(f"Error injecting packet: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @api_bp.route("/inject-batch", methods=["POST"])
    @login_required
    def inject_batch():
        """
        Inject multiple simulated packets at once for bulk testing.

        Request body:
        {
            "packets": [
                {"source": "...", "destination": "...", ...},
                {"source": "...", "destination": "...", ...}
            ]
        }
        """
        try:
            data = request.get_json()
            if not data or "packets" not in data:
                return jsonify({"success": False, "error": "No packets array provided"}), 400

            packets = data["packets"]
            if not isinstance(packets, list):
                return jsonify({"success": False, "error": "packets must be an array"}), 400

            results = []
            threats_detected = 0
            total_detections = 0

            for packet_data in packets:
                result = packet_service.inject_simulated_packet(packet_data)
                results.append(result)
                if result.get("threat_detected"):
                    threats_detected += 1
                total_detections += len(result.get("detections", []))

            return jsonify({
                "success": True,
                "total_packets": len(packets),
                "threats_detected": threats_detected,
                "total_detections": total_detections,
                "results": results[-10:]  # Return last 10 results to limit response size
            })

        except Exception as e:
            app.logger.error(f"Error injecting batch packets: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @api_bp.route("/simulation/status")
    @login_required
    def simulation_status():
        """Get current simulation/detection statistics"""
        stats = packet_service.get_stats()
        threat_stats = threat_service.get_threat_statistics()

        ai_stats = {}
        if ai_service and ai_service.is_ready():
            ai_stats = ai_service.get_detection_statistics()

        return jsonify({
            "packet_stats": stats,
            "threat_stats": threat_stats,
            "ai_stats": ai_stats,
            "simulation_ready": True
        })

    @api_bp.route("/simulation/reset", methods=["POST"])
    @login_required
    def reset_simulation():
        """Reset simulation statistics and clear detection buffers"""
        try:
            # Clear threat detections
            threat_service.signature_detections = []
            threat_service.scan_tracker.clear()
            threat_service.dns_tracker.clear()

            # Reset packet service stats
            packet_service.stats = {
                "total_packets": 0,
                "protocol_dist": {},
                "top_talkers": {},
                "threats_blocked": 0,
                "ai_detections": 0,
            }
            packet_service.traffic_data = []

            # Reset AI service if available
            if ai_service and ai_service.is_ready():
                ai_service.detections = []

            return jsonify({"success": True, "message": "Simulation reset complete"})

        except Exception as e:
            app.logger.error(f"Error resetting simulation: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    # =========================================================================
    # THREAT ACTION ENDPOINTS
    # =========================================================================

    @api_bp.route("/threat-action", methods=["POST"])
    @login_required
    def threat_action():
        """
        Handle threat response action (Quarantine, Block, Allow).
        """
        from datetime import datetime

        try:
            data = request.get_json()
            if not data:
                return jsonify({"success": False, "error": "No data provided"}), 400

            action = data.get("action")
            source_ip = data.get("source_ip")

            if not action or not source_ip:
                return jsonify({"success": False, "error": "Missing action or source_ip"}), 400

            if action not in ["quarantine", "block", "allow"]:
                return jsonify({"success": False, "error": "Invalid action"}), 400

            # Log the action
            app.logger.info(f"Threat action: {action} for IP {source_ip} by user {current_user.username}")

            # Store action record
            action_record = {
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "source_ip": source_ip,
                "user": current_user.username,
                "status": "applied"
            }

            # Add to blocked/quarantined lists based on action
            if action == "block":
                if not hasattr(threat_service, 'blocked_ips'):
                    threat_service.blocked_ips = set()
                threat_service.blocked_ips.add(source_ip)
                action_record["status"] = "IP added to blocklist"

            elif action == "quarantine":
                if not hasattr(threat_service, 'quarantined_ips'):
                    threat_service.quarantined_ips = set()
                threat_service.quarantined_ips.add(source_ip)
                action_record["status"] = "IP quarantined for monitoring"

            elif action == "allow":
                if hasattr(threat_service, 'blocked_ips'):
                    threat_service.blocked_ips.discard(source_ip)
                if hasattr(threat_service, 'quarantined_ips'):
                    threat_service.quarantined_ips.discard(source_ip)
                action_record["status"] = "IP allowed"

            # Store action history
            if not hasattr(threat_service, 'action_history'):
                threat_service.action_history = []
            threat_service.action_history.append(action_record)

            if len(threat_service.action_history) > 100:
                threat_service.action_history = threat_service.action_history[-100:]

            return jsonify({
                "success": True,
                "action": action,
                "source_ip": source_ip,
                "status": action_record["status"]
            })

        except Exception as e:
            app.logger.error(f"Error processing threat action: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @api_bp.route("/blocked-ips")
    @login_required
    def blocked_ips():
        """Get list of blocked and quarantined IPs"""
        blocked = list(getattr(threat_service, 'blocked_ips', set()))
        quarantined = list(getattr(threat_service, 'quarantined_ips', set()))
        return jsonify({
            "blocked": blocked,
            "quarantined": quarantined,
            "total_blocked": len(blocked),
            "total_quarantined": len(quarantined)
        })

    return api_bp
