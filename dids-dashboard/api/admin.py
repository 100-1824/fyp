"""
System Administration API
REST API endpoints for admin system administration tasks:
- Export Detection Data
- View System Logs
- Configure Whitelist
- Manage Signatures
"""

import csv
import io
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict, List

from bson import ObjectId
from flask import Blueprint, Response, current_app, jsonify, request
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

# Create blueprint
admin_api = Blueprint("admin_api", __name__, url_prefix="/api/v1/admin")


def admin_required(f):
    """Decorator to require admin privileges"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)

    return decorated_function


# ==================== EXPORT DETECTION DATA ====================


@admin_api.route("/export/detections", methods=["GET"])
@login_required
@admin_required
def export_detections():
    """Export detection data in JSON or CSV format"""
    try:
        # Get parameters
        format_type = request.args.get("format", "json").lower()
        days = request.args.get("days", 7, type=int)
        limit = request.args.get("limit", 1000, type=int)
        detector_type = request.args.get("detector_type")  # signature, ai, rl

        if format_type not in ["json", "csv"]:
            return jsonify({"error": "Invalid format. Use 'json' or 'csv'"}), 400

        # Calculate date range
        start_date = datetime.now() - timedelta(days=days)

        # Get MongoDB instance
        from flask_pymongo import PyMongo
        mongo = current_app.extensions.get('pymongo')
        if not mongo:
            return jsonify({"error": "Database not available"}), 500

        db = mongo.db

        # Build query
        query = {"timestamp": {"$gte": start_date}}
        if detector_type:
            query["detector_type"] = detector_type

        # Fetch detections
        detections = list(
            db.detections.find(query)
            .sort("timestamp", -1)
            .limit(limit)
        )

        # Convert ObjectId to string
        for detection in detections:
            detection["_id"] = str(detection["_id"])
            if "timestamp" in detection:
                detection["timestamp"] = detection["timestamp"].isoformat()

        if format_type == "json":
            return jsonify({
                "count": len(detections),
                "days": days,
                "exported_at": datetime.now().isoformat(),
                "detections": detections
            }), 200
        else:
            # CSV export
            if not detections:
                return Response(
                    "No data to export",
                    mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=detections.csv"}
                )

            # Create CSV
            output = io.StringIO()

            # Flatten nested structures for CSV
            flat_detections = []
            for d in detections:
                flat = {
                    "id": d.get("_id", ""),
                    "timestamp": d.get("timestamp", ""),
                    "detector_type": d.get("detector_type", ""),
                    "is_threat": d.get("result", {}).get("is_threat", False),
                    "attack_type": d.get("result", {}).get("attack_type", ""),
                    "confidence": d.get("result", {}).get("confidence", 0),
                    "severity": d.get("result", {}).get("severity", ""),
                    "processing_time_ms": d.get("processing_time_ms", 0),
                    "flow_id": d.get("flow_id", ""),
                }

                # Add packet data if available
                packet = d.get("packet_data", {})
                flat["source"] = packet.get("source", "")
                flat["destination"] = packet.get("destination", "")
                flat["protocol"] = packet.get("protocol", "")
                flat["src_port"] = packet.get("src_port", "")
                flat["dst_port"] = packet.get("dst_port", "")

                flat_detections.append(flat)

            if flat_detections:
                writer = csv.DictWriter(output, fieldnames=flat_detections[0].keys())
                writer.writeheader()
                writer.writerows(flat_detections)

            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={
                    "Content-Disposition": f"attachment;filename=detections_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                }
            )

    except Exception as e:
        logger.error(f"Error exporting detections: {e}")
        return jsonify({"error": str(e)}), 500


@admin_api.route("/export/threats", methods=["GET"])
@login_required
@admin_required
def export_threats():
    """Export threat data in JSON or CSV format"""
    try:
        # Get parameters
        format_type = request.args.get("format", "json").lower()
        days = request.args.get("days", 7, type=int)
        limit = request.args.get("limit", 1000, type=int)
        severity = request.args.get("severity")  # critical, high, medium, low

        if format_type not in ["json", "csv"]:
            return jsonify({"error": "Invalid format. Use 'json' or 'csv'"}), 400

        # Calculate date range
        start_date = datetime.now() - timedelta(days=days)

        # Get MongoDB instance
        mongo = current_app.extensions.get('pymongo')
        if not mongo:
            return jsonify({"error": "Database not available"}), 500

        db = mongo.db

        # Build query
        query = {"timestamp": {"$gte": start_date}}
        if severity:
            query["severity"] = severity

        # Fetch threats
        threats = list(
            db.threats.find(query)
            .sort("timestamp", -1)
            .limit(limit)
        )

        # Convert ObjectId to string
        for threat in threats:
            threat["_id"] = str(threat["_id"])
            if "timestamp" in threat:
                threat["timestamp"] = threat["timestamp"].isoformat()
            if "packet_id" in threat:
                threat["packet_id"] = str(threat["packet_id"])

        if format_type == "json":
            return jsonify({
                "count": len(threats),
                "days": days,
                "exported_at": datetime.now().isoformat(),
                "threats": threats
            }), 200
        else:
            # CSV export
            if not threats:
                return Response(
                    "No data to export",
                    mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=threats.csv"}
                )

            # Create CSV
            output = io.StringIO()

            # Flatten for CSV
            flat_threats = []
            for t in threats:
                flat = {
                    "id": t.get("_id", ""),
                    "timestamp": t.get("timestamp", ""),
                    "source": t.get("source", ""),
                    "destination": t.get("destination", ""),
                    "protocol": t.get("protocol", ""),
                    "threat_type": t.get("threat_type", ""),
                    "severity": t.get("severity", ""),
                    "confidence": t.get("confidence", 0),
                    "action": t.get("action", ""),
                    "detector": t.get("detector", ""),
                    "signature": t.get("signature", ""),
                    "blocked": t.get("blocked", False),
                    "flow_id": t.get("flow_id", ""),
                }
                flat_threats.append(flat)

            if flat_threats:
                writer = csv.DictWriter(output, fieldnames=flat_threats[0].keys())
                writer.writeheader()
                writer.writerows(flat_threats)

            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={
                    "Content-Disposition": f"attachment;filename=threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                }
            )

    except Exception as e:
        logger.error(f"Error exporting threats: {e}")
        return jsonify({"error": str(e)}), 500


@admin_api.route("/export/statistics", methods=["GET"])
@login_required
@admin_required
def export_statistics():
    """Export system statistics summary"""
    try:
        # Get MongoDB instance
        mongo = current_app.extensions.get('pymongo')
        if not mongo:
            return jsonify({"error": "Database not available"}), 500

        db = mongo.db

        # Gather statistics
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        stats = {
            "generated_at": now.isoformat(),
            "summary": {
                "total_detections": db.detections.count_documents({}),
                "total_threats": db.threats.count_documents({}),
                "total_packets": db.packets.count_documents({}),
                "total_users": db.users.count_documents({}),
            },
            "last_24h": {
                "detections": db.detections.count_documents({"timestamp": {"$gte": last_24h}}),
                "threats": db.threats.count_documents({"timestamp": {"$gte": last_24h}}),
            },
            "last_7d": {
                "detections": db.detections.count_documents({"timestamp": {"$gte": last_7d}}),
                "threats": db.threats.count_documents({"timestamp": {"$gte": last_7d}}),
            },
            "threats_by_severity": {
                "critical": db.threats.count_documents({"severity": "critical"}),
                "high": db.threats.count_documents({"severity": "high"}),
                "medium": db.threats.count_documents({"severity": "medium"}),
                "low": db.threats.count_documents({"severity": "low"}),
            },
            "detections_by_type": {
                "signature": db.detections.count_documents({"detector_type": "signature"}),
                "ai": db.detections.count_documents({"detector_type": "ai"}),
                "rl": db.detections.count_documents({"detector_type": "rl"}),
            }
        }

        return jsonify(stats), 200

    except Exception as e:
        logger.error(f"Error exporting statistics: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== SYSTEM LOGS ====================


@admin_api.route("/logs", methods=["GET"])
@login_required
@admin_required
def get_system_logs():
    """Get system logs with filtering"""
    try:
        # Get parameters
        level = request.args.get("level")  # DEBUG, INFO, WARNING, ERROR, CRITICAL
        component = request.args.get("component")
        user = request.args.get("user")
        hours = request.args.get("hours", 24, type=int)
        limit = request.args.get("limit", 100, type=int)
        offset = request.args.get("offset", 0, type=int)

        # Get MongoDB instance
        mongo = current_app.extensions.get('pymongo')
        if not mongo:
            return jsonify({"error": "Database not available"}), 500

        db = mongo.db

        # Build query
        start_date = datetime.now() - timedelta(hours=hours)
        query = {"timestamp": {"$gte": start_date}}

        if level:
            query["level"] = level.upper()
        if component:
            query["component"] = component
        if user:
            query["user"] = user

        # Get total count for pagination
        total = db.system_logs.count_documents(query)

        # Fetch logs
        logs = list(
            db.system_logs.find(query)
            .sort("timestamp", -1)
            .skip(offset)
            .limit(limit)
        )

        # Convert ObjectId to string
        for log in logs:
            log["_id"] = str(log["_id"])
            if "timestamp" in log:
                log["timestamp"] = log["timestamp"].isoformat()

        return jsonify({
            "total": total,
            "limit": limit,
            "offset": offset,
            "hours": hours,
            "logs": logs
        }), 200

    except Exception as e:
        logger.error(f"Error getting system logs: {e}")
        return jsonify({"error": str(e)}), 500


@admin_api.route("/logs", methods=["POST"])
@login_required
@admin_required
def create_system_log():
    """Create a system log entry (for admin actions)"""
    try:
        data = request.get_json()

        if not data or "message" not in data:
            return jsonify({"error": "Message required"}), 400

        # Get MongoDB instance
        mongo = current_app.extensions.get('pymongo')
        if not mongo:
            return jsonify({"error": "Database not available"}), 500

        db = mongo.db

        log_entry = {
            "timestamp": datetime.now(),
            "level": data.get("level", "INFO").upper(),
            "component": data.get("component", "admin"),
            "message": data["message"],
            "user": current_user.username,
            "action": data.get("action", ""),
            "ip_address": request.remote_addr,
            "metadata": data.get("metadata", {}),
        }

        result = db.system_logs.insert_one(log_entry)

        return jsonify({
            "message": "Log entry created",
            "id": str(result.inserted_id)
        }), 201

    except Exception as e:
        logger.error(f"Error creating system log: {e}")
        return jsonify({"error": str(e)}), 500


@admin_api.route("/logs/levels", methods=["GET"])
@login_required
@admin_required
def get_log_levels():
    """Get available log levels and their counts"""
    try:
        mongo = current_app.extensions.get('pymongo')
        if not mongo:
            return jsonify({"error": "Database not available"}), 500

        db = mongo.db

        # Aggregate log counts by level
        pipeline = [
            {"$group": {"_id": "$level", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]

        results = list(db.system_logs.aggregate(pipeline))

        levels = {r["_id"]: r["count"] for r in results if r["_id"]}

        return jsonify({
            "levels": levels,
            "available": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        }), 200

    except Exception as e:
        logger.error(f"Error getting log levels: {e}")
        return jsonify({"error": str(e)}), 500


@admin_api.route("/logs/components", methods=["GET"])
@login_required
@admin_required
def get_log_components():
    """Get available log components and their counts"""
    try:
        mongo = current_app.extensions.get('pymongo')
        if not mongo:
            return jsonify({"error": "Database not available"}), 500

        db = mongo.db

        # Aggregate log counts by component
        pipeline = [
            {"$group": {"_id": "$component", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]

        results = list(db.system_logs.aggregate(pipeline))

        components = {r["_id"]: r["count"] for r in results if r["_id"]}

        return jsonify({"components": components}), 200

    except Exception as e:
        logger.error(f"Error getting log components: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== WHITELIST MANAGEMENT ====================


@admin_api.route("/whitelist", methods=["GET"])
@login_required
@admin_required
def get_whitelist():
    """Get IP whitelist"""
    try:
        mongo = current_app.extensions.get('pymongo')
        if not mongo:
            return jsonify({"error": "Database not available"}), 500

        db = mongo.db

        # Get whitelist from database (create collection if not exists)
        whitelist = list(db.whitelist.find().sort("created_at", -1))

        # Convert ObjectId to string
        for entry in whitelist:
            entry["_id"] = str(entry["_id"])
            if "created_at" in entry:
                entry["created_at"] = entry["created_at"].isoformat()
            if "updated_at" in entry:
                entry["updated_at"] = entry["updated_at"].isoformat()

        return jsonify({
            "count": len(whitelist),
            "whitelist": whitelist
        }), 200

    except Exception as e:
        logger.error(f"Error getting whitelist: {e}")
        return jsonify({"error": str(e)}), 500


@admin_api.route("/whitelist", methods=["POST"])
@login_required
@admin_required
def add_to_whitelist():
    """Add IP/CIDR to whitelist"""
    try:
        data = request.get_json()

        if not data or "ip" not in data:
            return jsonify({"error": "IP address required"}), 400

        ip = data["ip"].strip()
        description = data.get("description", "").strip()

        # Basic IP validation
        import ipaddress
        try:
            if "/" in ip:
                ipaddress.ip_network(ip, strict=False)
            else:
                ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": "Invalid IP address or CIDR notation"}), 400

        mongo = current_app.extensions.get('pymongo')
        if not mongo:
            return jsonify({"error": "Database not available"}), 500

        db = mongo.db

        # Check if already exists
        existing = db.whitelist.find_one({"ip": ip})
        if existing:
            return jsonify({"error": "IP already in whitelist"}), 409

        # Add to whitelist
        entry = {
            "ip": ip,
            "description": description,
            "created_at": datetime.now(),
            "created_by": current_user.username,
            "active": True,
        }

        result = db.whitelist.insert_one(entry)

        # Log the action
        _log_admin_action(db, f"Added {ip} to whitelist", "whitelist_add", {"ip": ip})

        return jsonify({
            "message": f"IP {ip} added to whitelist",
            "id": str(result.inserted_id)
        }), 201

    except Exception as e:
        logger.error(f"Error adding to whitelist: {e}")
        return jsonify({"error": str(e)}), 500


@admin_api.route("/whitelist/<entry_id>", methods=["DELETE"])
@login_required
@admin_required
def remove_from_whitelist(entry_id):
    """Remove IP from whitelist"""
    try:
        mongo = current_app.extensions.get('pymongo')
        if not mongo:
            return jsonify({"error": "Database not available"}), 500

        db = mongo.db

        # Find the entry first
        entry = db.whitelist.find_one({"_id": ObjectId(entry_id)})
        if not entry:
            return jsonify({"error": "Whitelist entry not found"}), 404

        ip = entry.get("ip", "unknown")

        # Delete entry
        result = db.whitelist.delete_one({"_id": ObjectId(entry_id)})

        if result.deleted_count == 0:
            return jsonify({"error": "Failed to remove entry"}), 500

        # Log the action
        _log_admin_action(db, f"Removed {ip} from whitelist", "whitelist_remove", {"ip": ip})

        return jsonify({
            "message": f"IP {ip} removed from whitelist"
        }), 200

    except Exception as e:
        logger.error(f"Error removing from whitelist: {e}")
        return jsonify({"error": str(e)}), 500


@admin_api.route("/whitelist/<entry_id>", methods=["PUT"])
@login_required
@admin_required
def update_whitelist_entry(entry_id):
    """Update whitelist entry"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "Request body required"}), 400

        mongo = current_app.extensions.get('pymongo')
        if not mongo:
            return jsonify({"error": "Database not available"}), 500

        db = mongo.db

        # Find existing entry
        entry = db.whitelist.find_one({"_id": ObjectId(entry_id)})
        if not entry:
            return jsonify({"error": "Whitelist entry not found"}), 404

        # Build update
        update = {"updated_at": datetime.now()}

        if "description" in data:
            update["description"] = data["description"].strip()
        if "active" in data:
            update["active"] = bool(data["active"])

        # Update entry
        db.whitelist.update_one({"_id": ObjectId(entry_id)}, {"$set": update})

        # Log the action
        _log_admin_action(db, f"Updated whitelist entry {entry.get('ip')}", "whitelist_update", {"ip": entry.get("ip")})

        return jsonify({
            "message": "Whitelist entry updated"
        }), 200

    except Exception as e:
        logger.error(f"Error updating whitelist entry: {e}")
        return jsonify({"error": str(e)}), 500


@admin_api.route("/whitelist/check/<ip>", methods=["GET"])
@login_required
@admin_required
def check_whitelist(ip):
    """Check if IP is in whitelist"""
    try:
        import ipaddress

        mongo = current_app.extensions.get('pymongo')
        if not mongo:
            return jsonify({"error": "Database not available"}), 500

        db = mongo.db

        # Get all whitelist entries
        whitelist = list(db.whitelist.find({"active": True}))

        try:
            check_ip = ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": "Invalid IP address"}), 400

        # Check against each entry
        for entry in whitelist:
            entry_ip = entry.get("ip", "")
            try:
                if "/" in entry_ip:
                    network = ipaddress.ip_network(entry_ip, strict=False)
                    if check_ip in network:
                        return jsonify({
                            "whitelisted": True,
                            "matched_entry": entry_ip,
                            "description": entry.get("description", "")
                        }), 200
                else:
                    if check_ip == ipaddress.ip_address(entry_ip):
                        return jsonify({
                            "whitelisted": True,
                            "matched_entry": entry_ip,
                            "description": entry.get("description", "")
                        }), 200
            except ValueError:
                continue

        return jsonify({
            "whitelisted": False,
            "ip": ip
        }), 200

    except Exception as e:
        logger.error(f"Error checking whitelist: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== SIGNATURE MANAGEMENT ====================


@admin_api.route("/signatures", methods=["GET"])
@login_required
@admin_required
def get_signatures():
    """Get all signatures with filtering"""
    try:
        # Get parameters
        enabled = request.args.get("enabled")
        severity = request.args.get("severity")
        protocol = request.args.get("protocol")
        search = request.args.get("search")
        limit = request.args.get("limit", 100, type=int)
        offset = request.args.get("offset", 0, type=int)

        # Get rule manager from app context
        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager

        # Get all rules
        rules = rule_manager.active_rules.copy()

        # Apply filters
        if enabled is not None:
            enabled_bool = enabled.lower() in ["true", "1", "yes"]
            rules = [r for r in rules if r.get("enabled", True) == enabled_bool]

        if severity:
            rules = [r for r in rules if r.get("severity") == severity.lower()]

        if protocol:
            rules = [r for r in rules if r.get("protocol") == protocol.lower()]

        if search:
            search_lower = search.lower()
            rules = [
                r for r in rules
                if search_lower in r.get("msg", "").lower()
                or search_lower in r.get("sid", "").lower()
                or search_lower in r.get("classtype", "").lower()
            ]

        # Get total for pagination
        total = len(rules)

        # Apply pagination
        rules = rules[offset:offset + limit]

        # Clean up rules for JSON response
        for rule in rules:
            if "created_at" in rule and hasattr(rule["created_at"], "isoformat"):
                rule["created_at"] = rule["created_at"].isoformat()
            if "last_modified" in rule and hasattr(rule["last_modified"], "isoformat"):
                rule["last_modified"] = rule["last_modified"].isoformat()
            if "last_hit" in rule and hasattr(rule["last_hit"], "isoformat"):
                rule["last_hit"] = rule["last_hit"].isoformat()

        return jsonify({
            "total": total,
            "limit": limit,
            "offset": offset,
            "signatures": rules
        }), 200

    except Exception as e:
        logger.error(f"Error getting signatures: {e}")
        return jsonify({"error": str(e)}), 500


@admin_api.route("/signatures/<sid>", methods=["GET"])
@login_required
@admin_required
def get_signature(sid):
    """Get a specific signature by SID"""
    try:
        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager
        rule = rule_manager.get_rule_by_sid(sid)

        if not rule:
            return jsonify({"error": f"Signature with SID {sid} not found"}), 404

        # Clean up for JSON response
        rule_copy = rule.copy()
        if "created_at" in rule_copy and hasattr(rule_copy["created_at"], "isoformat"):
            rule_copy["created_at"] = rule_copy["created_at"].isoformat()
        if "last_modified" in rule_copy and hasattr(rule_copy["last_modified"], "isoformat"):
            rule_copy["last_modified"] = rule_copy["last_modified"].isoformat()
        if "last_hit" in rule_copy and hasattr(rule_copy["last_hit"], "isoformat"):
            rule_copy["last_hit"] = rule_copy["last_hit"].isoformat()

        return jsonify(rule_copy), 200

    except Exception as e:
        logger.error(f"Error getting signature {sid}: {e}")
        return jsonify({"error": str(e)}), 500


@admin_api.route("/signatures/<sid>/toggle", methods=["POST"])
@login_required
@admin_required
def toggle_signature(sid):
    """Enable or disable a signature"""
    try:
        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager
        rule = rule_manager.get_rule_by_sid(sid)

        if not rule:
            return jsonify({"error": f"Signature with SID {sid} not found"}), 404

        # Toggle enabled status
        currently_enabled = rule.get("enabled", True)
        if currently_enabled:
            rule_manager.disable_rule(sid)
            new_status = False
        else:
            rule_manager.enable_rule(sid)
            new_status = True

        # Log the action
        mongo = current_app.extensions.get('pymongo')
        if mongo:
            action = "enabled" if new_status else "disabled"
            _log_admin_action(
                mongo.db,
                f"Signature {sid} {action}",
                f"signature_{action}",
                {"sid": sid, "msg": rule.get("msg", "")}
            )

        return jsonify({
            "message": f"Signature {sid} {'enabled' if new_status else 'disabled'}",
            "sid": sid,
            "enabled": new_status
        }), 200

    except Exception as e:
        logger.error(f"Error toggling signature {sid}: {e}")
        return jsonify({"error": str(e)}), 500


@admin_api.route("/signatures", methods=["POST"])
@login_required
@admin_required
def create_signature():
    """Create a new signature from rule string"""
    try:
        data = request.get_json()

        if not data or "rule" not in data:
            return jsonify({"error": "Rule string required"}), 400

        rule_string = data["rule"]

        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager

        # Parse and add rule
        count = rule_manager.load_rules_from_strings([rule_string])

        if count == 0:
            return jsonify({"error": "Failed to parse rule. Check syntax."}), 400

        # Log the action
        mongo = current_app.extensions.get('pymongo')
        if mongo:
            _log_admin_action(
                mongo.db,
                f"Created new signature",
                "signature_create",
                {"rule": rule_string[:200]}
            )

        return jsonify({
            "message": "Signature created successfully",
            "count": count
        }), 201

    except Exception as e:
        logger.error(f"Error creating signature: {e}")
        return jsonify({"error": str(e)}), 500


@admin_api.route("/signatures/statistics", methods=["GET"])
@login_required
@admin_required
def get_signature_statistics():
    """Get signature statistics"""
    try:
        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager
        stats = rule_manager.get_statistics()

        # Add engine statistics if available
        if hasattr(current_app, "rule_engine") and current_app.rule_engine:
            engine_stats = current_app.rule_engine.get_statistics()
            stats["engine"] = engine_stats

        return jsonify(stats), 200

    except Exception as e:
        logger.error(f"Error getting signature statistics: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== HELPER FUNCTIONS ====================


def _log_admin_action(db, message: str, action: str, metadata: dict = None):
    """Log an admin action to system logs"""
    try:
        log_entry = {
            "timestamp": datetime.now(),
            "level": "INFO",
            "component": "admin",
            "message": message,
            "user": current_user.username if current_user.is_authenticated else "system",
            "action": action,
            "ip_address": request.remote_addr if request else None,
            "metadata": metadata or {},
        }
        db.system_logs.insert_one(log_entry)
    except Exception as e:
        logger.error(f"Failed to log admin action: {e}")


def init_admin_api(app):
    """Initialize admin API blueprint"""
    app.register_blueprint(admin_api)
    logger.info("Admin API initialized at /api/v1/admin")
    return admin_api
