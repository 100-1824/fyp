"""
Rule Management API
REST API endpoints for managing Suricata/Snort IDS rules
"""

import logging
import os
from datetime import datetime
from functools import wraps
from typing import Any, Dict, List

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

# Create blueprint
rules_api = Blueprint("rules_api", __name__, url_prefix="/api/v1/rules")


def admin_required(f):
    """Decorator to require admin privileges"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)

    return decorated_function


# ==================== RULE MANAGEMENT ====================


@rules_api.route("/", methods=["GET"])
@login_required
def get_all_rules():
    """Get all rules with optional filtering"""
    try:
        # Get query parameters
        protocol = request.args.get("protocol")
        severity = request.args.get("severity")
        enabled = request.args.get("enabled")
        search = request.args.get("search")

        # Get rule manager from app context
        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager

        # Get active rules
        if protocol:
            rules = rule_manager.get_active_rules(protocol=protocol)
        elif severity:
            rules = rule_manager.get_active_rules(severity=severity)
        else:
            rules = rule_manager.get_active_rules()

        # Filter by enabled status
        if enabled is not None:
            enabled_bool = enabled.lower() in ["true", "1", "yes"]
            rules = [r for r in rules if r.get("enabled", True) == enabled_bool]

        # Search filter
        if search:
            search_lower = search.lower()
            rules = [
                r
                for r in rules
                if search_lower in r.get("msg", "").lower()
                or search_lower in r.get("sid", "").lower()
                or search_lower in r.get("classtype", "").lower()
            ]

        # Format response
        response = {
            "total": len(rules),
            "rules": rules,
            "timestamp": datetime.now().isoformat(),
        }

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Error getting rules: {e}")
        return jsonify({"error": str(e)}), 500


@rules_api.route("/<sid>", methods=["GET"])
@login_required
def get_rule(sid):
    """Get a specific rule by SID"""
    try:
        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager
        rule = rule_manager.get_rule_by_sid(sid)

        if not rule:
            return jsonify({"error": f"Rule with SID {sid} not found"}), 404

        return jsonify(rule), 200

    except Exception as e:
        logger.error(f"Error getting rule {sid}: {e}")
        return jsonify({"error": str(e)}), 500


@rules_api.route("/", methods=["POST"])
@login_required
@admin_required
def create_rule():
    """Create a new rule from rule string"""
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
            return jsonify({"error": "Failed to parse rule"}), 400

        return jsonify({"message": "Rule created successfully", "count": count}), 201

    except Exception as e:
        logger.error(f"Error creating rule: {e}")
        return jsonify({"error": str(e)}), 500


@rules_api.route("/bulk", methods=["POST"])
@login_required
@admin_required
def create_rules_bulk():
    """Create multiple rules from array of rule strings"""
    try:
        data = request.get_json()

        if not data or "rules" not in data:
            return jsonify({"error": "Rules array required"}), 400

        rule_strings = data["rules"]

        if not isinstance(rule_strings, list):
            return jsonify({"error": "Rules must be an array"}), 400

        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager

        # Parse and add rules
        count = rule_manager.load_rules_from_strings(rule_strings)

        return (
            jsonify(
                {
                    "message": f"Successfully loaded {count} rules",
                    "total_provided": len(rule_strings),
                    "loaded": count,
                    "failed": len(rule_strings) - count,
                }
            ),
            201,
        )

    except Exception as e:
        logger.error(f"Error creating rules in bulk: {e}")
        return jsonify({"error": str(e)}), 500


@rules_api.route("/upload", methods=["POST"])
@login_required
@admin_required
def upload_rule_file():
    """Upload a rule file"""
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]

        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        # Save file temporarily
        filename = file.filename
        upload_dir = os.path.join(os.path.dirname(__file__), "..", "rules", "uploaded")
        os.makedirs(upload_dir, exist_ok=True)

        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)

        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager

        # Load rules from file
        count = rule_manager.load_rules_from_file(file_path)

        return (
            jsonify(
                {
                    "message": f"Successfully loaded {count} rules from {filename}",
                    "filename": filename,
                    "rules_loaded": count,
                }
            ),
            201,
        )

    except Exception as e:
        logger.error(f"Error uploading rule file: {e}")
        return jsonify({"error": str(e)}), 500


@rules_api.route("/<sid>", methods=["PUT"])
@login_required
@admin_required
def update_rule(sid):
    """Update a rule (enable/disable)"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "Request body required"}), 400

        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager

        # Check if rule exists
        rule = rule_manager.get_rule_by_sid(sid)
        if not rule:
            return jsonify({"error": f"Rule with SID {sid} not found"}), 404

        # Update enabled status
        if "enabled" in data:
            enabled = data["enabled"]
            if enabled:
                rule_manager.enable_rule(sid)
            else:
                rule_manager.disable_rule(sid)

        return (
            jsonify(
                {
                    "message": f"Rule {sid} updated successfully",
                    "sid": sid,
                    "enabled": rule.get("enabled", True),
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Error updating rule {sid}: {e}")
        return jsonify({"error": str(e)}), 500


@rules_api.route("/<sid>", methods=["DELETE"])
@login_required
@admin_required
def delete_rule(sid):
    """Delete a rule"""
    try:
        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager

        # For now, just disable the rule (safer than deletion)
        success = rule_manager.disable_rule(sid)

        if not success:
            return jsonify({"error": f"Rule with SID {sid} not found"}), 404

        return (
            jsonify({"message": f"Rule {sid} disabled successfully", "sid": sid}),
            200,
        )

    except Exception as e:
        logger.error(f"Error deleting rule {sid}: {e}")
        return jsonify({"error": str(e)}), 500


@rules_api.route("/<sid>/enable", methods=["POST"])
@login_required
@admin_required
def enable_rule(sid):
    """Enable a rule"""
    try:
        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager
        success = rule_manager.enable_rule(sid)

        if not success:
            return jsonify({"error": f"Rule with SID {sid} not found"}), 404

        return (
            jsonify(
                {
                    "message": f"Rule {sid} enabled successfully",
                    "sid": sid,
                    "enabled": True,
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Error enabling rule {sid}: {e}")
        return jsonify({"error": str(e)}), 500


@rules_api.route("/<sid>/disable", methods=["POST"])
@login_required
@admin_required
def disable_rule(sid):
    """Disable a rule"""
    try:
        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager
        success = rule_manager.disable_rule(sid)

        if not success:
            return jsonify({"error": f"Rule with SID {sid} not found"}), 404

        return (
            jsonify(
                {
                    "message": f"Rule {sid} disabled successfully",
                    "sid": sid,
                    "enabled": False,
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Error disabling rule {sid}: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== RULE STATISTICS ====================


@rules_api.route("/statistics", methods=["GET"])
@login_required
def get_rule_statistics():
    """Get rule statistics"""
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
        logger.error(f"Error getting rule statistics: {e}")
        return jsonify({"error": str(e)}), 500


@rules_api.route("/top", methods=["GET"])
@login_required
def get_top_rules():
    """Get top triggered rules"""
    try:
        limit = int(request.args.get("limit", 10))

        if not hasattr(current_app, "rule_manager") or not current_app.rule_manager:
            return jsonify({"error": "Rule engine not initialized"}), 500

        rule_manager = current_app.rule_manager
        all_rules = rule_manager.get_active_rules()

        # Sort by hit count
        top_rules = sorted(
            all_rules, key=lambda r: r.get("hit_count", 0), reverse=True
        )[:limit]

        response = {
            "count": len(top_rules),
            "rules": [
                {
                    "sid": r["sid"],
                    "msg": r.get("msg", ""),
                    "hit_count": r.get("hit_count", 0),
                    "severity": r.get("severity", "medium"),
                    "last_hit": r.get("last_hit", None),
                }
                for r in top_rules
                if r.get("hit_count", 0) > 0
            ],
        }

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Error getting top rules: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== RULE TESTING ====================


@rules_api.route("/test", methods=["POST"])
@login_required
def test_rule():
    """Test a rule against sample packet data"""
    try:
        data = request.get_json()

        if not data or "rule" not in data or "packet" not in data:
            return jsonify({"error": "Rule and packet data required"}), 400

        # This would require implementing a test harness
        # For now, just validate the rule
        from services.rule_parser import RuleParser

        parser = RuleParser()
        parsed_rule = parser.parse_rule(data["rule"])

        if not parsed_rule:
            return jsonify({"error": "Invalid rule syntax"}), 400

        is_valid, error_msg = parser.validate_rule(parsed_rule)

        if not is_valid:
            return jsonify({"error": error_msg}), 400

        return (
            jsonify(
                {
                    "valid": True,
                    "parsed_rule": parsed_rule,
                    "message": "Rule syntax is valid",
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Error testing rule: {e}")
        return jsonify({"error": str(e)}), 500
