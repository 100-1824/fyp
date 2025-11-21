from flask import Blueprint, redirect, render_template, url_for
from flask_login import current_user, login_required
from utils.decorators import admin_required

main_bp = Blueprint("main", __name__)


def init_main_routes(app, mongo, user_service):
    """Initialize main routes with dependencies"""

    @main_bp.route("/")
    @login_required
    def dashboard():
        if current_user.role == "admin":
            return redirect(url_for("main.admin_dashboard"))
        return render_template("index.html")

    @main_bp.route("/admin")
    @admin_required
    def admin_dashboard():
        users = user_service.get_all_users()
        user_stats = user_service.get_user_statistics()
        return render_template("admin.html", users=users, stats=user_stats)

    @main_bp.route("/ai-detection")
    @login_required
    def ai_detection():
        """AI Detection dashboard page"""
        return render_template("ai_detection.html")

    @main_bp.route("/threats")
    @login_required
    def threats():
        """Threats dashboard page"""
        return render_template("threats.html")

    @main_bp.route("/analytics")
    @login_required
    def analytics():
        """Analytics dashboard page"""
        return render_template("analytics.html")

    @main_bp.route("/threat-intel")
    @login_required
    def threat_intel():
        """Threat Intelligence dashboard page (IBM X-Force & AlienVault OTX)"""
        return render_template("threat_intel.html")

    @main_bp.route("/settings")
    @login_required
    def settings():
        """Settings page"""
        return render_template("settings.html")

    return main_bp
