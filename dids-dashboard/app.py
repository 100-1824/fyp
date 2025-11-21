import logging
import os
from threading import Thread

# Import dashboard API
from api import init_dashboard_api
# Import configuration
from config import config
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_pymongo import PyMongo
# Import models
from models import Admin, User
# Import routes
from routes import (init_admin_routes, init_api_routes, init_auth_routes,
                    init_main_routes)
# Import services
from services import (AIDetectionService, PacketCaptureService,
                      ThreatDetectionService, UserService,
                      init_threat_intel_service)
from services.rl_detection import RLDetectionService
from services.rule_engine import RuleEngine
from services.rule_parser import RuleManager


def create_app(config_name="default"):
    """
    Application factory pattern for creating Flask app.

    Args:
        config_name: Configuration name ('development', 'production', 'testing')

    Returns:
        Configured Flask application
    """
    # Initialize Flask app
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(config[config_name])

    # Initialize extensions
    mongo = PyMongo(app)
    bcrypt = Bcrypt(app)
    login_manager = LoginManager(app)

    # Configure login manager
    login_manager.login_view = app.config["LOGIN_VIEW"]
    login_manager.login_message_category = app.config["LOGIN_MESSAGE_CATEGORY"]

    # Set admin password hash
    app.config["ADMIN_PASSWORD_HASH"] = bcrypt.generate_password_hash(
        app.config["ADMIN_DEFAULT_PASSWORD"]
    ).decode("utf-8")

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, app.config["LOG_LEVEL"]), format=app.config["LOG_FORMAT"]
    )

    # User loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        if user_id == "admin":
            return Admin(app.config["ADMIN_USERNAME"])

        user_service = UserService(mongo, bcrypt)
        user_data = user_service.get_user_by_id(user_id)
        return User(user_data) if user_data else None

    # Initialize services
    app.logger.info("=" * 70)
    app.logger.info("🚀 Initializing DIDS Services")
    app.logger.info("=" * 70)

    # 0. Initialize Suricata/Snort rule engine
    app.logger.info("0️⃣  Initializing Suricata/Snort Rule Engine...")
    try:
        rule_manager = RuleManager(db=mongo.db)
        rule_engine = RuleEngine(rule_manager)

        # Load default rules
        default_rules_path = os.path.join(
            os.path.dirname(__file__), "rules", "default.rules"
        )
        if os.path.exists(default_rules_path):
            rules_loaded = rule_manager.load_rules_from_file(default_rules_path)
            app.logger.info(
                f"✓ Suricata/Snort rule engine initialized with {rules_loaded} rules"
            )

            # Show rule statistics
            stats = rule_manager.get_statistics()
            app.logger.info(f"   📋 Rules by severity: {stats.get('by_severity', {})}")
            app.logger.info(f"   🔧 Rules by protocol: {stats.get('by_protocol', {})}")
        else:
            app.logger.warning(
                f"⚠️  Default rules file not found at {default_rules_path}"
            )
            rules_loaded = 0
    except Exception as e:
        app.logger.error(f"⚠️  Failed to initialize rule engine: {e}")
        rule_manager = None
        rule_engine = None

    # 1. Initialize threat detection service (with rule engine)
    app.logger.info("1️⃣  Initializing Signature-Based Threat Detection...")
    threat_service = ThreatDetectionService(app.config, rule_engine=rule_engine)
    app.logger.info("✓ Signature-based threat detection ready")

    # 2. Initialize AI detection service
    app.logger.info("2️⃣  Initializing AI-Powered Threat Detection...")
    model_path = os.path.join(os.path.dirname(__file__), "model")
    ai_service = AIDetectionService(app.config, model_path=model_path)

    if ai_service.is_ready():
        app.logger.info("✓ AI detection service initialized successfully")
        model_info = ai_service.get_model_info()
        app.logger.info(
            f"   📊 Model loaded with {model_info['feature_count']} features"
        )
        app.logger.info(
            f"   🎯 Attack types: {', '.join(model_info['attack_types'][:5])}..."
        )
        if "accuracy" in model_info:
            app.logger.info(f"   📈 Model accuracy: {model_info['accuracy']}")
    else:
        app.logger.warning(
            "⚠️  AI detection service not ready - will use signature-based only"
        )
        ai_service = None

    # 2.5. Initialize RL detection service
    app.logger.info("2.5️⃣  Initializing RL-Powered Threat Response...")
    rl_model_path = os.path.join(os.path.dirname(__file__), "model")
    rl_service = RLDetectionService(app.config, model_path=rl_model_path)

    if rl_service.is_ready():
        app.logger.info("✓ RL detection service initialized successfully")
        rl_stats = rl_service.get_statistics()
        app.logger.info(f"   🤖 RL model loaded: {rl_stats.get('rl_model_loaded', False)}")
        app.logger.info(f"   🎯 Actions: allow, alert, block")
    else:
        app.logger.warning(
            "⚠️  RL detection service not ready - will use basic policies"
        )
        rl_service = None

    # 3. Initialize packet capture service (depends on threat, AI, and RL services)
    app.logger.info("3️⃣  Initializing Packet Capture Service...")
    packet_service = PacketCaptureService(app.config, threat_service, ai_service, rl_service)
    app.logger.info("✓ Packet capture service ready")

    # 4. Initialize user service
    user_service = UserService(mongo, bcrypt)

    # 5. Initialize threat intelligence service (IBM X-Force & AlienVault OTX)
    app.logger.info("5️⃣  Initializing Threat Intelligence Service...")
    threat_intel_service = init_threat_intel_service(app)
    health = threat_intel_service.get_health()
    if health.get("xforce_configured") or health.get("otx_configured"):
        app.logger.info("✓ Threat intelligence service initialized")
        if health.get("xforce_configured"):
            app.logger.info("   🔷 IBM X-Force Exchange: Connected")
        if health.get("otx_configured"):
            app.logger.info("   🔶 AlienVault OTX: Connected")
    else:
        app.logger.warning("⚠️  Threat intelligence APIs not configured")

    app.logger.info("=" * 70)
    app.logger.info("✅ All services initialized successfully")
    app.logger.info("=" * 70)

    # Store services in app context for access in routes
    app.packet_service = packet_service
    app.threat_service = threat_service
    app.ai_service = ai_service
    app.rl_service = rl_service
    app.user_service = user_service
    app.rule_manager = rule_manager
    app.rule_engine = rule_engine
    app.threat_intel_service = threat_intel_service

    # Register blueprints
    auth_bp = init_auth_routes(app, mongo, bcrypt, user_service)
    main_bp = init_main_routes(app, mongo, user_service)
    admin_bp = init_admin_routes(app, user_service)
    api_bp = init_api_routes(app, packet_service, threat_service, ai_service, rl_service)

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    # Register dashboard API
    init_dashboard_api(app)
    app.logger.info("✓ Dashboard API registered at /api/v1")

    # Register rules API
    from api.rules import rules_api

    app.register_blueprint(rules_api)
    app.logger.info("✓ Rules API registered at /api/v1/rules")

    # Register admin API (System Administration)
    from api.admin import init_admin_api

    init_admin_api(app)
    app.logger.info("✓ Admin API registered at /api/v1/admin")

    # Start packet capture in background thread
    if not app.config.get("TESTING"):
        capture_thread = Thread(target=packet_service.capture_packets, daemon=True)
        capture_thread.start()

        if ai_service and ai_service.is_ready():
            app.logger.info(
                "🔍 Packet capture started with AI-powered threat detection"
            )
        else:
            app.logger.info(
                "🔍 Packet capture started with signature-based threat detection"
            )

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return {"error": "Not found"}, 404

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal error: {error}")
        return {"error": "Internal server error"}, 500

    return app


if __name__ == "__main__":
    # Get configuration from environment or default to development
    env = os.environ.get("FLASK_ENV", "development")

    # Create application
    app = create_app(env)

    # Run application
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", 8000))
    debug = env == "development"

    app.run(
        host=host,
        port=port,
        debug=debug,
        use_reloader=False,  # Disabled to prevent duplicate thread creation
    )
