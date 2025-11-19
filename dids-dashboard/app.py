from flask import Flask
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from threading import Thread
import logging
import os

# Import configuration
from config import config

# Import models
from models import User, Admin

# Import services
from services import PacketCaptureService, ThreatDetectionService, UserService

# Import routes
from routes import (
    init_auth_routes,
    init_main_routes,
    init_admin_routes,
    init_api_routes
)


def create_app(config_name='default'):
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
    login_manager.login_view = app.config['LOGIN_VIEW']
    login_manager.login_message_category = app.config['LOGIN_MESSAGE_CATEGORY']
    
    # Set admin password hash
    app.config['ADMIN_PASSWORD_HASH'] = bcrypt.generate_password_hash(
        app.config['ADMIN_DEFAULT_PASSWORD']
    ).decode('utf-8')
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, app.config['LOG_LEVEL']),
        format=app.config['LOG_FORMAT']
    )
    
    # User loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        if user_id == "admin":
            return Admin(app.config['ADMIN_USERNAME'])
        
        user_service = UserService(mongo, bcrypt)
        user_data = user_service.get_user_by_id(user_id)
        return User(user_data) if user_data else None
    
    # Initialize services
    # IMPORTANT: Initialize threat service first, then pass it to packet service
    threat_service = ThreatDetectionService(app.config)
    packet_service = PacketCaptureService(app.config, threat_service)
    user_service = UserService(mongo, bcrypt)
    
    # Store services in app context for access in routes
    app.packet_service = packet_service
    app.threat_service = threat_service
    app.user_service = user_service
    
    # Register blueprints
    auth_bp = init_auth_routes(app, mongo, bcrypt, user_service)
    main_bp = init_main_routes(app, mongo, user_service)
    admin_bp = init_admin_routes(app, user_service)
    api_bp = init_api_routes(app, packet_service, threat_service)
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)
    
    # Start packet capture in background thread
    if not app.config.get('TESTING'):
        capture_thread = Thread(
            target=packet_service.capture_packets,
            daemon=True
        )
        capture_thread.start()
        app.logger.info("Packet capture thread started with enhanced threat detection")
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return {"error": "Not found"}, 404
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal error: {error}")
        return {"error": "Internal server error"}, 500
    
    return app


if __name__ == '__main__':
    # Get configuration from environment or default to development
    env = os.environ.get('FLASK_ENV', 'development')
    
    # Create application
    app = create_app(env)
    
    # Run application
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 8000))
    debug = env == 'development'
    
    app.run(
        host=host,
        port=port,
        debug=debug,
        use_reloader=False  # Disabled to prevent duplicate thread creation
    )