import os
from datetime import timedelta

class Config:
    """Base configuration class"""
    
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)
    
    # MongoDB configuration
    MONGO_URI = os.environ.get('MONGO_URI') or "mongodb://localhost:27017/dids_dashboard"
    
    # Admin credentials (should be moved to environment variables in production)
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME') or "admin"
    ADMIN_PASSWORD_HASH = None  # Will be set at runtime
    ADMIN_DEFAULT_PASSWORD = os.environ.get('ADMIN_PASSWORD') or "SecureAdmin123!"
    
    # Flask-Login configuration
    LOGIN_VIEW = "auth.login"
    LOGIN_MESSAGE_CATEGORY = "info"
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    
    # Packet capture configuration
    TRAFFIC_DATA_MAX_SIZE = 1000
    STATS_HISTORY_SIZE = 100
    THREAT_DETECTION_BUFFER = 20
    DEFAULT_INTERFACE = 'eth0'
    
    # Logging configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Security configuration
    PASSWORD_MIN_LENGTH = 8
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Rate limiting (for future implementation)
    RATELIMIT_ENABLED = False
    RATELIMIT_DEFAULT = "100/hour"


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    MONGO_URI = "mongodb://localhost:27017/dids_dashboard_test"


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}