import os
from datetime import timedelta


class Config:
    """Base configuration class"""

    # Flask configuration
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(24)

    # MongoDB configuration
    MONGO_URI = (
        os.environ.get("MONGO_URI") or "mongodb://localhost:27017/dids_dashboard"
    )

    # Admin credentials (should be moved to environment variables in production)
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME") or "admin"
    ADMIN_PASSWORD_HASH = None  # Will be set at runtime
    ADMIN_DEFAULT_PASSWORD = os.environ.get("ADMIN_PASSWORD") or "SecureAdmin123!"

    # Flask-Login configuration
    LOGIN_VIEW = "auth.login"
    LOGIN_MESSAGE_CATEGORY = "info"
    REMEMBER_COOKIE_DURATION = timedelta(days=7)

    # Packet capture configuration
    TRAFFIC_DATA_MAX_SIZE = 1000
    STATS_HISTORY_SIZE = 100
    THREAT_DETECTION_BUFFER = 20
    # DEFAULT_INTERFACE is a fallback - auto-detection is attempted first
    # Can be overridden with NETWORK_INTERFACE environment variable
    DEFAULT_INTERFACE = os.environ.get("NETWORK_INTERFACE") or "eth0"

    # Logging configuration
    LOG_LEVEL = os.environ.get("LOG_LEVEL") or "INFO"
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Security configuration
    PASSWORD_MIN_LENGTH = 8
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Rate limiting (for future implementation)
    RATELIMIT_ENABLED = False
    RATELIMIT_DEFAULT = "100/hour"

    # Microservices URLs
    API_GATEWAY_URL = os.environ.get("API_GATEWAY_URL") or "http://localhost:5000"
    TRAFFIC_CAPTURE_URL = (
        os.environ.get("TRAFFIC_CAPTURE_URL") or "http://localhost:5001"
    )
    SIGNATURE_DETECTION_URL = (
        os.environ.get("SIGNATURE_DETECTION_URL") or "http://localhost:5002"
    )
    AI_DETECTION_URL = os.environ.get("AI_DETECTION_URL") or "http://localhost:5003"
    RL_DETECTION_URL = os.environ.get("RL_DETECTION_URL") or "http://localhost:5004"
    THREAT_INTEL_URL = os.environ.get("THREAT_INTEL_URL") or "http://localhost:5005"

    # Threat Intelligence API Configuration
    # IBM X-Force Exchange API (https://exchange.xforce.ibmcloud.com/)
    XFORCE_API_KEY = os.environ.get("XFORCE_API_KEY") or "842c9565-1f2d-44d8-93b5-19c9e18cb6e1"
    XFORCE_API_PASSWORD = os.environ.get("XFORCE_API_PASSWORD") or "7667c28e-d88f-4db0-af77-cfe4ae806770"

    # AlienVault OTX API (https://otx.alienvault.com/)
    OTX_API_KEY = os.environ.get("OTX_API_KEY") or "7c7471b24cbd76b9ef0dbb5ba84b941e9f2b51337a6808dd57a9377ce5fea5a0"

    # Threat Intelligence Settings
    THREAT_INTEL_CACHE_TTL = int(os.environ.get("THREAT_INTEL_CACHE_TTL") or 3600)
    THREAT_INTEL_ENABLED = (
        os.environ.get("THREAT_INTEL_ENABLED", "true").lower() == "true"
    )


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
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
