"""
Shared configuration for all microservices
"""

import os
from typing import Dict


class Config:
    """Base configuration"""

    # MongoDB
    MONGO_URI = os.environ.get("MONGO_URI", "mongodb://mongodb:27017/dids")

    # Redis (for caching and message queue)
    REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
    REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))

    # Service URLs (for inter-service communication)
    TRAFFIC_CAPTURE_URL = os.environ.get(
        "TRAFFIC_CAPTURE_URL", "http://traffic-capture:5001"
    )
    SIGNATURE_DETECTION_URL = os.environ.get(
        "SIGNATURE_DETECTION_URL", "http://signature-detection:5002"
    )
    AI_DETECTION_URL = os.environ.get("AI_DETECTION_URL", "http://ai-detection:5003")
    RL_DETECTION_URL = os.environ.get("RL_DETECTION_URL", "http://rl-detection:5004")
    THREAT_INTEL_URL = os.environ.get(
        "THREAT_INTEL_URL", "http://threat-intel:5005"
    )
    API_GATEWAY_URL = os.environ.get("API_GATEWAY_URL", "http://api-gateway:5000")

    # Service ports
    API_GATEWAY_PORT = int(os.environ.get("API_GATEWAY_PORT", 5000))
    TRAFFIC_CAPTURE_PORT = int(os.environ.get("TRAFFIC_CAPTURE_PORT", 5001))
    SIGNATURE_DETECTION_PORT = int(os.environ.get("SIGNATURE_DETECTION_PORT", 5002))
    AI_DETECTION_PORT = int(os.environ.get("AI_DETECTION_PORT", 5003))
    RL_DETECTION_PORT = int(os.environ.get("RL_DETECTION_PORT", 5004))
    THREAT_INTEL_PORT = int(os.environ.get("THREAT_INTEL_PORT", 5005))

    # Threat Intelligence API Configuration
    # IBM X-Force Exchange API
    XFORCE_API_KEY = os.environ.get("XFORCE_API_KEY", "")
    XFORCE_API_PASSWORD = os.environ.get("XFORCE_API_PASSWORD", "")

    # AlienVault OTX API
    OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

    # Logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Security
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    JWT_SECRET = os.environ.get("JWT_SECRET", "jwt-secret-change-in-production")
    JWT_EXPIRATION = int(os.environ.get("JWT_EXPIRATION", 3600))  # 1 hour

    # Performance
    MAX_WORKERS = int(os.environ.get("MAX_WORKERS", 4))
    REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", 30))

    # Feature flags
    ENABLE_AI_DETECTION = (
        os.environ.get("ENABLE_AI_DETECTION", "true").lower() == "true"
    )
    ENABLE_RL_DETECTION = (
        os.environ.get("ENABLE_RL_DETECTION", "true").lower() == "true"
    )
    ENABLE_SIGNATURE_DETECTION = (
        os.environ.get("ENABLE_SIGNATURE_DETECTION", "true").lower() == "true"
    )
    ENABLE_THREAT_INTEL = (
        os.environ.get("ENABLE_THREAT_INTEL", "true").lower() == "true"
    )


class DevelopmentConfig(Config):
    """Development configuration"""

    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""

    DEBUG = False
    TESTING = False


class TestingConfig(Config):
    """Testing configuration"""

    DEBUG = True
    TESTING = True
    MONGO_URI = "mongodb://mongodb:27017/dids_test"


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}


def get_config() -> Config:
    """Get configuration based on environment"""
    env = os.environ.get("FLASK_ENV", "development")
    return config.get(env, config["default"])
