"""
DIDS Dashboard Database Module
Complete MongoDB schema definitions and database initialization
"""

from .schemas import (
    PACKETS_SCHEMA,
    THREATS_SCHEMA,
    DETECTIONS_SCHEMA,
    FLOWS_SCHEMA,
    ALERTS_SCHEMA,
    USERS_SCHEMA,
    STATISTICS_SCHEMA,
    SYSTEM_LOGS_SCHEMA,
    init_database,
    create_indexes
)

__all__ = [
    'PACKETS_SCHEMA',
    'THREATS_SCHEMA',
    'DETECTIONS_SCHEMA',
    'FLOWS_SCHEMA',
    'ALERTS_SCHEMA',
    'USERS_SCHEMA',
    'STATISTICS_SCHEMA',
    'SYSTEM_LOGS_SCHEMA',
    'init_database',
    'create_indexes'
]
