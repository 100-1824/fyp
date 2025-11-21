"""
DIDS Dashboard REST API
Complete API for dashboard functionality
"""

from .dashboard import dashboard_api, init_dashboard_api
from .admin import admin_api, init_admin_api

__all__ = ["dashboard_api", "init_dashboard_api", "admin_api", "init_admin_api"]
