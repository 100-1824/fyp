from .auth import init_auth_routes
from .main import init_main_routes
from .admin import init_admin_routes
from .api import init_api_routes

__all__ = [
    'init_auth_routes',
    'init_main_routes',
    'init_admin_routes',
    'init_api_routes'
]