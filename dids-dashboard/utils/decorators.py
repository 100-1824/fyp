from functools import wraps

from flask import flash, redirect, url_for
from flask_login import current_user


def admin_required(f):
    """
    Decorator to require admin role for access.

    Usage:
        @app.route('/admin')
        @admin_required
        def admin_page():
            return "Admin only"
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please log in to access this page", "error")
            return redirect(url_for("auth.login"))

        if current_user.role != "admin":
            flash("Admin access required", "error")
            return redirect(url_for("auth.login"))

        return f(*args, **kwargs)

    return decorated_function


def role_required(*roles):
    """
    Decorator to require specific roles for access.

    Usage:
        @app.route('/page')
        @role_required('admin', 'moderator')
        def restricted_page():
            return "Restricted content"
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in to access this page", "error")
                return redirect(url_for("auth.login"))

            if current_user.role not in roles:
                flash(f"Access denied. Required role: {', '.join(roles)}", "error")
                return redirect(url_for("main.dashboard"))

            return f(*args, **kwargs)

        return decorated_function

    return decorator
