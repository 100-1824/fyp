from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from utils.decorators import admin_required

main_bp = Blueprint('main', __name__)


def init_main_routes(app, mongo, user_service):
    """Initialize main routes with dependencies"""
    
    @main_bp.route('/')
    @login_required
    def dashboard():
        if current_user.role == 'admin':
            return redirect(url_for('main.admin_dashboard'))
        return render_template('index.html')
    
    @main_bp.route('/admin')
    @admin_required
    def admin_dashboard():
        users = user_service.get_all_users()
        user_stats = user_service.get_user_statistics()
        return render_template('admin.html', users=users, stats=user_stats)
    
    return main_bp