from flask import Blueprint, redirect, url_for, flash, request
from flask_login import login_required
from bson.objectid import ObjectId
from utils.decorators import admin_required

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def init_admin_routes(app, user_service):
    """Initialize admin routes with dependencies"""
    
    @admin_bp.route('/delete-user/<user_id>', methods=['POST'])
    @admin_required
    def delete_user(user_id):
        try:
            success = user_service.delete_user(user_id)
            if success:
                flash("User deleted successfully", "success")
            else:
                flash("User not found", "error")
        except Exception as e:
            app.logger.error(f"Error deleting user: {e}")
            flash("Error deleting user", "error")
        
        return redirect(url_for('main.admin_dashboard'))
    
    @admin_bp.route('/toggle-user/<user_id>', methods=['POST'])
    @admin_required
    def toggle_user(user_id):
        try:
            new_status = user_service.toggle_user_status(user_id)
            if new_status is not None:
                status = "activated" if new_status else "deactivated"
                flash(f"User {status} successfully", "success")
            else:
                flash("User not found", "error")
        except Exception as e:
            app.logger.error(f"Error toggling user status: {e}")
            flash("Error updating user status", "error")
        
        return redirect(url_for('main.admin_dashboard'))
    
    @admin_bp.route('/edit-user/<user_id>', methods=['GET', 'POST'])
    @admin_required
    def edit_user(user_id):
        if request.method == 'POST':
            update_data = {
                'full_name': request.form.get('full_name', '').strip(),
                'email': request.form.get('email', '').strip().lower(),
                'role': request.form.get('role', 'user')
            }
            
            success = user_service.update_user(user_id, update_data)
            if success:
                flash("User updated successfully", "success")
            else:
                flash("Error updating user", "error")
            
            return redirect(url_for('main.admin_dashboard'))
        
        user = user_service.get_user_by_id(user_id)
        if not user:
            flash("User not found", "error")
            return redirect(url_for('main.admin_dashboard'))
        
        return redirect(url_for('main.admin_dashboard'))
    
    return admin_bp