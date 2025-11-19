from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from models import User, Admin
from utils.validators import validate_password, validate_email, validate_username

auth_bp = Blueprint('auth', __name__)


def init_auth_routes(app, mongo, bcrypt, user_service):
    """Initialize authentication routes with dependencies"""
    
    @auth_bp.route('/login', methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            if current_user.role == 'admin':
                return redirect(url_for('main.admin_dashboard'))
            return redirect(url_for('main.dashboard'))
        
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            remember = request.form.get("remember", "off") == "on"
            
            # Check for admin login
            if username == app.config['ADMIN_USERNAME']:
                if bcrypt.check_password_hash(app.config['ADMIN_PASSWORD_HASH'], password):
                    admin = Admin()
                    login_user(admin, remember=remember)
                    flash("Admin login successful!", "success")
                    return redirect(url_for('main.admin_dashboard'))
                else:
                    flash("Invalid admin password", "error")
                    return redirect(url_for('auth.login'))
            
            # Regular user login
            user_data = user_service.verify_credentials(username, password)
            
            if user_data:
                user = User(user_data)
                login_user(user, remember=remember)
                flash("Login successful!", "success")
                
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for("main.dashboard"))
            else:
                user_exists = user_service.get_user_by_username(username)
                if user_exists and not user_exists.get('active', True):
                    flash("This account is disabled", "error")
                else:
                    flash("Invalid username or password", "error")
        
        return render_template("login.html")
    
    @auth_bp.route('/register', methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('main.dashboard'))
        
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            email = request.form.get("email", "").strip().lower()
            
            # Validation
            if not full_name:
                flash("Full name is required", "error")
                return redirect(url_for("auth.register"))
            
            is_valid, message = validate_username(username)
            if not is_valid:
                flash(message, "error")
                return redirect(url_for("auth.register"))
            
            if not password:
                flash("Password is required", "error")
                return redirect(url_for("auth.register"))
            
            if password != confirm_password:
                flash("Passwords do not match", "error")
                return redirect(url_for("auth.register"))
            
            is_valid, message = validate_password(password)
            if not is_valid:
                flash(message, "error")
                return redirect(url_for("auth.register"))
            
            # Check if username exists
            if user_service.get_user_by_username(username):
                flash("Username already exists", "error")
                return redirect(url_for("auth.register"))
            
            # Validate and check email
            if email:
                if not validate_email(email):
                    flash("Invalid email address", "error")
                    return redirect(url_for("auth.register"))
                
                if user_service.get_user_by_email(email):
                    flash("Email already registered", "error")
                    return redirect(url_for("auth.register"))
            
            # Create user
            user_data = {
                "full_name": full_name,
                "username": username,
                "password": password,
                "email": email,
                "role": "user",
                "active": True
            }
            
            user_id = user_service.create_user(user_data)
            
            if user_id:
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("auth.login"))
            else:
                flash("Failed to create user account", "error")
                return redirect(url_for("auth.register"))
        
        return render_template("registration.html")
    
    @auth_bp.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash("You have been logged out", "info")
        return redirect(url_for("auth.login"))
    
    @auth_bp.route('/change-password', methods=['GET', 'POST'])
    @login_required
    def change_password():
        if request.method == 'POST':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not all([current_password, new_password, confirm_password]):
                flash("All fields are required", "error")
                return redirect(url_for('auth.change_password'))
            
            if new_password != confirm_password:
                flash("New passwords do not match", "error")
                return redirect(url_for('auth.change_password'))
            
            is_valid, message = validate_password(new_password)
            if not is_valid:
                flash(message, "error")
                return redirect(url_for('auth.change_password'))
            
            try:
                if current_user.role == 'admin':
                    if not bcrypt.check_password_hash(app.config['ADMIN_PASSWORD_HASH'], current_password):
                        flash("Current password is incorrect", "error")
                        return redirect(url_for('auth.change_password'))
                    
                    # Update admin password
                    app.config['ADMIN_PASSWORD_HASH'] = bcrypt.generate_password_hash(
                        new_password
                    ).decode('utf-8')
                    flash("Password changed successfully", "success")
                else:
                    success = user_service.change_password(
                        current_user.id,
                        current_password,
                        new_password
                    )
                    
                    if success:
                        flash("Password changed successfully", "success")
                    else:
                        flash("Current password is incorrect", "error")
                        return redirect(url_for('auth.change_password'))
                
                return redirect(url_for('main.dashboard'))
                
            except Exception as e:
                app.logger.error(f"Password change error: {e}")
                flash("Error changing password", "error")
        
        return render_template('change_password.html')
    
    @auth_bp.route('/forgot-password', methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            if email:
                # In production, send password reset email
                flash("If this email exists, you'll receive a password reset link", "info")
                return redirect(url_for("auth.login"))
        
        return render_template("forgot_password.html")
    
    return auth_bp