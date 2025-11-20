from bson.objectid import ObjectId
from flask_login import UserMixin


class User(UserMixin):
    """User model for regular users"""

    def __init__(self, user_data):
        self.id = str(user_data["_id"])
        self.username = user_data["username"]
        self.full_name = user_data.get("full_name", "")
        self.email = user_data.get("email", "")
        self.role = user_data.get("role", "user")
        self.active = user_data.get("active", True)
        self.created_at = user_data.get("created_at")

    def to_dict(self):
        """Convert user object to dictionary"""
        return {
            "id": self.id,
            "username": self.username,
            "full_name": self.full_name,
            "email": self.email,
            "role": self.role,
            "active": self.active,
        }

    @property
    def is_active(self):
        """Check if user account is active"""
        return self.active

    def __repr__(self):
        return f"<User {self.username}>"


class Admin(UserMixin):
    """Admin model for administrator users"""

    def __init__(self, username="admin"):
        self.id = "admin"
        self.username = username
        self.role = "admin"
        self.active = True
        self.full_name = "Administrator"
        self.email = "admin@dids.local"

    def to_dict(self):
        """Convert admin object to dictionary"""
        return {
            "id": self.id,
            "username": self.username,
            "full_name": self.full_name,
            "email": self.email,
            "role": self.role,
            "active": self.active,
        }

    @property
    def is_active(self):
        """Admin is always active"""
        return True

    def __repr__(self):
        return f"<Admin {self.username}>"
