import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from bson.objectid import ObjectId

logger = logging.getLogger(__name__)


class UserService:
    """Service for managing user operations"""

    def __init__(self, mongo, bcrypt):
        """
        Initialize UserService with MongoDB and bcrypt.

        Args:
            mongo: Flask-PyMongo instance
            bcrypt: Flask-Bcrypt instance
        """
        self.mongo = mongo
        self.bcrypt = bcrypt
        self.users_collection = mongo.db.users

    def create_user(self, user_data: Dict[str, Any]) -> Optional[str]:
        """
        Create a new user.

        Args:
            user_data: Dictionary containing user information

        Returns:
            User ID if successful, None otherwise
        """
        try:
            # Hash the password
            hashed_password = self.bcrypt.generate_password_hash(
                user_data["password"]
            ).decode("utf-8")

            # Prepare user document
            user_doc = {
                "full_name": user_data.get("full_name", ""),
                "username": user_data["username"],
                "email": user_data.get("email", ""),
                "password": hashed_password,
                "role": user_data.get("role", "user"),
                "active": user_data.get("active", True),
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            }

            # Insert into database
            result = self.users_collection.insert_one(user_doc)
            logger.info(f"User created: {user_data['username']}")
            return str(result.inserted_id)

        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return None

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Get user by username.

        Args:
            username: Username to search for

        Returns:
            User document if found, None otherwise
        """
        try:
            return self.users_collection.find_one({"username": username})
        except Exception as e:
            logger.error(f"Error getting user by username: {e}")
            return None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Get user by email.

        Args:
            email: Email to search for

        Returns:
            User document if found, None otherwise
        """
        try:
            return self.users_collection.find_one({"email": email})
        except Exception as e:
            logger.error(f"Error getting user by email: {e}")
            return None

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user by ID.

        Args:
            user_id: User ID to search for

        Returns:
            User document if found, None otherwise
        """
        try:
            return self.users_collection.find_one({"_id": ObjectId(user_id)})
        except Exception as e:
            logger.error(f"Error getting user by ID: {e}")
            return None

    def get_all_users(self) -> List[Dict[str, Any]]:
        """
        Get all users.

        Returns:
            List of user documents
        """
        try:
            return list(self.users_collection.find())
        except Exception as e:
            logger.error(f"Error getting all users: {e}")
            return []

    def verify_credentials(
        self, username: str, password: str
    ) -> Optional[Dict[str, Any]]:
        """
        Verify user credentials.

        Args:
            username: Username
            password: Password to verify

        Returns:
            User document if credentials are valid, None otherwise
        """
        try:
            user = self.get_user_by_username(username)

            if not user:
                return None

            # Check if user is active
            if not user.get("active", True):
                return None

            # Verify password
            if self.bcrypt.check_password_hash(user["password"], password):
                return user

            return None

        except Exception as e:
            logger.error(f"Error verifying credentials: {e}")
            return None

    def update_user(self, user_id: str, update_data: Dict[str, Any]) -> bool:
        """
        Update user information.

        Args:
            user_id: User ID
            update_data: Dictionary containing fields to update

        Returns:
            True if successful, False otherwise
        """
        try:
            # Add updated timestamp
            update_data["updated_at"] = datetime.utcnow()

            result = self.users_collection.update_one(
                {"_id": ObjectId(user_id)}, {"$set": update_data}
            )

            if result.modified_count > 0:
                logger.info(f"User updated: {user_id}")
                return True

            return False

        except Exception as e:
            logger.error(f"Error updating user: {e}")
            return False

    def delete_user(self, user_id: str) -> bool:
        """
        Delete a user.

        Args:
            user_id: User ID to delete

        Returns:
            True if successful, False otherwise
        """
        try:
            result = self.users_collection.delete_one({"_id": ObjectId(user_id)})

            if result.deleted_count > 0:
                logger.info(f"User deleted: {user_id}")
                return True

            return False

        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            return False

    def toggle_user_status(self, user_id: str) -> Optional[bool]:
        """
        Toggle user active status.

        Args:
            user_id: User ID

        Returns:
            New active status if successful, None otherwise
        """
        try:
            user = self.get_user_by_id(user_id)

            if not user:
                return None

            new_status = not user.get("active", True)

            result = self.users_collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"active": new_status, "updated_at": datetime.utcnow()}},
            )

            if result.modified_count > 0:
                logger.info(f"User status toggled: {user_id} -> {new_status}")
                return new_status

            return None

        except Exception as e:
            logger.error(f"Error toggling user status: {e}")
            return None

    def change_password(
        self, user_id: str, current_password: str, new_password: str
    ) -> bool:
        """
        Change user password.

        Args:
            user_id: User ID
            current_password: Current password for verification
            new_password: New password to set

        Returns:
            True if successful, False otherwise
        """
        try:
            user = self.get_user_by_id(user_id)

            if not user:
                return False

            # Verify current password
            if not self.bcrypt.check_password_hash(user["password"], current_password):
                return False

            # Hash new password
            hashed_password = self.bcrypt.generate_password_hash(new_password).decode(
                "utf-8"
            )

            # Update password
            result = self.users_collection.update_one(
                {"_id": ObjectId(user_id)},
                {
                    "$set": {
                        "password": hashed_password,
                        "updated_at": datetime.utcnow(),
                    }
                },
            )

            if result.modified_count > 0:
                logger.info(f"Password changed for user: {user_id}")
                return True

            return False

        except Exception as e:
            logger.error(f"Error changing password: {e}")
            return False

    def get_user_statistics(self) -> Dict[str, Any]:
        """
        Get user statistics.

        Returns:
            Dictionary containing user statistics
        """
        try:
            total_users = self.users_collection.count_documents({})
            active_users = self.users_collection.count_documents({"active": True})
            inactive_users = self.users_collection.count_documents({"active": False})

            # Count by role
            admin_count = self.users_collection.count_documents({"role": "admin"})
            user_count = self.users_collection.count_documents({"role": "user"})

            return {
                "total_users": total_users,
                "active_users": active_users,
                "inactive_users": inactive_users,
                "admin_count": admin_count,
                "user_count": user_count,
            }

        except Exception as e:
            logger.error(f"Error getting user statistics: {e}")
            return {
                "total_users": 0,
                "active_users": 0,
                "inactive_users": 0,
                "admin_count": 0,
                "user_count": 0,
            }

    def search_users(self, query: str) -> List[Dict[str, Any]]:
        """
        Search users by username, email, or full name.

        Args:
            query: Search query string

        Returns:
            List of matching user documents
        """
        try:
            search_filter = {
                "$or": [
                    {"username": {"$regex": query, "$options": "i"}},
                    {"email": {"$regex": query, "$options": "i"}},
                    {"full_name": {"$regex": query, "$options": "i"}},
                ]
            }

            return list(self.users_collection.find(search_filter))

        except Exception as e:
            logger.error(f"Error searching users: {e}")
            return []

    def get_recent_users(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recently created users.

        Args:
            limit: Maximum number of users to return

        Returns:
            List of user documents
        """
        try:
            return list(
                self.users_collection.find().sort("created_at", -1).limit(limit)
            )
        except Exception as e:
            logger.error(f"Error getting recent users: {e}")
            return []

    def user_exists(self, username: str = None, email: str = None) -> bool:
        """
        Check if a user exists by username or email.

        Args:
            username: Username to check
            email: Email to check

        Returns:
            True if user exists, False otherwise
        """
        try:
            query = {}

            if username:
                query["username"] = username

            if email:
                query["email"] = email

            if not query:
                return False

            return self.users_collection.count_documents(query) > 0

        except Exception as e:
            logger.error(f"Error checking if user exists: {e}")
            return False
