import os
import jwt
import bcrypt
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app

logger = logging.getLogger(__name__)

# In-memory user store (replace with database in production)
USERS = {
    'admin': {
        'id': 1,
        'username': 'admin',
        'email': 'admin@example.com',
        # This will be properly hashed when we add user registration
        'password_hash': None,  # Will be set when user is created
        'created_at': datetime.utcnow().isoformat(),
        'is_active': True
    }
}


class PasswordManager:
    """Handles password hashing and verification using bcrypt."""

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using bcrypt.

        Args:
            password: Plain text password

        Returns:
            str: Hashed password
        """
        if not password:
            raise ValueError("Password cannot be empty")

        # Generate salt and hash password
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        return password_hash.decode('utf-8')

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            password: Plain text password to verify
            password_hash: Stored password hash

        Returns:
            bool: True if password matches, False otherwise
        """
        if not password or not password_hash:
            return False

        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                password_hash.encode('utf-8')
            )
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False


class UserManager:
    """Handles user creation, authentication, and management."""

    @staticmethod
    def create_user(username: str, email: str, password: str) -> dict:
        """
        Create a new user with hashed password.

        Args:
            username: User's username
            email: User's email
            password: Plain text password

        Returns:
            dict: {'success': bool, 'user': dict, 'error': str}
        """
        try:
            # Validate input
            if not username or not email or not password:
                return {'success': False, 'error': 'All fields are required'}

            if username in USERS:
                return {'success': False, 'error': 'Username already exists'}

            # Validate password strength
            if len(password) < 8:
                return {'success': False, 'error': 'Password must be at least 8 characters'}

            # Hash password
            password_hash = PasswordManager.hash_password(password)

            # Create user
            user = {
                'id': len(USERS) + 1,
                'username': username,
                'email': email,
                'password_hash': password_hash,
                'created_at': datetime.utcnow().isoformat(),
                'is_active': True
            }

            USERS[username] = user
            logger.info(f"User created successfully: {username}")

            # Return user data without password hash
            safe_user = {k: v for k, v in user.items() if k != 'password_hash'}
            return {'success': True, 'user': safe_user}

        except Exception as e:
            logger.error(f"User creation error: {e}")
            return {'success': False, 'error': 'Failed to create user'}

    @staticmethod
    def authenticate_user(username: str, password: str) -> dict:
        """
        Authenticate user with username and password.

        Args:
            username: User's username
            password: Plain text password

        Returns:
            dict: User data if authenticated, None otherwise
        """
        try:
            if not username or not password:
                return None

            user = USERS.get(username)
            if not user or not user.get('is_active'):
                return None

            # Verify password
            if PasswordManager.verify_password(password, user['password_hash']):
                # Return user data without password hash
                return {k: v for k, v in user.items() if k != 'password_hash'}
            else:
                return None

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None

    @staticmethod
    def get_user_by_id(user_id: int) -> dict:
        """Get user by ID."""
        for user in USERS.values():
            if user['id'] == user_id:
                return {k: v for k, v in user.items() if k != 'password_hash'}
        return None

    @staticmethod
    def update_password(username: str, old_password: str, new_password: str) -> dict:
        """
        Update user password.

        Args:
            username: User's username
            old_password: Current password
            new_password: New password

        Returns:
            dict: {'success': bool, 'error': str}
        """
        try:
            user = USERS.get(username)
            if not user:
                return {'success': False, 'error': 'User not found'}

            # Verify old password
            if not PasswordManager.verify_password(old_password, user['password_hash']):
                return {'success': False, 'error': 'Current password is incorrect'}

            # Validate new password
            if len(new_password) < 8:
                return {'success': False, 'error': 'New password must be at least 8 characters'}

            # Hash and update password
            new_hash = PasswordManager.hash_password(new_password)
            user['password_hash'] = new_hash

            logger.info(f"Password updated for user: {username}")
            return {'success': True}

        except Exception as e:
            logger.error(f"Password update error: {e}")
            return {'success': False, 'error': 'Failed to update password'}


class JWTManager:
    """Handles JWT token creation and validation."""

    @staticmethod
    def create_jwt_token(user_id: int, username: str, expires_hours: int = 24) -> str:
        """
        Create JWT token for user.

        Args:
            user_id: User's ID
            username: User's username
            expires_hours: Token expiration in hours

        Returns:
            str: JWT token
        """
        try:
            payload = {
                'user_id': user_id,
                'username': username,
                'exp': datetime.utcnow() + timedelta(hours=expires_hours),
                'iat': datetime.utcnow()
            }

            secret_key = current_app.config.get('SECRET_KEY', 'default-secret')
            token = jwt.encode(payload, secret_key, algorithm='HS256')

            return token

        except Exception as e:
            logger.error(f"JWT creation error: {e}")
            raise

    @staticmethod
    def decode_jwt_token(token: str) -> dict:
        """
        Decode and validate JWT token.

        Args:
            token: JWT token string

        Returns:
            dict: Token payload if valid, None otherwise
        """
        try:
            secret_key = current_app.config.get('SECRET_KEY', 'default-secret')
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
            return payload

        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {e}")
            return None
        except Exception as e:
            logger.error(f"JWT decode error: {e}")
            return None


def get_current_user():
    """Get current user from JWT token in request."""
    try:
        # Check for token in cookie first, then Authorization header
        token = request.cookies.get('jwt_token')

        if not token:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return None

        # Decode token
        payload = JWTManager.decode_jwt_token(token)
        if not payload:
            return None

        # Get user data
        user = UserManager.get_user_by_id(payload['user_id'])
        return user

    except Exception as e:
        logger.error(f"Get current user error: {e}")
        return None


def jwt_required(f):
    """Decorator to require JWT authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.content_type == 'application/json':
                return jsonify({'error': 'Authentication required'}), 401
            else:
                from flask import redirect, url_for
                return redirect(url_for('main.login'))

        # Add user to request context
        request.current_user = user
        return f(*args, **kwargs)

    return decorated_function


def create_login_response(user: dict) -> dict:
    """Create login response with JWT token."""
    try:
        token = JWTManager.create_jwt_token(user['id'], user['username'])
        return {
            'success': True,
            'user': user,
            'token': token
        }
    except Exception as e:
        logger.error(f"Login response creation error: {e}")
        return {'success': False, 'error': 'Failed to create login response'}

# Initialize default admin user with hashed password


def initialize_default_users():
    """Initialize default users with proper password hashing."""
    try:
        # Get password from environment
        default_password = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'admin123')
        logger.info(f"Initializing admin user with password from environment")

        # Check if admin user exists
        if 'admin' in USERS:
            # User exists - check if it has a password hash
            if not USERS['admin'].get('password_hash'):
                # Update existing user with password hash
                USERS['admin']['password_hash'] = PasswordManager.hash_password(
                    default_password)
                logger.info("Updated existing admin user with hashed password")
            else:
                logger.info("Admin user already has password hash")
        else:
            # Create new admin user
            result = UserManager.create_user(
                'admin', 'admin@example.com', default_password)
            if result['success']:
                logger.info("Default admin user created with hashed password")
            else:
                logger.error(f"Failed to create admin user: {result['error']}")

    except Exception as e:
        logger.error(f"User initialization error: {e}")

# Convenience functions for backward compatibility


def authenticate_user(username: str, password: str) -> dict:
    """Backward compatible authentication function."""
    return UserManager.authenticate_user(username, password)


def create_jwt_token(user_id: int, username: str) -> str:
    """Backward compatible JWT creation function."""
    return JWTManager.create_jwt_token(user_id, username)
