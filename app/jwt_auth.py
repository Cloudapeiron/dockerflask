import jwt
import datetime
from functools import wraps
from flask import request, jsonify, current_app, make_response
import os


def create_jwt_token(user_id, username):
    """Create a JWT token for the user"""
    payload = {
        'user_id': user_id,
        'username': username,
        # Token expires in 24 hours
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        'iat': datetime.datetime.utcnow()
    }

    secret_key = current_app.config.get('SECRET_KEY', 'fallback-secret')
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token


def decode_jwt_token(token):
    """Decode and validate a JWT token"""
    try:
        secret_key = current_app.config.get('SECRET_KEY', 'fallback-secret')
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_current_user():
    """Get current user from JWT token"""
    # Try to get token from cookie first, then from Authorization header
    token = request.cookies.get('jwt_token')

    if not token:
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Remove 'Bearer ' prefix
            except IndexError:
                return None

    if not token:
        return None

    payload = decode_jwt_token(token)
    if payload:
        return {
            'user_id': payload['user_id'],
            'username': payload['username']
        }
    return None


def jwt_required(f):
    """Decorator to require JWT authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            # Return JSON for API calls, HTML for web pages
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            else:
                # Redirect to login page for web requests
                from flask import redirect, url_for
                return redirect(url_for('main.login'))

        # Make user available in the route
        request.current_user = user
        return f(*args, **kwargs)

    return decorated_function


# Simple user storage for demo (in production, use DynamoDB)
DEMO_USERS = {
    'admin': {
        'id': 1,
        'username': 'admin',
        'password': 'password'  # In production, use hashed passwords
    }
}


def authenticate_user(username, password):
    """Authenticate user credentials"""
    user = DEMO_USERS.get(username)
    if user and user['password'] == password:
        return user
    return None


def create_login_response(user):
    """Create response with JWT token"""
    token = create_jwt_token(user['id'], user['username'])

    # Create response and set cookie
    response = make_response({
        'message': 'Login successful',
        'user': {'username': user['username']},
        'token': token
    })

    # Set JWT token as HTTP-only cookie (more secure)
    response.set_cookie(
        'jwt_token',
        token,
        max_age=24*60*60,  # 24 hours
        httponly=True,
        secure=True,  # HTTPS only
        samesite='Lax'
    )

    return response
