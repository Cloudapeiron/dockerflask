import os
import logging
from flask import Flask
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def create_app(config_name=None):
    """Application factory pattern with python-dotenv integration."""

    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)

    # Configure logging based on environment
    log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
    logging.basicConfig(level=getattr(logging, log_level))

    # Load configuration from environment variables (now loaded from .env)
    app.config['SECRET_KEY'] = os.environ.get(
        'SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['FLASK_ENV'] = os.environ.get('FLASK_ENV', 'development')
    app.config['DEBUG'] = os.environ.get(
        'FLASK_DEBUG', 'false').lower() == 'true'

    # Database configuration
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'sqlite:///app.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # File upload configuration
    app.config['MAX_CONTENT_LENGTH'] = int(
        os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))
    app.config['UPLOAD_FOLDER'] = os.environ.get(
        'UPLOAD_FOLDER', os.path.join(app.instance_path, 'uploads'))

    # AWS configuration
    app.config['AWS_ACCESS_KEY_ID'] = os.environ.get('AWS_ACCESS_KEY_ID')
    app.config['AWS_SECRET_ACCESS_KEY'] = os.environ.get(
        'AWS_SECRET_ACCESS_KEY')
    app.config['AWS_REGION'] = os.environ.get('AWS_REGION', 'us-east-1')
    app.config['S3_BUCKET_NAME'] = os.environ.get('S3_BUCKET_NAME')
    app.config['DYNAMODB_TABLE_NAME'] = os.environ.get(
        'DYNAMODB_TABLE_NAME', 'flask-file-metadata')

    # Feature flags
    app.config['USE_S3_STORAGE'] = os.environ.get(
        'USE_S3_STORAGE', 'false').lower() == 'true'
    app.config['USE_DYNAMODB'] = os.environ.get(
        'USE_DYNAMODB', 'false').lower() == 'true'
    app.config['USE_SECRETS_MANAGER'] = os.environ.get(
        'USE_SECRETS_MANAGER', 'false').lower() == 'true'

    # Celery configuration
    app.config['CELERY_BROKER_URL'] = os.environ.get(
        'CELERY_BROKER_URL', 'redis://localhost:6379/0')
    app.config['CELERY_RESULT_BACKEND'] = os.environ.get(
        'CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    app.config['REDIS_URL'] = os.environ.get(
        'REDIS_URL', 'redis://localhost:6379/0')

    # Validate required configuration
    required_config = []

    if app.config['USE_S3_STORAGE'] and not app.config['S3_BUCKET_NAME']:
        required_config.append('S3_BUCKET_NAME (USE_S3_STORAGE is enabled)')

    if app.config['USE_S3_STORAGE'] and not app.config['AWS_ACCESS_KEY_ID']:
        required_config.append('AWS_ACCESS_KEY_ID (USE_S3_STORAGE is enabled)')

    if required_config:
        app.logger.warning(
            f"Missing required configuration: {', '.join(required_config)}")
        app.logger.info("Some features may not work properly")

    # Only create upload directory if not in Lambda environment
    if not os.environ.get('LAMBDA_ENVIRONMENT'):
        upload_dir = app.config.get('UPLOAD_FOLDER')
        if upload_dir and not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
            app.logger.info(f"Created upload directory: {upload_dir}")

    # Initialize S3 storage if enabled
    if app.config.get('USE_S3_STORAGE', False):
        try:
            from app.storage import init_storage
            init_storage(app)
            app.logger.info("S3 storage initialized")
        except Exception as e:
            app.logger.error(f"S3 storage initialization failed: {e}")
            app.logger.info("Falling back to local storage")

    # Initialize DynamoDB if enabled
    if app.config.get('USE_DYNAMODB', False):
        try:
            from app.dynamodb_manager import init_dynamodb
            init_dynamodb(app)
            app.logger.info("DynamoDB initialized")
        except Exception as e:
            app.logger.error(f"DynamoDB initialization failed: {e}")
            app.logger.info("Falling back to SQLite for metadata")

    # Initialize file validator
    try:
        from app.file_validator import init_file_validator
        init_file_validator(app)
        app.logger.info("File validator initialized with python-magic")
    except Exception as e:
        app.logger.error(f"File validator initialization failed: {e}")
        app.logger.warning("File uploads will not be validated for security")

    # Initialize authentication system
    with app.app_context():
        try:
            from app.jwt_auth import initialize_default_users
            initialize_default_users()
            app.logger.info("Authentication system initialized with bcrypt")
        except Exception as e:
            app.logger.error(f"Authentication initialization failed: {e}")

    # Register blueprints
    from app.routes import main
    app.register_blueprint(main)

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return "Page not found", 404

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal error: {error}")
        return "Internal server error", 500

    @app.errorhandler(413)
    def too_large(error):
        return "File too large", 413

    # Configuration debug endpoint (development only)
    @app.route('/debug/config')
    def debug_config():
        if app.config.get('FLASK_ENV') == 'development':
            safe_config = {}
            for key, value in app.config.items():
                # Don't expose sensitive values
                if any(sensitive in key.lower() for sensitive in ['secret', 'key', 'password', 'token']):
                    safe_config[key] = '***HIDDEN***'
                else:
                    safe_config[key] = value
            return safe_config
        else:
            return {"error": "Debug endpoint disabled in production"}, 403

    # Environment info endpoint
    @app.route('/debug/env')
    def debug_env():
        if app.config.get('FLASK_ENV') == 'development':
            return {
                'env_loaded': 'dotenv' in str(type(load_dotenv)),
                'flask_env': app.config.get('FLASK_ENV'),
                'debug_mode': app.config.get('DEBUG'),
                'features': {
                    's3_storage': app.config.get('USE_S3_STORAGE'),
                    'dynamodb': app.config.get('USE_DYNAMODB'),
                    'secrets_manager': app.config.get('USE_SECRETS_MANAGER'),
                }
            }
        else:
            return {"error": "Debug endpoint disabled in production"}, 403

    app.logger.info(f"Flask app created with environment: {config_name}")
    return app


# For development - run the app directly
if __name__ == '__main__':
    app = create_app()

    # Get host and port from environment
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    app.run(host=host, port=port, debug=debug)
