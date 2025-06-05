import os
import logging
from flask import Flask


def create_app(config_name=None):
    """Application factory pattern."""

    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)

    # Load configuration - fallback to basic config if config.py doesn't exist
    try:
        from config import config
        app.config.from_object(config[config_name])
    except ImportError:
        # Fallback configuration if config.py doesn't exist
        app.config['SECRET_KEY'] = os.environ.get(
            'SECRET_KEY', 'dev-secret-key-change-in-production')
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
            'DATABASE_URL', 'sqlite:///app.db')
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.config['MAX_CONTENT_LENGTH'] = 16 * \
            1024 * 1024  # 16MB max file size
        app.config['UPLOAD_FOLDER'] = os.path.join(
            app.instance_path, 'uploads')

    # Only create upload directory if not in Lambda environment
    if not os.environ.get('LAMBDA_ENVIRONMENT'):
        upload_dir = app.config.get(
            'UPLOAD_FOLDER', os.path.join(app.instance_path, 'uploads'))
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)

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

    # Register blueprints
    from app.routes import main
    app.register_blueprint(main)

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return "Page not found", 404

    @app.errorhandler(500)
    def internal_error(error):
        return "Internal server error", 500

    @app.errorhandler(413)
    def too_large(error):
        return "File too large", 413

    return app
