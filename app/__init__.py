import os
import logging
from flask import Flask
from flask_login import LoginManager

# Don't import db here - we'll import it from models
login_manager = LoginManager()


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

    # Ensure upload directory exists (for local fallback)
    upload_dir = app.config.get(
        'UPLOAD_FOLDER', os.path.join(app.instance_path, 'uploads'))
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)

    # Initialize extensions with app
    from app.models import db
    db.init_app(app)
    login_manager.init_app(app)

    # Initialize S3 storage if enabled
    if app.config.get('USE_S3_STORAGE', False):
        try:
            from app.storage import init_storage
            init_storage(app)
            app.logger.info("S3 storage initialized")
        except Exception as e:
            app.logger.error(f"S3 storage initialization failed: {e}")
            app.logger.info("Falling back to local storage")

    # Configure Flask-Login
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))

    # Register blueprints
    from app.routes import main
    app.register_blueprint(main)

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return "Page not found", 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return "Internal server error", 500

    @app.errorhandler(413)
    def too_large(error):
        return "File too large", 413

    # Create database tables
    with app.app_context():
        db.create_all()

        # Create default admin user if it doesn't exist
        from app.models import User
        from werkzeug.security import generate_password_hash

        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password=generate_password_hash('password')
            )
            db.session.add(admin)
            db.session.commit()
            print("Created default admin user: admin/password")

    return app
