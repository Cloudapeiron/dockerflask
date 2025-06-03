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

    # Load configuration
    from config import config
    app.config.from_object(config[config_name])

    # Ensure upload directory exists
    upload_dir = app.config['UPLOAD_FOLDER']
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)

    # Initialize extensions with app
    from app.models import db
    db.init_app(app)
    login_manager.init_app(app)

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

    return app
