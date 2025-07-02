import os
import logging
from flask import Flask
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def create_app(config_name=None):
    """Application factory pattern with python-dotenv integration."""
    app = Flask(__name__)

    # Set up logging
    logging.basicConfig(level=logging.INFO)

    # Load configuration
    config_name = config_name or os.environ.get('FLASK_ENV', 'development')

    if config_name == 'production':
        from config import ProductionConfig
        app.config.from_object(ProductionConfig)
    elif config_name == 'testing':
        from config import TestingConfig
        app.config.from_object(TestingConfig)
    else:
        from config import DevelopmentConfig
        app.config.from_object(DevelopmentConfig)

    # Override with environment variables
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    if not app.config['SECRET_KEY']:
        raise ValueError(
            "SECRET_KEY must be set in environment variables or Parameter Store")

    # S3 Configuration from environment
    app.config['USE_S3_STORAGE'] = os.environ.get(
        'USE_S3_STORAGE', 'false').lower() == 'true'
    app.config['AWS_ACCESS_KEY_ID'] = os.environ.get('AWS_ACCESS_KEY_ID')
    app.config['AWS_SECRET_ACCESS_KEY'] = os.environ.get(
        'AWS_SECRET_ACCESS_KEY')
    app.config['AWS_REGION'] = os.environ.get('AWS_REGION', 'us-west-1')
    app.config['S3_BUCKET_NAME'] = os.environ.get('S3_BUCKET_NAME')

    # File upload configuration
    app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB
    app.config['UPLOAD_FOLDER'] = os.path.join(
        app.instance_path, 'uploads')

    # DynamoDB Configuration from environment
    app.config['DYNAMODB_TABLE_NAME'] = os.environ.get(
        'DYNAMODB_TABLE_NAME', 'app-metadata')

    # JWT Configuration
    app.config['JWT_SECRET_KEY'] = app.config['SECRET_KEY']
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False

    app.config['USE_DYNAMODB'] = os.environ.get(
        'USE_DYNAMODB', 'false').lower() == 'true'

    # Create instance folder
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Create upload folder
    if not app.config.get('USE_S3_STORAGE', False):
        try:
            os.makedirs(app.config['UPLOAD_FOLDER'])
            app.logger.info(
                f"Created upload directory: {app.config['UPLOAD_FOLDER']}")
        except OSError:
            app.logger.info(
                f"Upload directory already exists: {app.config['UPLOAD_FOLDER']}")

    # Initialize file validator
    try:
        from app.file_validator import init_file_validator
        init_file_validator(app)
        app.logger.info("File validator initialized")
    except Exception as e:
        app.logger.error(f"File validator initialization failed: {e}")

    # Initialize S3 storage if enabled
    if app.config.get('USE_S3_STORAGE', False):
        try:
            from app.storage import init_storage
            init_storage(app)
            app.logger.info("S3 storage initialized")
        except Exception as e:
            app.logger.error(f"S3 storage initialization failed: {e}")

    # Initialize authentication system
    try:
        from app.jwt_auth import initialize_default_users
        initialize_default_users()
        app.logger.info("Authentication system initialized with bcrypt")
    except Exception as e:
        app.logger.error(f"Authentication initialization failed: {e}")
        raise

    # DEBUG: Check DynamoDB configuration
    print(f"DEBUG: USE_DYNAMODB = {app.config.get('USE_DYNAMODB', False)}")
    print(
        f"DEBUG: DYNAMODB_TABLE_NAME = {app.config.get('DYNAMODB_TABLE_NAME')}")
    print(f"DEBUG: About to check DynamoDB initialization")

    # Initialize DynamoDB if enabled
    if app.config.get('USE_DYNAMODB', False):
        print("DEBUG: DynamoDB is enabled, initializing...")
        try:
            from app.dynamodb_manager import init_dynamodb
            init_dynamodb(app)
            app.logger.info("DynamoDB initialized")
            print("DEBUG: DynamoDB initialization completed successfully")
        except Exception as e:
            print(f"DEBUG: DynamoDB error: {e}")
            app.logger.error(f"DynamoDB initialization failed: {e}")
    else:
        print("DEBUG: DynamoDB is NOT enabled")

    # Register blueprints
    try:
        from app.routes import main
        app.register_blueprint(main)
        app.logger.info("Routes registered successfully")
    except Exception as e:
        app.logger.error(f"Failed to register routes: {e}")
        raise

    # Initialize Celery if available
    try:
        from app.celery_tasks import init_celery
        init_celery(app)
        app.logger.info("Celery initialized")
    except ImportError:
        app.logger.info("Celery not available - background tasks disabled")
    except Exception as e:
        app.logger.warning(f"Celery initialization failed: {e}")

    app.logger.info(f"Flask app created with environment: {config_name}")

    # Debug information
    debug_info = {
        'config': {
            key: '***' if any(sensitive in key.lower() for sensitive in ['secret', 'key', 'password', 'token'])
            else value for key, value in app.config.items()
        },
        'instance_path': app.instance_path,
        'upload_folder': app.config.get('UPLOAD_FOLDER'),
        's3_enabled': app.config.get('USE_S3_STORAGE'),
        'bucket_name': app.config.get('S3_BUCKET_NAME'),
        'region': app.config.get('AWS_REGION'),
        'env_vars': {
            'FLASK_ENV': os.environ.get('FLASK_ENV'),
            'USE_S3_STORAGE': os.environ.get('USE_S3_STORAGE'),
            'S3_BUCKET_NAME': os.environ.get('S3_BUCKET_NAME'),
            'AWS_REGION': os.environ.get('AWS_REGION'),
            'USE_DYNAMODB': os.environ.get('USE_DYNAMODB'),
            'DYNAMODB_TABLE_NAME': os.environ.get('DYNAMODB_TABLE_NAME')
        },
        'features': {
            's3': app.config.get('USE_S3_STORAGE'),
            'dynamodb': app.config.get('USE_DYNAMODB'),
            'env_loaded': 'dotenv' in str(type(load_dotenv)),
        }
    }

    # Store debug info for later access
    app.debug_info = debug_info

    return app
