import os


def get_secret_from_parameter_store(parameter_name, region='us-west-1'):
    """Fetch secret from AWS Parameter Store"""
    try:
        import boto3
        ssm = boto3.client('ssm', region_name=region)
        response = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
        return response['Parameter']['Value']
    except Exception as e:
        print(f"Error fetching parameter {parameter_name}: {e}")
        return None


class Config:
    """Base configuration."""
    # App name for Parameter Store paths
    APP_NAME = os.environ.get('APP_NAME', 'your-app')

    # Get JWT secret key from Parameter Store, fallback to environment
    SECRET_KEY = (
        get_secret_from_parameter_store(f'/{APP_NAME}/jwt-secret-key') or
        os.environ.get('SECRET_KEY')
    )

    # Validate that we have a secret key
    if not SECRET_KEY:
        raise ValueError(
            f"SECRET_KEY must be set in Parameter Store (/{APP_NAME}/jwt-secret-key) or environment variable")

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1GB max file size
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or 'uploads'

    # S3 Configuration
    USE_S3_STORAGE = os.environ.get(
        'USE_S3_STORAGE', 'false').lower() == 'true'
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
    AWS_REGION = os.environ.get('AWS_REGION', 'us-west-1')
    S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME')

    # DynamoDB Configuration
    USE_DYNAMODB = os.environ.get('USE_DYNAMODB', 'false').lower() == 'true'
    DYNAMODB_TABLE_NAME = os.environ.get('DYNAMODB_TABLE_NAME', 'app-metadata')


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL') or 'sqlite:///app.db'


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL') or 'sqlite:///app.db'

    # Production should use DynamoDB by default
    USE_DYNAMODB = os.environ.get('USE_DYNAMODB', 'true').lower() == 'true'


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

    # Testing uses local storage by default
    USE_S3_STORAGE = False
    USE_DYNAMODB = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
