import os
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import logging

logger = logging.getLogger(__name__)


def get_secret_from_parameter_store(parameter_name, region='us-west-1'):
    """Fetch secret from AWS Parameter Store"""
    try:
        ssm = boto3.client('ssm', region_name=region)
        response = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
        return response['Parameter']['Value']
    except Exception as e:
        logger.error(f"Error fetching parameter {parameter_name}: {e}")
        return None


class S3StorageManager:
    """Handles all S3 operations for file storage."""

    def __init__(self):
        self.s3_client = None
        self.bucket_name = None
        self._initialize_s3()

    def _initialize_s3(self):
        """Initialize S3 client with credentials from Parameter Store."""
        try:
            # Get credentials from Parameter Store (preferred method)
            app_name = os.environ.get('APP_NAME', 'your-app')
            region = os.environ.get('AWS_REGION', 'us-west-1')
            
            logger.info(f"Attempting to get credentials from Parameter Store for app: {app_name}, region: {region}")
            
            aws_access_key = get_secret_from_parameter_store(
                f'/{app_name}/aws-access-key-id', region=region)
            aws_secret_key = get_secret_from_parameter_store(
                f'/{app_name}/aws-secret-access-key', region=region)
            
            # Fallback to environment variables if Parameter Store fails
            if not aws_access_key or not aws_secret_key:
                logger.warning("Parameter Store credentials not found, falling back to environment variables")
                aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
                aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')

            # Initialize S3 client
            if aws_access_key and aws_secret_key:
                logger.info("Using explicit AWS credentials for S3")
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=region
                )
            else:
                # Use default credentials (from ~/.aws/credentials) as last resort
                logger.warning("No explicit credentials found, using default AWS credentials")
                self.s3_client = boto3.client(
                    's3',
                    region_name=region
                )

            self.bucket_name = os.environ.get('S3_BUCKET_NAME')

            if not self.bucket_name:
                raise ValueError("S3_BUCKET_NAME environment variable is required")

            # Test connection
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            logger.info(f"S3 connection established to bucket: {self.bucket_name}")

        except NoCredentialsError:
            logger.error("AWS credentials not found")
            raise
        except ClientError as e:
            logger.error(f"S3 connection failed: {e}")
            raise
        except Exception as e:
            logger.error(f"S3 initialization failed: {e}")
            raise


# Global instance
storage_manager = None


def init_storage(app):
    """Initialize storage manager for Flask app."""
    global storage_manager
    try:
        storage_manager = S3StorageManager()
        logger.info("S3 Storage Manager initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize S3 Storage Manager: {e}")
        raise


def get_storage_manager():
    """Get the global storage manager instance."""
    return storage_manager
