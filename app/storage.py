import os
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import logging
import uuid

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

            logger.info(
                f"Attempting to get credentials from Parameter Store for app: {app_name}, region: {region}")

            aws_access_key = get_secret_from_parameter_store(
                f'/{app_name}/aws-access-key-id', region=region)
            aws_secret_key = get_secret_from_parameter_store(
                f'/{app_name}/aws-secret-access-key', region=region)

            # Fallback to environment variables if Parameter Store fails
            if not aws_access_key or not aws_secret_key:
                logger.warning(
                    "Parameter Store credentials not found, falling back to environment variables")
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
                logger.warning(
                    "No explicit credentials found, using default AWS credentials")
                self.s3_client = boto3.client(
                    's3',
                    region_name=region
                )

            self.bucket_name = os.environ.get('S3_BUCKET_NAME')

            if not self.bucket_name:
                raise ValueError(
                    "S3_BUCKET_NAME environment variable is required")

            # Test connection
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            logger.info(
                f"S3 connection established to bucket: {self.bucket_name}")

        except NoCredentialsError:
            logger.error("AWS credentials not found")
            raise
        except ClientError as e:
            logger.error(f"S3 connection failed: {e}")
            raise
        except Exception as e:
            logger.error(f"S3 initialization failed: {e}")
            raise


def upload_to_s3(file_obj, filename, content_type=None, custom_filename=None):
    """Upload a file to S3 bucket."""
    try:
        storage = get_storage_manager()
        if not storage or not storage.s3_client:
            raise Exception("S3 storage manager not initialized")

        # Use custom filename if provided, otherwise generate unique filename
        if custom_filename:
            unique_filename = custom_filename
        else:
            unique_filename = f"{uuid.uuid4().hex}_{filename}"

        # Upload the file
        extra_args = {}
        if content_type:
            extra_args['ContentType'] = content_type

        storage.s3_client.upload_fileobj(
            file_obj,
            storage.bucket_name,
            unique_filename,
            ExtraArgs=extra_args
        )

        # Return the S3 URL
        region = os.environ.get('AWS_REGION', 'us-west-1')
        s3_url = f"https://{storage.bucket_name}.s3.{region}.amazonaws.com/{unique_filename}"

        logger.info(f"File uploaded successfully to S3: {unique_filename}")
        return {
            'success': True,
            'filename': unique_filename,
            'url': s3_url
        }

    except Exception as e:
        logger.error(f"S3 upload failed: {e}")
        return {
            'success': False,
            'error': str(e)
        }


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
