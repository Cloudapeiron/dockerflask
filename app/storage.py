import os
import logging
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from werkzeug.utils import secure_filename
from flask import current_app
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)


class S3StorageManager:
    """Handles all S3 operations for file storage."""

    def __init__(self):
        self.s3_client = None
        self.bucket_name = None
        self._initialize_s3()

    def _initialize_s3(self):
        """Initialize S3 client with credentials from environment."""
        try:
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                region_name=os.environ.get('AWS_REGION', 'us-west-1')
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

    def upload_file(self, file, folder='uploads', custom_filename=None):
        """
        Upload file to S3 bucket.

        Args:
            file: FileStorage object from Flask request
            folder: S3 folder/prefix (default: 'uploads')
            custom_filename: Optional custom filename

        Returns:
            dict: {'success': bool, 'url': str, 'key': str, 'error': str}
        """
        try:
            if not file or not file.filename:
                return {'success': False, 'error': 'No file provided'}

            # Generate secure filename
            if custom_filename:
                filename = secure_filename(custom_filename)
            else:
                # Add UUID to prevent naming conflicts
                filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"

            # Create S3 key with folder structure
            s3_key = f"{folder}/{filename}"

            # Upload file
            self.s3_client.upload_fileobj(
                file,
                self.bucket_name,
                s3_key,
                ExtraArgs={
                    'ContentType': file.content_type or 'binary/octet-stream',
                    'Metadata': {
                        'uploaded_at': datetime.utcnow().isoformat(),
                        'original_filename': file.filename
                    }
                }
            )

            # Generate URL
            file_url = f"https://{self.bucket_name}.s3.amazonaws.com/{s3_key}"

            logger.info(f"File uploaded successfully: {s3_key}")
            return {
                'success': True,
                'url': file_url,
                'key': s3_key,
                'filename': filename
            }

        except ClientError as e:
            logger.error(f"S3 upload failed: {e}")
            return {'success': False, 'error': f'Upload failed: {str(e)}'}
        except Exception as e:
            logger.error(f"Unexpected error during upload: {e}")
            return {'success': False, 'error': f'Upload error: {str(e)}'}

    def download_file(self, s3_key, local_path=None):
        """
        Download file from S3.

        Args:
            s3_key: S3 object key
            local_path: Optional local file path to save to

        Returns:
            dict: {'success': bool, 'data': bytes, 'error': str}
        """
        try:
            if local_path:
                # Download to local file
                self.s3_client.download_file(
                    self.bucket_name, s3_key, local_path)
                return {'success': True, 'path': local_path}
            else:
                # Download to memory
                response = self.s3_client.get_object(
                    Bucket=self.bucket_name, Key=s3_key)
                return {'success': True, 'data': response['Body'].read()}

        except ClientError as e:
            logger.error(f"S3 download failed: {e}")
            return {'success': False, 'error': f'Download failed: {str(e)}'}
        except Exception as e:
            logger.error(f"Unexpected error during download: {e}")
            return {'success': False, 'error': f'Download error: {str(e)}'}

    def delete_file(self, s3_key):
        """
        Delete file from S3.

        Args:
            s3_key: S3 object key to delete

        Returns:
            dict: {'success': bool, 'error': str}
        """
        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=s3_key)
            logger.info(f"File deleted successfully: {s3_key}")
            return {'success': True}

        except ClientError as e:
            logger.error(f"S3 delete failed: {e}")
            return {'success': False, 'error': f'Delete failed: {str(e)}'}
        except Exception as e:
            logger.error(f"Unexpected error during delete: {e}")
            return {'success': False, 'error': f'Delete error: {str(e)}'}

    def list_files(self, folder='uploads', limit=100):
        """
        List files in S3 bucket folder.

        Args:
            folder: S3 folder/prefix to list
            limit: Maximum number of files to return

        Returns:
            dict: {'success': bool, 'files': list, 'error': str}
        """
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=f"{folder}/",
                MaxKeys=limit
            )

            files = []
            if 'Contents' in response:
                for obj in response['Contents']:
                    files.append({
                        'key': obj['Key'],
                        'size': obj['Size'],
                        'last_modified': obj['LastModified'],
                        'url': f"https://{self.bucket_name}.s3.amazonaws.com/{obj['Key']}"
                    })

            return {'success': True, 'files': files}

        except ClientError as e:
            logger.error(f"S3 list failed: {e}")
            return {'success': False, 'error': f'List failed: {str(e)}'}
        except Exception as e:
            logger.error(f"Unexpected error during list: {e}")
            return {'success': False, 'error': f'List error: {str(e)}'}

    def generate_presigned_url(self, s3_key, expiration=3600, method='get_object'):
        """
        Generate presigned URL for secure access.

        Args:
            s3_key: S3 object key
            expiration: URL expiration time in seconds (default: 1 hour)
            method: S3 method ('get_object' for download, 'put_object' for upload)

        Returns:
            dict: {'success': bool, 'url': str, 'error': str}
        """
        try:
            url = self.s3_client.generate_presigned_url(
                method,
                Params={'Bucket': self.bucket_name, 'Key': s3_key},
                ExpiresIn=expiration
            )
            return {'success': True, 'url': url}

        except ClientError as e:
            logger.error(f"Presigned URL generation failed: {e}")
            return {'success': False, 'error': f'URL generation failed: {str(e)}'}
        except Exception as e:
            logger.error(f"Unexpected error generating URL: {e}")
            return {'success': False, 'error': f'URL error: {str(e)}'}

    def file_exists(self, s3_key):
        """
        Check if file exists in S3.

        Args:
            s3_key: S3 object key to check

        Returns:
            bool: True if file exists, False otherwise
        """
        try:
            self.s3_client.head_object(Bucket=self.bucket_name, Key=s3_key)
            return True
        except ClientError:
            return False


# Global instance
storage_manager = None


def init_storage(app):
    """Initialize storage manager with Flask app."""
    global storage_manager
    try:
        storage_manager = S3StorageManager()
        app.logger.info("S3 Storage Manager initialized successfully")
    except Exception as e:
        app.logger.error(f"Failed to initialize S3 Storage Manager: {e}")
        # Could fallback to local storage here if needed
        storage_manager = None


def get_storage_manager():
    """Get the global storage manager instance."""
    return storage_manager


# Helper functions for easy use in routes
def upload_to_s3(file, folder='uploads', custom_filename=None):
    """Upload file to S3 - convenience function."""
    if storage_manager:
        return storage_manager.upload_file(file, folder, custom_filename)
    else:
        return {'success': False, 'error': 'S3 storage not initialized'}


def download_from_s3(s3_key, local_path=None):
    """Download file from S3 - convenience function."""
    if storage_manager:
        return storage_manager.download_file(s3_key, local_path)
    else:
        return {'success': False, 'error': 'S3 storage not initialized'}


def delete_from_s3(s3_key):
    """Delete file from S3 - convenience function."""
    if storage_manager:
        return storage_manager.delete_file(s3_key)
    else:
        return {'success': False, 'error': 'S3 storage not initialized'}
