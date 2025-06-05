import os
import logging
import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError
from flask import current_app
import uuid
import json

logger = logging.getLogger(__name__)


class DynamoDBManager:
    """Handles all DynamoDB operations for file metadata."""

    def __init__(self):
        self.dynamodb = None
        self.table_name = None
        self.table = None
        self._initialize_dynamodb()

    def _initialize_dynamodb(self):
        """Initialize DynamoDB client and table."""
        try:
            self.dynamodb = boto3.resource(
                'dynamodb',
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                region_name=os.environ.get('AWS_REGION', 'us-east-1')
            )

            self.table_name = os.environ.get(
                'DYNAMODB_TABLE_NAME', 'flask-file-metadata')

            # Get or create table
            self.table = self._get_or_create_table()

            logger.info(
                f"DynamoDB connection established to table: {self.table_name}")

        except NoCredentialsError:
            logger.error("AWS credentials not found for DynamoDB")
            raise
        except Exception as e:
            logger.error(f"DynamoDB initialization failed: {e}")
            raise

    def _get_or_create_table(self):
        """Get existing table or create new one."""
        try:
            # Try to get existing table
            table = self.dynamodb.Table(self.table_name)
            table.wait_until_exists()
            logger.info(f"Using existing DynamoDB table: {self.table_name}")
            return table

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                # Table doesn't exist, create it
                logger.info(f"Creating DynamoDB table: {self.table_name}")
                return self._create_table()
            else:
                raise

    def _create_table(self):
        """Create DynamoDB table for file metadata."""
        try:
            table = self.dynamodb.create_table(
                TableName=self.table_name,
                KeySchema=[
                    {
                        'AttributeName': 'file_id',
                        'KeyType': 'HASH'  # Primary key
                    }
                ],
                AttributeDefinitions=[
                    {
                        'AttributeName': 'file_id',
                        'AttributeType': 'S'
                    },
                    {
                        'AttributeName': 'user_id',
                        'AttributeType': 'S'
                    },
                    {
                        'AttributeName': 'upload_date',
                        'AttributeType': 'S'
                    }
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'user-upload-index',
                        'KeySchema': [
                            {
                                'AttributeName': 'user_id',
                                'KeyType': 'HASH'
                            },
                            {
                                'AttributeName': 'upload_date',
                                'KeyType': 'RANGE'
                            }
                        ],
                        'Projection': {
                            'ProjectionType': 'ALL'
                        }
                    }
                ],
                BillingMode='PAY_PER_REQUEST'  # On-demand pricing
            )

            # Wait for table to be created
            table.wait_until_exists()
            logger.info(
                f"DynamoDB table created successfully: {self.table_name}")
            return table

        except Exception as e:
            logger.error(f"Failed to create DynamoDB table: {e}")
            raise

    def save_file_metadata(self, file_data):
        """
        Save file metadata to DynamoDB.

        Args:
            file_data: dict with file information

        Returns:
            dict: {'success': bool, 'file_id': str, 'error': str}
        """
        try:
            file_id = str(uuid.uuid4())
            timestamp = datetime.now(timezone.utc).isoformat()

            item = {
                'file_id': file_id,
                'user_id': str(file_data['user_id']),
                'filename': file_data['filename'],
                'original_filename': file_data['original_filename'],
                'file_size': int(file_data['file_size']),
                'file_type': file_data['file_type'],
                'upload_date': timestamp,
                'storage_type': file_data.get('storage_type', 'local'),
                'file_path': file_data['file_path'],
                's3_url': file_data.get('s3_url', ''),
                'view_count': 0,
                'download_count': 0,
                'tags': file_data.get('tags', []),
                'description': file_data.get('description', ''),
                'category': file_data.get('category', 'general'),
                'is_public': file_data.get('is_public', False),
                'created_at': timestamp,
                'updated_at': timestamp
            }

            self.table.put_item(Item=item)

            logger.info(f"File metadata saved to DynamoDB: {file_id}")
            return {'success': True, 'file_id': file_id}

        except Exception as e:
            logger.error(f"Failed to save file metadata: {e}")
            return {'success': False, 'error': str(e)}

    def get_file_metadata(self, file_id):
        """
        Get file metadata by file_id.

        Args:
            file_id: string file identifier

        Returns:
            dict: file metadata or None
        """
        try:
            response = self.table.get_item(Key={'file_id': file_id})

            if 'Item' in response:
                return response['Item']
            else:
                return None

        except Exception as e:
            logger.error(f"Failed to get file metadata: {e}")
            return None

    def get_user_files(self, user_id, limit=50):
        """
        Get all files for a user, sorted by upload date.

        Args:
            user_id: string user identifier
            limit: maximum number of files to return

        Returns:
            list: file metadata items
        """
        try:
            response = self.table.query(
                IndexName='user-upload-index',
                KeyConditionExpression='user_id = :user_id',
                ExpressionAttributeValues={':user_id': str(user_id)},
                ScanIndexForward=False,  # Sort by upload_date descending
                Limit=limit
            )

            return response.get('Items', [])

        except Exception as e:
            logger.error(f"Failed to get user files: {e}")
            return []

    def update_file_metadata(self, file_id, updates):
        """
        Update file metadata.

        Args:
            file_id: string file identifier
            updates: dict of fields to update

        Returns:
            dict: {'success': bool, 'error': str}
        """
        try:
            # Build update expression
            update_expr = "SET updated_at = :timestamp"
            expr_values = {':timestamp': datetime.now(
                timezone.utc).isoformat()}

            for key, value in updates.items():
                if key not in ['file_id', 'user_id']:  # Don't update key fields
                    update_expr += f", {key} = :{key}"
                    expr_values[f":{key}"] = value

            self.table.update_item(
                Key={'file_id': file_id},
                UpdateExpression=update_expr,
                ExpressionAttributeValues=expr_values
            )

            logger.info(f"File metadata updated: {file_id}")
            return {'success': True}

        except Exception as e:
            logger.error(f"Failed to update file metadata: {e}")
            return {'success': False, 'error': str(e)}

    def delete_file_metadata(self, file_id):
        """
        Delete file metadata.

        Args:
            file_id: string file identifier

        Returns:
            dict: {'success': bool, 'error': str}
        """
        try:
            self.table.delete_item(Key={'file_id': file_id})

            logger.info(f"File metadata deleted: {file_id}")
            return {'success': True}

        except Exception as e:
            logger.error(f"Failed to delete file metadata: {e}")
            return {'success': False, 'error': str(e)}

    def increment_view_count(self, file_id):
        """Increment file view count."""
        try:
            self.table.update_item(
                Key={'file_id': file_id},
                UpdateExpression='ADD view_count :inc SET updated_at = :timestamp',
                ExpressionAttributeValues={
                    ':inc': 1,
                    ':timestamp': datetime.now(timezone.utc).isoformat()
                }
            )
            return {'success': True}
        except Exception as e:
            logger.error(f"Failed to increment view count: {e}")
            return {'success': False, 'error': str(e)}

    def increment_download_count(self, file_id):
        """Increment file download count."""
        try:
            self.table.update_item(
                Key={'file_id': file_id},
                UpdateExpression='ADD download_count :inc SET updated_at = :timestamp',
                ExpressionAttributeValues={
                    ':inc': 1,
                    ':timestamp': datetime.now(timezone.utc).isoformat()
                }
            )
            return {'success': True}
        except Exception as e:
            logger.error(f"Failed to increment download count: {e}")
            return {'success': False, 'error': str(e)}

    def search_files(self, user_id, search_term, limit=20):
        """
        Search files by filename or tags.

        Args:
            user_id: string user identifier
            search_term: string to search for
            limit: maximum results

        Returns:
            list: matching file metadata
        """
        try:
            # DynamoDB doesn't have full-text search, so we'll scan with filters
            # In production, consider using Amazon OpenSearch for better search
            response = self.table.scan(
                FilterExpression='user_id = :user_id AND (contains(original_filename, :term) OR contains(tags, :term))',
                ExpressionAttributeValues={
                    ':user_id': str(user_id),
                    ':term': search_term
                },
                Limit=limit
            )

            return response.get('Items', [])

        except Exception as e:
            logger.error(f"Failed to search files: {e}")
            return []


# Global instance
dynamodb_manager = None


def init_dynamodb(app):
    """Initialize DynamoDB manager with Flask app."""
    global dynamodb_manager
    try:
        dynamodb_manager = DynamoDBManager()
        app.logger.info("DynamoDB Manager initialized successfully")
    except Exception as e:
        app.logger.error(f"Failed to initialize DynamoDB Manager: {e}")
        dynamodb_manager = None


def get_dynamodb_manager():
    """Get the global DynamoDB manager instance."""
    return dynamodb_manager


# Helper functions for easy use in routes
def save_file_metadata(file_data):
    """Save file metadata - convenience function."""
    if dynamodb_manager:
        return dynamodb_manager.save_file_metadata(file_data)
    else:
        return {'success': False, 'error': 'DynamoDB not initialized'}


def get_file_metadata(file_id):
    """Get file metadata - convenience function."""
    if dynamodb_manager:
        return dynamodb_manager.get_file_metadata(file_id)
    else:
        return None


def get_user_files(user_id, limit=50):
    """Get user files - convenience function."""
    if dynamodb_manager:
        return dynamodb_manager.get_user_files(user_id, limit)
    else:
        return []
