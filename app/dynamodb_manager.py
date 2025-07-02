# app/dynamodb_manager.py
import os
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import logging

logger = logging.getLogger(__name__)


def get_secret_from_parameter_store(parameter_name, region='us-west-1'):
    """Fetch secret from AWS Parameter Store"""
    try:
        import boto3
        ssm = boto3.client('ssm', region_name=region)
        response = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
        return response['Parameter']['Value']
    except Exception as e:
        logger.error(f"Error fetching parameter {parameter_name}: {e}")
        return None


class DynamoDBManager:
    """Handles all DynamoDB operations for file metadata."""

    def __init__(self):
        self.dynamodb = None
        self.table = None
        self.table_name = None
        self._initialize_dynamodb()

    def _initialize_dynamodb(self):
        """Initialize DynamoDB client and table."""
        try:
            # Get credentials from Parameter Store (preferred method)
            app_name = os.environ.get('APP_NAME', 'your-app')
            region = os.environ.get('AWS_REGION', 'us-west-1')

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

            # Initialize DynamoDB resource
            if aws_access_key and aws_secret_key:
                self.dynamodb = boto3.resource(
                    'dynamodb',
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=os.environ.get('AWS_REGION', 'us-west-1')
                )
            else:
                # Use default credentials (from ~/.aws/credentials)
                self.dynamodb = boto3.resource(
                    'dynamodb',
                    region_name=os.environ.get('AWS_REGION', 'us-west-1')
                )

            self.table_name = os.environ.get(
                'DYNAMODB_TABLE_NAME', 'app-metadata')

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
        """Get existing table or create new one if it doesn't exist."""
        try:
            # Try to get existing table
            table = self.dynamodb.Table(self.table_name)
            table.load()  # This will raise an exception if table doesn't exist
            logger.info(f"Using existing DynamoDB table: {self.table_name}")
            return table

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                # Table doesn't exist, create it
                logger.info(f"Creating DynamoDB table: {self.table_name}")
                return self._create_table()
            else:
                logger.error(f"Error accessing DynamoDB table: {e}")
                raise
        except Exception as e:
            logger.error(f"Unexpected error with DynamoDB table: {e}")
            raise

    def _create_table(self):
        """Create DynamoDB table with proper schema."""
        try:
            table = self.dynamodb.create_table(
                TableName=self.table_name,
                KeySchema=[
                    {
                        'AttributeName': 'file_id',
                        'KeyType': 'HASH'  # Partition key
                    }
                ],
                AttributeDefinitions=[
                    {
                        'AttributeName': 'file_id',
                        'AttributeType': 'S'
                    }
                ],
                BillingMode='PAY_PER_REQUEST'  # On-demand billing
            )

            # Wait for table to be created
            table.wait_until_exists()
            logger.info(
                f"DynamoDB table created successfully: {self.table_name}")
            return table

        except Exception as e:
            logger.error(f"Failed to create DynamoDB table: {e}")
            raise

    def store_file_metadata(self, file_id, metadata):
        """Store file metadata in DynamoDB."""
        try:
            # Add timestamp
            from datetime import datetime
            metadata['created_at'] = datetime.utcnow().isoformat()
            metadata['file_id'] = file_id

            response = self.table.put_item(Item=metadata)
            logger.info(f"Metadata stored for file: {file_id}")
            return {'success': True, 'response': response}

        except Exception as e:
            logger.error(f"Failed to store metadata for {file_id}: {e}")
            return {'success': False, 'error': str(e)}

    def get_file_metadata(self, file_id):
        """Retrieve file metadata from DynamoDB."""
        try:
            response = self.table.get_item(Key={'file_id': file_id})

            if 'Item' in response:
                logger.info(f"Metadata retrieved for file: {file_id}")
                return {'success': True, 'metadata': response['Item']}
            else:
                logger.info(f"No metadata found for file: {file_id}")
                return {'success': False, 'error': 'File not found'}

        except Exception as e:
            logger.error(f"Failed to retrieve metadata for {file_id}: {e}")
            return {'success': False, 'error': str(e)}

    def delete_file_metadata(self, file_id):
        """Delete file metadata from DynamoDB."""
        try:
            response = self.table.delete_item(Key={'file_id': file_id})
            logger.info(f"Metadata deleted for file: {file_id}")
            return {'success': True, 'response': response}

        except Exception as e:
            logger.error(f"Failed to delete metadata for {file_id}: {e}")
            return {'success': False, 'error': str(e)}

    def list_user_files(self, user_id, limit=50):
        """List all files for a specific user."""
        try:
            # Scan with filter for user_id
            response = self.table.scan(
                FilterExpression='user_id = :user_id',
                ExpressionAttributeValues={':user_id': user_id},
                Limit=limit
            )

            files = response.get('Items', [])
            logger.info(f"Retrieved {len(files)} files for user: {user_id}")
            return {'success': True, 'files': files}

        except Exception as e:
            logger.error(f"Failed to list files for user {user_id}: {e}")
            return {'success': False, 'error': str(e)}


# Global instance
dynamodb_manager = None


def init_dynamodb(app):
    """Initialize DynamoDB manager for Flask app."""
    global dynamodb_manager
    try:
        use_dynamodb = os.environ.get(
            'USE_DYNAMODB', 'false').lower() == 'true'

        if use_dynamodb:
            dynamodb_manager = DynamoDBManager()
            logger.info("DynamoDB Manager initialized successfully")
        else:
            logger.info(
                "DynamoDB disabled via USE_DYNAMODB environment variable")

    except Exception as e:
        logger.error(f"Failed to initialize DynamoDB Manager: {e}")
        # Don't raise the exception, just log it
        # This allows the app to continue running without DynamoDB


def get_dynamodb_manager():
    """Get the global DynamoDB manager instance."""
    return dynamodb_manager
