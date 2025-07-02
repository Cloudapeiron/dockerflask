# Serverless File Upload App

A modern, serverless file upload application built with Flask and deployed on AWS Lambda. Features secure JWT authentication with AWS Parameter Store, cloud storage, and support for large file uploads up to 1GB.

## 🚀 Architecture

* **Frontend**: Flask with responsive HTML templates
* **Authentication**: JWT tokens with AWS Parameter Store
* **Backend**: AWS Lambda (serverless compute)
* **Storage**: AWS S3 (file storage)
* **Database**: AWS DynamoDB (metadata storage)
* **API**: AWS API Gateway (public endpoints)
* **Security**: AWS Parameter Store for encrypted secret management

## 🤖 AI Integration Architecture

This Flask application serves as the frontend ingestion layer for a comprehensive AI processing system. While the core file upload and management functionality is production-ready, we're actively developing an enhanced backend infrastructure for AI algorithm integration.

### Current Role in AI Workflow

* **File Ingestion**: Secure upload and validation of media files (video, audio, documents)
* **Metadata Management**: Track file processing status and results in DynamoDB
* **API Gateway**: RESTful endpoints for frontend applications and AI service integration
* **Status Tracking**: Real-time monitoring of file processing workflows

### Planned AI Backend Integration

* **AWS Step Functions**: Orchestrate complex AI processing workflows
* **Batch Processing**: Handle large-scale media processing efficiently
* **Real-time Status Updates**: WebSocket connections for live processing feedback
* **Multi-Algorithm Support**: Video analysis, audio processing, document understanding
* **Scalable Architecture**: Auto-scaling infrastructure for varying workloads

### Why This Architecture

The separation of concerns allows:
* **Independent Development**: Frontend team can iterate without blocking AI development
* **Scalable Processing**: Backend can handle intensive AI workloads separately
* **Flexible Integration**: Easy to add new AI algorithms and processing types
* **Cost Optimization**: Scale compute resources based on actual processing needs

## ✨ Current Features

### 🔐 Security

* **AWS Parameter Store Integration** - Encrypted secret storage, no hardcoded credentials
* **JWT Authentication** - Stateless authentication with secure token management
* **Zero Secrets in Code** - All sensitive data stored securely in AWS
* **Regional Consistency** - All AWS services use consistent us-west-1 region

### 📁 File Handling

* **Large File Support** - Upload files up to 1GB
* **Multiple File Types** - Video (.mp4, .mov, .avi), audio (.wav, .mp3, .flac), documents, images
* **Smart Validation** - MIME type detection and file categorization
* **Large File Warnings** - Automatic warnings for files over 100MB

### ☁️ Cloud Infrastructure

* **S3 Storage** - Files stored securely in AWS S3
* **DynamoDB Metadata** - File tracking and user management
* **Serverless Scaling** - Pay only for what you use, auto-scaling
* **Responsive Design** - Works on all devices
* **Drag & Drop** - Intuitive file upload experience

## 🏗️ Tech Stack

* **Backend**: Python 3.11, Flask
* **Authentication**: PyJWT with AWS Parameter Store
* **Security**: AWS Parameter Store for secret management
* **Cloud Platform**: AWS (Lambda, S3, DynamoDB, API Gateway, Parameter Store)
* **Deployment**: Zappa
* **Frontend**: HTML5, CSS3, JavaScript

## 🌐 Live Application

* **Production URL**: Demo environment available - contact for access
* **Demo Access**: Contact administrator for demo credentials

## 📁 Project Structure

```
serverless-file-upload/
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── zappa_settings.json        # Zappa deployment configuration
├── .env.example               # Environment variables template
├── README.md                  # Project documentation
├── .gitignore                 # Git ignore rules
├── config/
│   ├── __init__.py
│   ├── aws_config.py          # AWS service configurations
│   └── jwt_config.py          # JWT authentication settings
├── utils/
│   ├── __init__.py
│   ├── auth.py                # Authentication utilities
│   ├── file_validator.py      # File validation logic
│   ├── s3_handler.py          # S3 operations
│   └── dynamodb_handler.py    # DynamoDB operations
├── templates/
│   ├── base.html              # Base template
│   ├── index.html             # Main upload page
│   ├── login.html             # Authentication page
│   └── dashboard.html         # User dashboard
├── static/
│   ├── css/
│   │   └── style.css          # Application styles
│   ├── js/
│   │   ├── upload.js          # File upload functionality
│   │   └── auth.js            # Authentication handling
│   └── images/
│       └── logo.png           # Application assets
├── tests/
│   ├── __init__.py
│   ├── test_app.py            # Application tests
│   ├── test_auth.py           # Authentication tests
│   └── test_file_upload.py    # File upload tests
└── scripts/
    ├── setup_aws.py           # AWS infrastructure setup
    ├── deploy.sh              # Deployment script
    └── cleanup.py             # Resource cleanup
```

## 🔧 Configuration Files

### zappa_settings.json
```json
{
    "production": {
        "app_function": "app.app",
        "aws_region": "us-west-1",
        "runtime": "python3.11",
        "s3_bucket": "your-zappa-deployment-bucket",
        "memory_size": 512,
        "timeout_seconds": 900,
        "environment_variables": {
            "LAMBDA_ENVIRONMENT": "true"
        },
        "cors": true,
        "binary_support": true
    }
}
```

### requirements.txt
```
Flask==2.3.3
PyJWT==2.8.0
boto3==1.29.7
python-dotenv==1.0.0
Pillow==10.0.1
python-magic==0.4.27
zappa==0.58.0
```

## 🐛 Debugging Guide

### Enable Debug Mode
```python
# In app.py for local development
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
```

### AWS CloudWatch Logs
```bash
# View Lambda logs
zappa tail production

# View logs in real-time
zappa tail production --since 1h

# Save logs to file
zappa save-python-settings-file production
```

### Local Testing
```python
# Test file upload locally
python test_local_upload.py

# Test AWS connections
python scripts/test_aws_connections.py
```

### Debug Environment Variables
```python
import os
print("Environment variables:")
for key, value in os.environ.items():
    if 'AWS' in key or 'JWT' in key:
        print(f"{key}: {'*' * len(value) if value else 'None'}")
```

## ⚠️ Common Problems & Solutions

### 1. **JWT Token Issues**
**Problem**: "Invalid token" or "Token expired" errors
```
Error: JWT token validation failed
```
**Solutions**:
- Check AWS Parameter Store for correct JWT secret
- Verify token expiration time (default 1 hour)
- Ensure consistent timezone handling
```python
# Debug JWT issues
import jwt
token = request.headers.get('Authorization', '').replace('Bearer ', '')
try:
    payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])
    print(f"Token valid, expires: {payload.get('exp')}")
except jwt.ExpiredSignatureError:
    print("Token expired")
except jwt.InvalidTokenError as e:
    print(f"Invalid token: {e}")
```

### 2. **File Upload Failures**
**Problem**: Large files failing to upload
```
Error: Request entity too large (413)
```
**Solutions**:
- Increase API Gateway payload limit (10MB max)
- Implement multipart upload for files >10MB
- Use pre-signed URLs for large files
```python
# Generate pre-signed URL for large files
def generate_presigned_url(bucket, key, expiration=3600):
    s3_client = boto3.client('s3')
    return s3_client.generate_presigned_url(
        'put_object',
        Params={'Bucket': bucket, 'Key': key},
        ExpiresIn=expiration
    )
```

### 3. **AWS Permission Errors**
**Problem**: Access denied errors for AWS services
```
Error: AccessDenied: User is not authorized to perform action
```
**Solutions**:
- Verify IAM role permissions
- Check Lambda execution role
- Ensure consistent AWS region (us-west-1)
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject"
            ],
            "Resource": "arn:aws:s3:::your-bucket/*"
        }
    ]
}
```

### 4. **DynamoDB Connection Issues**
**Problem**: Cannot connect to DynamoDB table
```
Error: ResourceNotFoundException: Requested resource not found
```
**Solutions**:
- Verify table exists in correct region
- Check table name in Parameter Store
- Ensure proper IAM permissions
```python
# Test DynamoDB connection
import boto3
dynamodb = boto3.resource('dynamodb', region_name='us-west-1')
try:
    table = dynamodb.Table('your-table-name')
    response = table.scan(Limit=1)
    print("DynamoDB connection successful")
except Exception as e:
    print(f"DynamoDB error: {e}")
```

### 5. **Parameter Store Access**
**Problem**: Cannot retrieve secrets from Parameter Store
```
Error: ParameterNotFound: Parameter not found
```
**Solutions**:
- Verify parameter names and paths
- Check encryption/decryption permissions
- Ensure parameters exist in correct region
```python
# Debug Parameter Store access
import boto3
ssm = boto3.client('ssm', region_name='us-west-1')
try:
    response = ssm.get_parameter(
        Name='/your-app/jwt-secret',
        WithDecryption=True
    )
    print("Parameter Store access successful")
except Exception as e:
    print(f"Parameter Store error: {e}")
```

### 6. **CORS Issues**
**Problem**: Browser blocking requests due to CORS
```
Error: Access to fetch blocked by CORS policy
```
**Solutions**:
- Enable CORS in zappa_settings.json
- Add proper headers in Flask responses
```python
from flask_cors import CORS
CORS(app, origins=['https://yourdomain.com'])

# Or manually add headers
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    return response
```

### 7. **Memory/Timeout Issues**
**Problem**: Lambda function timing out or running out of memory
```
Error: Task timed out after 30.00 seconds
```
**Solutions**:
- Increase memory allocation in zappa_settings.json
- Optimize file processing logic
- Use streaming for large files
```json
{
    "memory_size": 1024,
    "timeout_seconds": 900
}
```

## 📊 Monitoring & Logs

### CloudWatch Metrics
- Lambda duration and memory usage
- API Gateway request count and latency
- S3 upload success/failure rates
- DynamoDB read/write capacity

### Custom Logging
```python
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    logger.info(f"Upload attempt by user: {current_user_id}")
    try:
        # Upload logic
        logger.info(f"File uploaded successfully: {filename}")
    except Exception as e:
        logger.error(f"Upload failed: {str(e)}")
        raise
```

## 🔍 Health Check Endpoint
```python
@app.route('/health')
def health_check():
    checks = {
        'database': test_dynamodb_connection(),
        'storage': test_s3_connection(),
        'auth': test_parameter_store_connection()
    }
    
    if all(checks.values()):
        return jsonify({'status': 'healthy', 'checks': checks}), 200
    else:
        return jsonify({'status': 'unhealthy', 'checks': checks}), 503
```

## AWS Resources

| Component | Description | Value |
|-----------|-------------|-------|
| LAMBDA_ENVIRONMENT | Lambda environment flag | true |

**AWS Resources**
* **S3 Bucket**: Configured via Parameter Store
* **DynamoDB Table**: Configured during deployment
* **Lambda Function**: Auto-generated during Zappa deployment
* **API Gateway**: Auto-generated endpoint
* **Parameter Store**: Encrypted secret storage
