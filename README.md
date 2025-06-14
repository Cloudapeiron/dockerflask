# Serverless File Upload App

A modern, serverless file upload application built with Flask and deployed on AWS Lambda. Features secure JWT authentication with AWS Parameter Store, cloud storage, and support for large file uploads up to 1GB.

## 🚀 Architecture

- **Frontend**: Flask with responsive HTML templates
- **Authentication**: JWT tokens with AWS Parameter Store
- **Backend**: AWS Lambda (serverless compute)
- **Storage**: AWS S3 (file storage)
- **Database**: AWS DynamoDB (metadata storage)
- **API**: AWS API Gateway (public endpoints)
- **Security**: AWS Parameter Store for encrypted secret management

## 🤖 AI Integration Architecture

This Flask application serves as the **frontend ingestion layer** for a comprehensive AI processing system. While the core file upload and management functionality is production-ready, we're actively developing an enhanced backend infrastructure for AI algorithm integration.

### Current Role in AI Workflow

- **File Ingestion**: Secure upload and validation of media files (video, audio, documents)
- **Metadata Management**: Track file processing status and results in DynamoDB
- **API Gateway**: RESTful endpoints for frontend applications and AI service integration
- **Status Tracking**: Real-time monitoring of file processing workflows

### Planned AI Backend Integration

- **AWS Step Functions**: Orchestrate complex AI processing workflows
- **Batch Processing**: Handle large-scale media processing efficiently
- **Real-time Status Updates**: WebSocket connections for live processing feedback
- **Multi-Algorithm Support**: Video analysis, audio processing, document understanding
- **Scalable Architecture**: Auto-scaling infrastructure for varying workloads

### Why This Architecture

The separation of concerns allows:

- **Independent Development**: Frontend team can iterate without blocking AI development
- **Scalable Processing**: Backend can handle intensive AI workloads separately
- **Flexible Integration**: Easy to add new AI algorithms and processing types
- **Cost Optimization**: Scale compute resources based on actual processing needs

## ✨ Current Features

### 🔐 Security

- **AWS Parameter Store Integration** - Encrypted secret storage, no hardcoded credentials
- **JWT Authentication** - Stateless authentication with secure token management
- **Zero Secrets in Code** - All sensitive data stored securely in AWS

### 📁 File Handling

- **Large File Support** - Upload files up to 1GB
- **Multiple File Types** - Video (.mp4, .mov, .avi), audio (.wav, .mp3, .flac), documents, images
- **Smart Validation** - MIME type detection and file categorization
- **Large File Warnings** - Automatic warnings for files over 100MB

### ☁️ Cloud Infrastructure

- **S3 Storage** - Files stored securely in AWS S3
- **DynamoDB Metadata** - File tracking and user management
- **Serverless Scaling** - Pay only for what you use, auto-scaling
- **Responsive Design** - Works on all devices
- **Drag & Drop** - Intuitive file upload experience

## 🏗️ Tech Stack

- **Backend**: Python 3.11, Flask
- **Authentication**: PyJWT with AWS Parameter Store
- **Security**: AWS Parameter Store for secret management
- **Cloud Platform**: AWS (Lambda, S3, DynamoDB, API Gateway, Parameter Store)
- **Deployment**: Zappa
- **Frontend**: HTML5, CSS3, JavaScript

## 🌐 Live Application

**Production URL**: Demo environment available - contact for access

**Demo Access**: Contact administrator for demo credentials

## 📁 Project Structure

```
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── routes.py                # API routes and web endpoints
│   ├── jwt_auth.py              # JWT authentication system
│   ├── dynamodb_manager.py      # DynamoDB operations
│   ├── storage.py               # S3 storage operations
│   ├── file_validator.py        # File validation (1GB support)
│   └── templates/               # HTML templates
│       ├── login.html          # Login page
│       ├── upload.html         # File upload interface
│       └── my_files.html       # File listing page
├── config.py                    # Configuration with Parameter Store
├── lambda_function.py           # AWS Lambda entry point
├── zappa_settings.json          # Zappa deployment config
├── debug_app.py                 # Development entry point
└── requirements.txt             # Python dependencies
```

## ⚙️ Configuration

### AWS Parameter Store Setup

Store your secrets securely in AWS Parameter Store:

```bash
# JWT Secret Key (Required)
aws ssm put-parameter \
    --name "/your-app/jwt-secret-key" \
    --value "your-secure-64-character-secret" \
    --type "SecureString" \
    --region us-west-1

# S3 Bucket Name
aws ssm put-parameter \
    --name "/your-app/s3-bucket-name" \
    --value "your-unique-bucket-name" \
    --type "String" \
    --region us-west-1
```

### Environment Variables

| Variable            | Description                | Default                 |
| ------------------- | -------------------------- | ----------------------- |
| AWS_REGION          | AWS region for services    | us-west-1               |
| S3_BUCKET_NAME      | S3 bucket for file storage | Set via Parameter Store |
| DYNAMODB_TABLE_NAME | DynamoDB table name        | your-app-metadata       |
| USE_S3_STORAGE      | Enable S3 storage          | true                    |
| USE_DYNAMODB        | Enable DynamoDB            | true                    |
| LAMBDA_ENVIRONMENT  | Lambda environment flag    | true                    |

### AWS Resources

- **S3 Bucket**: Configured via Parameter Store
- **DynamoDB Table**: Configured during deployment
- **Lambda Function**: Auto-generated during Zappa deployment
- **API Gateway**: Auto-generated endpoint
- **Parameter Store**: Encrypted secret storage
