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
| Variable | Description | Default |
|----------|-------------|---------|
| AWS_REGION | AWS region for services | us-west-1 |
| S3_BUCKET_NAME | S3 bucket for file storage | Set via Parameter Store |
| DYNAMODB_TABLE_NAME | DynamoDB table name | your-app-metadata |
| USE_S3_STORAGE | Enable S3 storage | true |
| USE_DYNAMODB | Enable DynamoDB | true |
| LAMBDA_ENVIRONMENT | Lambda environment flag | true |

### AWS Resources
- **S3 Bucket**: Configured via Parameter Store
- **DynamoDB Table**: Configured during deployment
- **Lambda Function**: Auto-generated during Zappa deployment
- **API Gateway**: Auto-generated endpoint
- **Parameter Store**: Encrypted secret storage in `/your-app/` namespace

## 🚦 Getting Started

### Serverless Deployment

1. **Clone the repository**
```bash
git clone https://github.com/Cloudapeiron/dockerflask.git
cd dockerflask
```

2. **Create virtual environment**
```bash
python -m venv flask-lambda-env
source flask-lambda-env/bin/activate
```

3. **Install dependencies** 
```bash
pip install flask boto3 PyJWT zappa marshmallow
```

4. **Configure AWS**
```bash
aws configure  # Set up AWS credentials
export AWS_REGION=us-west-1
```

5. **Set up Parameter Store secrets**
```bash
# Generate secure JWT secret
python -c "import secrets; print(secrets.token_hex(32))"

# Store in Parameter Store
aws ssm put-parameter \
    --name "/your-app/jwt-secret-key" \
    --value "YOUR_GENERATED_SECRET" \
    --type "SecureString"
```

6. **Create S3 bucket**
```bash
aws s3 mb s3://your-unique-bucket-name --region us-west-1
```

7. **Deploy to AWS**
```bash
zappa deploy development
```

### Local Development

For local testing:
```bash
# The app will automatically use Parameter Store if available,
# fallback to environment variables for local development
export SECRET_KEY=your-local-secret
export USE_S3_STORAGE=true
export USE_DYNAMODB=true

# Start development server
python debug_app.py
```

## 📊 File Upload Capabilities

### Supported File Types
- **Images**: JPG, JPEG, PNG, GIF
- **Documents**: PDF, TXT, DOC, DOCX, XLS, XLSX, PPT, PPTX, CSV
- **Video**: MP4, MOV, AVI, MKV
- **Audio**: MP3, WAV, M4A, FLAC
- **Archives**: ZIP

### File Size & Validation
- **Maximum file size**: 1GB
- **Warning threshold**: 100MB (users get warnings for large uploads)
- **Automatic categorization**: Files are categorized by type
- **MIME type validation**: Proper file type detection

### Check Upload Limits
```bash
# Test file info endpoint
curl -X GET https://your-api-endpoint/development/api/file-info

# Response includes:
{
  "max_size": "1GB",
  "max_size_bytes": 1073741824,
  "allowed_extensions": [".mp4", ".mov", ".avi", ...],
  "categories": ["video", "audio", "document", "image", "archive"],
  "note": "Large files (>100MB) may take time to upload"
}
```

## 🚀 Deployment Commands

```bash
# Deploy to serverless
zappa deploy development

# Update existing deployment  
zappa update development

# View real-time logs
zappa tail development

# Check deployment status
zappa status development

# Remove deployment
zappa undeploy development
```

## 🔒 Security Features

### Parameter Store Integration
- **Encrypted Storage**: All secrets encrypted at rest in AWS Parameter Store
- **No Hardcoded Secrets**: Zero sensitive data in source code
- **Automatic Fallback**: Gracefully falls back to environment variables for development
- **Regional Security**: Secrets stored in the same region as application

### How It Works
```python
# The app automatically checks Parameter Store first, then environment variables
SECRET_KEY = get_secret_from_parameter_store('/your-app/jwt-secret-key') or os.environ.get('SECRET_KEY')

# Fail-safe: App won't start without a valid secret key
if not SECRET_KEY:
    raise ValueError("SECRET_KEY must be set in Parameter Store or environment")
```

## 💰 Cost Breakdown

**Serverless Architecture**:
- Lambda: 1M requests/month FREE
- S3: ~$0.023/GB/month  
- DynamoDB: 25GB FREE tier
- Parameter Store: 10,000 parameters FREE
- **Estimated cost**: < $1/month for low traffic

## 🛠️ API Endpoints

### Authentication
- `POST /api/register` - User registration
- `POST /api/login` - User login  
- `POST /api/change-password` - Change password

### File Operations  
- `POST /api/upload` - Upload file (supports up to 1GB)
- `GET /api/files` - List user's files
- `POST /api/validate-file` - Validate file without uploading

### Utility
- `GET /api/status` - Application health check
- `GET /api/file-info` - Get upload limits and supported file types

## 🧪 Testing

### Test Large File Upload
```bash
# Test with a large file
curl -X POST -F "file=@path/to/large-video.mp4" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  https://your-api-endpoint/development/api/upload

# Check file info
curl -X GET https://your-api-endpoint/development/api/file-info
```

### Test Authentication
```bash
# Login
curl -X POST https://your-api-endpoint/development/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'
```

## 🎯 Use Cases & AI Integration

### Current Production Use Cases
1. **Media File Ingestion** - Secure upload and storage of video, audio, and document files
2. **User Management** - JWT-based authentication and file ownership tracking
3. **File Validation** - Type checking, size validation, and metadata extraction
4. **API Access** - RESTful endpoints for frontend applications

### AI Processing Integration (In Development)
1. **Video Analysis** - Content analysis, object detection, scene recognition
2. **Audio Processing** - Speech-to-text, audio classification, noise reduction  
3. **Document Understanding** - OCR, text extraction, content analysis
4. **Batch Workflows** - Process multiple files with complex AI pipelines
5. **Real-time Feedback** - Live status updates during processing

### Architecture Benefits for AI
- **Separation of Concerns**: File management and AI processing are decoupled
- **Scalable Processing**: Backend can scale independently based on AI workload
- **Multiple AI Services**: Easy integration of different AI algorithms and providers
- **Fault Tolerance**: Failed AI processing doesn't affect file storage and management

### Parameter Store Issues
- **"SECRET_KEY not found"**: `aws ssm get-parameter --name "/your-app/jwt-secret-key"`
- **"Access Denied"**: Check IAM permissions for Parameter Store
- **"Wrong Region"**: Ensure secrets are in `us-west-1`

### Large File Upload Issues  
- **"File too large"**: Check Flask and API Gateway limits
- **"Request timeout"**: Large files may take time
- **"Memory errors"**: Monitor Lambda memory usage

### Common Issues

1. **"S3 storage not
