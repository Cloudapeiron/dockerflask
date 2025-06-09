Serverless File Upload App
A modern, serverless file upload application built with Flask and deployed on AWS Lambda. Features secure JWT authentication, cloud storage, and a beautiful responsive UI.
🚀 Architecture Evolution
Previous Version: Traditional Flask app with Docker deployment
Current Version: Fully serverless application on AWS Lambda

Frontend: Flask with beautiful responsive HTML templates
Authentication: JWT tokens (serverless-friendly, replaced Flask-Login)
Backend: AWS Lambda (serverless compute)
Storage: AWS S3 (file storage)
Database: AWS DynamoDB (metadata storage, replaced SQLite)
API: AWS API Gateway (public endpoints)

✨ Features

🔐 Secure Authentication - JWT-based stateless authentication
☁️ Cloud Storage - Files stored securely in AWS S3
📊 Metadata Tracking - File information stored in DynamoDB
📱 Responsive Design - Beautiful UI that works on all devices
🎯 Drag & Drop - Intuitive file upload experience
⚡ Serverless - Pay only for what you use, auto-scaling
🛡️ Secure - AWS IAM permissions and encrypted storage

🏗️ Tech Stack
Current (Serverless):

Backend: Python 3.11, Flask
Authentication: PyJWT (replaced Flask-Login)
Cloud Platform: AWS (Lambda, S3, DynamoDB, API Gateway)
Deployment: Zappa (replaced Docker)
Frontend: HTML5, CSS3, JavaScript (Vanilla)

Previous (Traditional):

Backend: Flask, SQLAlchemy, Flask-Login
Storage: AWS S3 + Local filesystem fallback
Database: SQLite/PostgreSQL
Deployment: Docker, Gunicorn

🌐 Live Application
Production URL: https://0ufbqvfkaj.execute-api.us-west-1.amazonaws.com/development/
Default Credentials:

Username: admin
Password: password

📁 Project Structure
├── app/
│   ├── __init__.py          # Flask app factory (serverless-optimized)
│   ├── routes.py            # API routes and web endpoints
│   ├── jwt_auth.py          # JWT authentication system
│   ├── dynamodb_manager.py  # DynamoDB operations
│   ├── storage.py           # S3 storage operations
│   ├── models.py            # Legacy SQLAlchemy models (unused in serverless)
│   └── templates/           # HTML templates
│       ├── login.html       # Login page
│       ├── upload.html      # File upload interface
│       └── my_files.html    # File listing page
├── config.py                # Configuration settings (supports both modes)
├── lambda_function.py       # AWS Lambda entry point
├── zappa_settings.json      # Zappa deployment config
├── docker-compose.yml       # Legacy Docker setup (if needed locally)
├── Dockerfile               # Legacy Docker configuration
└── requirements.txt         # Python dependencies
⚙️ Configuration
Environment Variables
VariableDescriptionServerless DefaultAWS_REGIONAWS region for servicesus-west-1S3_BUCKET_NAMES3 bucket for file storageyour-flask-uploadsDYNAMODB_TABLE_NAMEDynamoDB table nameflask-file-metadataUSE_S3_STORAGEEnable S3 storagetrue (required)USE_DYNAMODBEnable DynamoDBtrue (required)LAMBDA_ENVIRONMENTLambda environment flagtrueSECRET_KEYFlask secret keyFrom AWS Parameter Store
AWS Resources

S3 Bucket: your-flask-uploads (us-west-1)
DynamoDB Table: flask-file-metadata (auto-created)
Lambda Function: flask-file-app-dev-development
API Gateway: Auto-generated endpoint
Parameter Store: Secure secret key storage

🚦 Getting Started
Serverless Deployment (Current)

Clone the repository
bashgit clone <your-repo-url>
cd dockerflask

Create virtual environment
bashpython -m venv flask-lambda-env
source flask-lambda-env/bin/activate

Install dependencies
bashpip install flask boto3 flask-login werkzeug PyJWT zappa

Configure AWS
bashaws configure  # Set up AWS credentials
export AWS_REGION=us-west-1

Create S3 bucket
bashaws s3 mb s3://your-flask-uploads --region us-west-1

Deploy to AWS
bashzappa deploy development


Local Development (Legacy Mode)
For local testing with the traditional Flask setup:
bash# Use SQLite and local storage
export LAMBDA_ENVIRONMENT=false
export USE_S3_STORAGE=false
export USE_DYNAMODB=false
flask run
🚀 Deployment Commands
bash# Deploy to serverless
zappa deploy development

# Update existing deployment
zappa update development

# View real-time logs
zappa tail development

# Check deployment status
zappa status development

# Remove deployment
zappa undeploy development
💰 Cost Comparison
Serverless (Current):

Lambda: 1M requests/month FREE
S3: ~$0.023/GB/month
DynamoDB: 25GB FREE tier
Estimated cost: < $1/month for low traffic

Traditional (Previous):

Docker hosting: $5-50/month
Database hosting: $5-20/month
Estimated cost: $10-70/month

🔄 Migration Notes
What Changed:

✅ Replaced Flask-Login with JWT authentication
✅ Replaced SQLite/PostgreSQL with DynamoDB
✅ Removed Docker dependency for production
✅ Added Zappa for serverless deployment
✅ Updated templates for serverless architecture

What Stayed:

✅ Flask framework and routing structure
✅ S3 storage integration
✅ Beautiful responsive UI
✅ File upload/download functionality

🛠️ Development
Testing Locally
bash# Test serverless functions locally
LAMBDA_ENVIRONMENT=true python -c "from lambda_function import app; print('App works!')"

# Test authentication
curl -X POST https://your-api-url/development/login \
  -d "username=admin&password=password"
Adding Features

Backend Routes: Add to app/routes.py
Authentication: Modify app/jwt_auth.py
Storage: Extend app/storage.py
Database: Update app/dynamodb_manager.py

🆘 Troubleshooting
Common Serverless Issues

"S3 storage not initialized"

Verify S3 bucket exists: aws s3 ls s3://your-flask-uploads
Check IAM permissions
Confirm bucket is in us-west-1 region


"DynamoDB initialization failed"

Check AWS credentials
Verify region settings


"502 Bad Gateway"

Check logs: zappa tail development
Verify all dependencies are installed



Legacy Docker Issues
If you need to run the legacy Docker version:
bashdocker-compose up --build
🎯 Roadmap
Serverless Enhancements:

 File deletion via DynamoDB
 User registration system in DynamoDB
 Custom domain setup
 Production environment
 File sharing capabilities
 Advanced file preview

Legacy Support:

 Maintain Docker compatibility for local development
 Support both SQLite and DynamoDB modes


🚀 Now fully serverless on AWS Lambda - from traditional Docker app to modern cloud architecture!
Built with ❤️ using Flask, AWS Lambda, and modern web technologiesRetryClaude can make mistakes. Please double-check responses.Researchbeta Sonnet 4
