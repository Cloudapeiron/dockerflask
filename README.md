# Flask File Upload App with AWS S3 Integration

A modern Flask web application with user authentication and cloud file storage using AWS S3. Features hybrid storage (S3 + local fallback) and Docker containerization.

## Features

- 🔐 **User Authentication** - Registration, login, profile management
- ☁️ **AWS S3 Integration** - Cloud file storage with local fallback
- 📁 **File Management** - Upload, download, delete files
- 🐳 **Docker Ready** - Containerized deployment
- 📊 **File Analytics** - Track file sizes, types, and storage locations
- 🔄 **Hybrid Storage** - Automatic S3/local storage switching
- 🛡️ **Secure** - Environment-based credential management

## Tech Stack

- **Backend**: Flask, SQLAlchemy, Flask-Login
- **Storage**: AWS S3, Local filesystem (fallback)
- **Database**: SQLite (development), PostgreSQL (production ready)
- **Frontend**: Bootstrap 5, Jinja2 templates
- **Deployment**: Docker, Gunicorn

## Quick Start

### Prerequisites

- Python 3.11+
- AWS Account (for S3 storage)
- Docker (optional)

### Local Development

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/dockerflask.git
   cd dockerflask
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Set up AWS S3 (Optional)**

   ```bash
   export USE_S3_STORAGE=true
   export AWS_ACCESS_KEY_ID=your-access-key
   export AWS_SECRET_ACCESS_KEY=your-secret-key
   export S3_BUCKET_NAME=your-bucket-name
   export AWS_REGION=us-west-1
   ```

4. **Run the application**

   ```bash
   flask run
   ```

5. **Access the app**
   - Open http://127.0.0.1:5000
   - Default admin login: `admin` / `password`

### Docker Deployment

1. **Build and run**

   ```bash
   docker-compose up --build
   ```

2. **With S3 environment variables**
   ```bash
   docker-compose up -e USE_S3_STORAGE=true -e AWS_ACCESS_KEY_ID=your-key
   ```

## Configuration

### Environment Variables

| Variable                | Description         | Default            |
| ----------------------- | ------------------- | ------------------ |
| `USE_S3_STORAGE`        | Enable S3 storage   | `false`            |
| `AWS_ACCESS_KEY_ID`     | AWS access key      | Required for S3    |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key      | Required for S3    |
| `S3_BUCKET_NAME`        | S3 bucket name      | Required for S3    |
| `AWS_REGION`            | AWS region          | `us-east-1`        |
| `SECRET_KEY`            | Flask secret key    | Auto-generated     |
| `DATABASE_URL`          | Database connection | `sqlite:///app.db` |

### Storage Types

- **S3 Storage**: Files stored in AWS S3 bucket with user-specific folders
- **Local Storage**: Files stored in `/app/uploads` (Docker) or `./uploads` (local)
- **Hybrid Mode**: Automatically falls back to local if S3 unavailable

## Project Structure

```
dockerflask/
├── app/
│   ├── __init__.
```
