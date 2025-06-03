# Flask File Upload Application

A secure, full-featured web application built with Flask that provides user authentication and file upload capabilities with a modern, responsive UI.

## 🚀 Features

### Authentication System
- **User Registration & Login** - Secure user account creation and authentication
- **Password Hashing** - Werkzeug security for password protection
- **Session Management** - Flask-Login integration with "remember me" functionality
- **Profile Management** - Users can update username and password
- **Protected Routes** - Login required for file operations

### File Upload & Management
- **Secure File Upload** - Multiple file type support with validation
- **File Size Limits** - 16MB maximum file size protection
- **File Type Validation** - Whitelist of allowed extensions
- **Unique File Storage** - UUID-based naming prevents conflicts
- **User-Isolated Storage** - Each user has private file directory
- **File Metadata Tracking** - Database storage of file information
- **Download & Delete** - Full file lifecycle management

### Modern UI/UX
- **Drag & Drop Interface** - Interactive file upload experience
- **Progress Indicators** - Real-time upload progress tracking
- **Responsive Design** - Mobile-friendly interface
- **Flash Messaging** - User feedback for all operations
- **File Preview** - Visual file information before upload

## 🛠 Tech Stack

- **Backend:** Python 3.x, Flask
- **Database:** SQLAlchemy with SQLite
- **Authentication:** Flask-Login, Werkzeug Security
- **Frontend:** HTML5, CSS3, JavaScript (Vanilla)
- **File Handling:** Secure filename processing, UUID generation
- **Containerization:** Docker support

## 📦 Installation & Setup

### Prerequisites
- Python 3.7+
- Docker (optional)

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/dockerflask.git
   cd dockerflask
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python run.py
   ```

5. **Access the application**
   - Open browser to `http://localhost:5000`
   - Default admin credentials: `admin` / `password`

### Docker Deployment

1. **Build the Docker image**
   ```bash
   docker build -t flask-upload-app .
   ```

2. **Run the container**
   ```bash
   docker run -p 5000:5000 flask-upload-app
   ```

## 🏗 Application Structure

```
app/
├── __init__.py          # Application factory
├── models.py            # Database models (User, UploadedFile)
├── routes.py            # Application routes and logic
└── templates/
    ├── upload.html      # File upload interface
    ├── login.html       # User authentication
    ├── register.html    # User registration
    ├── dashboard.html   # User dashboard
    ├── profile.html     # Profile management
    └── my_files.html    # File management
uploads/                 # User file storage (user-segregated)
run.py                   # Application entry point
Dockerfile              # Container configuration
requirements.txt        # Python dependencies
```

## 🔒 Security Features

- **Password Hashing:** All passwords encrypted using Werkzeug
- **Session Security:** Secure session management with Flask-Login
- **File Validation:** Whitelist-based file type checking
- **Path Security:** Secure filename processing prevents directory traversal
- **User Isolation:** Files are stored in user-specific directories
- **Size Limits:** Prevents large file uploads (DoS protection)
- **Authentication Required:** All file operations require login

## 📝 API Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/` | GET | Welcome page | No |
| `/login` | GET/POST | User authentication | No |
| `/register` | GET/POST | User registration | No |
| `/dashboard` | GET | User dashboard | Yes |
| `/profile` | GET/POST | Profile management | Yes |
| `/upload` | GET/POST | File upload interface | Yes |
| `/my-files` | GET | File management page | Yes |
| `/download/<id>` | GET | Download specific file | Yes |
| `/delete/<id>` | POST | Delete specific file | Yes |
| `/logout` | GET | User logout | Yes |

## 🎯 Supported File Types

**Documents:** PDF, DOC, DOCX, TXT, MD  
**Images:** PNG, JPG, JPEG, GIF  
**Data:** CSV, XLSX  
**Code:** PY, JS, HTML, CSS  
**Archives:** ZIP  

## 🚀 Production Considerations

### Environment Variables
```bash
export FLASK_ENV=production
export SECRET_KEY=your-production-secret-key
export DATABASE_URL=your-production-database-url
```

### Recommended Enhancements
- PostgreSQL for production database
- Redis for session storage
- AWS S3 for file storage
- Nginx reverse proxy
- SSL/TLS encryption
- Environment-based configuration
- Logging and monitoring
- Automated testing

## 🔧 Configuration

Key configuration options in `app/__init__.py`:

```python
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Developer

Built by **Travis Doster** - Cloud Architect & Full-Stack Developer  
🔗 [LinkedIn](https://linkedin.com/in/travisdoster) | 🌐 [Website](https://cloudapeiron.com)
