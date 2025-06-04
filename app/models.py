# app/models.py - WITH S3 SUPPORT
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    # Add relationship to uploaded files
    uploaded_files = db.relationship(
        'UploadedFile', backref='user', lazy=True, cascade='all, delete-orphan')


class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(100), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # For local: file path, For S3: S3 key
    file_path = db.Column(db.String(500), nullable=False)

    # New S3-related fields
    s3_url = db.Column(db.String(1000), nullable=True)  # Direct S3 URL
    storage_type = db.Column(
        db.String(20), default='local', nullable=False)  # 'local' or 's3'
    # S3 object key (backup field)
    s3_key = db.Column(db.String(500), nullable=True)

    def __repr__(self):
        return f'<UploadedFile {self.original_filename}>'

    def format_file_size(self):
        """Helper method to format file size in human readable format."""
        if self.file_size == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        size = float(self.file_size)
        while size >= 1024 and i < len(size_names) - 1:
            size /= 1024.0
            i += 1
        return f"{size:.1f} {size_names[i]}"

    def get_storage_icon(self):
        """Helper method to get storage type icon for templates."""
        if self.storage_type == 's3':
            return '☁️'  # Cloud icon for S3
        else:
            return '💾'  # Disk icon for local storage

    def is_s3_file(self):
        """Check if file is stored in S3."""
        return self.storage_type == 's3'

    def get_download_url(self):
        """Get the appropriate download URL based on storage type."""
