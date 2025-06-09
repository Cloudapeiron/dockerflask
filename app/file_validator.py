import os
import logging
from typing import Dict, List, Optional, Tuple
from werkzeug.datastructures import FileStorage

logger = logging.getLogger(__name__)


class FileValidator:
    ALLOWED_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.doc', '.docx',
        '.xls', '.xlsx', '.zip', '.mp4', '.mp3', '.csv', '.mov', '.avi',
        '.mkv', '.wav', '.m4a', '.flac', '.pptx', '.ppt'
    }

    # Increased size limit for POC - 1GB
    MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB in bytes

    def __init__(self):
        logger.info('Basic file validator initialized with 1GB size limit')

    def validate_file(self, file):
        result = {
            'valid': False, 'mime_type': 'unknown', 'category': 'unknown',
            'size': 0, 'errors': [], 'warnings': []
        }

        if not file or not file.filename:
            result['errors'].append('No file provided')
            return result

        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)
        result['size'] = file_size

        if file_size == 0:
            result['errors'].append('File is empty')
            return result

        import os
        file_ext = os.path.splitext(file.filename)[1].lower()
        if file_ext not in self.ALLOWED_EXTENSIONS:
            result['errors'].append(f'File type {file_ext} not allowed')
            return result

        # Updated size check - now 1GB limit
        if file_size > self.MAX_FILE_SIZE:
            size_mb = file_size / (1024 * 1024)
            result['errors'].append(
                f'File too large ({size_mb:.1f}MB, max 1GB)')
            return result

        # Add warning for large files (over 100MB)
        if file_size > 100 * 1024 * 1024:
            size_mb = file_size / (1024 * 1024)
            result['warnings'].append(
                f'Large file detected ({size_mb:.1f}MB) - upload may take time')

        result['valid'] = True

        # Better MIME type detection
        result['mime_type'] = self._get_mime_type(file_ext)
        result['category'] = self._get_file_category(file_ext)

        return result

    def _get_mime_type(self, file_ext):
        """Get proper MIME type for file extension"""
        mime_types = {
            '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
            '.gif': 'image/gif', '.pdf': 'application/pdf', '.txt': 'text/plain',
            '.doc': 'application/msword', '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel', '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.ppt': 'application/vnd.ms-powerpoint', '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            '.zip': 'application/zip', '.csv': 'text/csv',
            '.mp4': 'video/mp4', '.mov': 'video/quicktime', '.avi': 'video/x-msvideo', '.mkv': 'video/x-matroska',
            '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.m4a': 'audio/mp4', '.flac': 'audio/flac'
        }
        return mime_types.get(file_ext, f'application/{file_ext[1:]}')

    def _get_file_category(self, file_ext):
        """Categorize file by extension"""
        categories = {
            'image': {'.jpg', '.jpeg', '.png', '.gif'},
            'document': {'.pdf', '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.csv'},
            'video': {'.mp4', '.mov', '.avi', '.mkv'},
            'audio': {'.mp3', '.wav', '.m4a', '.flac'},
            'archive': {'.zip'}
        }

        for category, extensions in categories.items():
            if file_ext in extensions:
                return category
        return 'other'


file_validator = None


def init_file_validator(app):
    global file_validator
    try:
        file_validator = FileValidator()
        app.logger.info('Basic file validator initialized with 1GB limit')
        return True
    except Exception as e:
        app.logger.error(f'File validator failed: {e}')
        return False


def validate_uploaded_file(file):
    if file_validator:
        return file_validator.validate_file(file)
    return {
        'valid': False, 'errors': ['File validator not available'],
        'warnings': [], 'mime_type': 'unknown', 'category': 'unknown', 'size': 0
    }


def get_allowed_file_info():
    return {
        'allowed_extensions': list(FileValidator.ALLOWED_EXTENSIONS),
        'max_size': '1GB',
        'max_size_bytes': FileValidator.MAX_FILE_SIZE,
        'categories': ['image', 'document', 'video', 'audio', 'archive', 'other'],
        'note': 'Large files (>100MB) may take time to upload'
    }
