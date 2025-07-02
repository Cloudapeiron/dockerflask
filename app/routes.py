from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, make_response, current_app
from app.jwt_auth import jwt_required, authenticate_user, create_login_response, get_current_user
from app.schemas import (
    UserRegistrationSchema, UserLoginSchema, PasswordChangeSchema,
    FileUploadResponseSchema, FileListResponseSchema, UserResponseSchema,
    FileValidationResponseSchema, TaskStatusSchema, BatchProcessSchema,
    validate_request_json, serialize_response, create_error_response, create_success_response
)
from marshmallow import Schema, fields
from werkzeug.utils import secure_filename
import logging
import uuid
import hashlib
import os
import mimetypes
from datetime import datetime

# Try to import python-magic, fallback if not available
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("Warning: python-magic not available, using basic MIME detection")

logger = logging.getLogger(__name__)
main = Blueprint('main', __name__)

# ADD HEALTH CHECK HERE (around line 27):


@main.route('/health')
def health_check():
    """Health check endpoint for Kubernetes probes."""
    return {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'flask-app'
    }, 200


# Multi-format configuration that matches your Lambda
SUPPORTED_FORMATS = {
    'image': {
        'extensions': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'],
        'mime_types': ['image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/tiff', 'image/webp'],
        'max_size': 20 * 1024 * 1024,  # 20MB
        'description': 'Images (JPG, PNG, GIF, etc.)'
    },
    'document': {
        'extensions': ['.pdf', '.doc', '.docx', '.txt', '.rtf'],
        'mime_types': ['application/pdf', 'application/msword',
                       'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                       'text/plain', 'application/rtf'],
        'max_size': 100 * 1024 * 1024,  # 100MB
        'description': 'Documents (PDF, DOC, TXT, etc.)'
    },
    'video': {
        'extensions': ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm'],
        'mime_types': ['video/mp4', 'video/avi', 'video/quicktime', 'video/x-ms-wmv'],
        'max_size': 500 * 1024 * 1024,  # 500MB
        'description': 'Videos (MP4, AVI, MOV, etc.)'
    },
    'audio': {
        'extensions': ['.mp3', '.wav', '.flac', '.aac', '.ogg'],
        'mime_types': ['audio/mpeg', 'audio/wav', 'audio/flac', 'audio/aac'],
        'max_size': 50 * 1024 * 1024,  # 50MB
        'description': 'Audio (MP3, WAV, FLAC, etc.)'
    }
}


class EnhancedFileValidator:
    """Enhanced file validator with multi-format support"""

    @staticmethod
    def validate_file_advanced(file, filename):
        """Enhanced validation that works with your existing validator"""
        errors = []
        warnings = []

        # Use your existing validator first
        from app.file_validator import validate_uploaded_file
        basic_validation = validate_uploaded_file(file)

        if not basic_validation['valid']:
            return basic_validation

        # Reset file position for additional validation
        file.seek(0)
        file_content = file.read()
        file.seek(0)

        # Enhanced MIME type detection
        try:
            if MAGIC_AVAILABLE:
                detected_mime = magic.from_buffer(file_content, mime=True)
            else:
                detected_mime = mimetypes.guess_type(filename)[0] or basic_validation.get(
                    'mime_type', 'application/octet-stream')
        except:
            detected_mime = basic_validation.get(
                'mime_type', 'application/octet-stream')

        # Determine file type category
        file_extension = os.path.splitext(filename.lower())[1]
        file_type = None
        config = None

        for ftype, fconfig in SUPPORTED_FORMATS.items():
            if (detected_mime in fconfig['mime_types'] or
                    file_extension in fconfig['extensions']):
                file_type = ftype
                config = fconfig
                break

        if not file_type:
            warnings.append(
                f"File type not supported for enhanced processing: {detected_mime}")
            file_type = 'other'

        # Check enhanced size limits
        file_size = len(file_content)
        if config and file_size > config['max_size']:
            max_size_mb = config['max_size'] / (1024 * 1024)
            errors.append(
                f"File too large for {file_type} processing. Maximum: {max_size_mb:.1f}MB")

        # Add enhanced metadata
        enhanced_result = basic_validation.copy()
        enhanced_result.update({
            'file_type': file_type,
            'detected_mime': detected_mime,
            'enhanced_validation': True,
            'supports_optimization': file_type in ['image', 'video', 'audio'],
            'config': config
        })

        if errors:
            enhanced_result['valid'] = False
            enhanced_result['errors'].extend(errors)

        if warnings:
            if 'warnings' not in enhanced_result:
                enhanced_result['warnings'] = []
            enhanced_result['warnings'].extend(warnings)

        return enhanced_result


@main.route('/')
def index():
    """Home page - redirect to upload if authenticated, login if not"""
    user = get_current_user()
    if user:
        return redirect(url_for('main.upload'))
    return redirect(url_for('main.login'))


@main.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = authenticate_user(username, password)
        if user:
            if request.content_type != 'application/json':
                response = make_response(redirect(url_for('main.upload')))
                from app.jwt_auth import create_jwt_token
                token = create_jwt_token(user['id'], user['username'])
                response.set_cookie(
                    'jwt_token',
                    token,
                    max_age=24*60*60,
                    httponly=True,
                    secure=True,
                    samesite='Lax'
                )
                return response
            else:
                return create_login_response(user)
        else:
            if request.content_type != 'application/json':
                flash('Invalid username or password')
                return render_template('login.html')
            else:
                return jsonify({'error': 'Invalid credentials'}), 401

    return render_template('login.html')


@main.route('/logout')
def logout():
    """Logout - clear JWT token"""
    response = make_response(redirect(url_for('main.login')))
    response.set_cookie('jwt_token', '', expires=0)
    return response


@main.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if password != confirm_password:
            if request.content_type == 'application/json':
                return jsonify({'error': 'Passwords do not match'}), 400
            else:
                flash('Passwords do not match', 'error')
                return render_template('register.html')

        from app.jwt_auth import UserManager
        result = UserManager.create_user(username, email, password)

        if result['success']:
            if request.content_type == 'application/json':
                return jsonify({
                    'success': True,
                    'message': 'User created successfully',
                    'user': result['user']
                })
            else:
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('main.login'))
        else:
            if request.content_type == 'application/json':
                return jsonify({'error': result['error']}), 400
            else:
                flash(result['error'], 'error')
                return render_template('register.html')

    return render_template('register.html')


@main.route('/profile', methods=['GET', 'POST'])
@jwt_required
def profile():
    """User profile management"""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if new_password:
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return render_template('profile.html', user=request.current_user)

            from app.jwt_auth import UserManager
            result = UserManager.update_password(
                request.current_user['username'],
                current_password,
                new_password
            )

            if result['success']:
                flash('Password updated successfully!', 'success')
            else:
                flash(result['error'], 'error')

        return redirect(url_for('main.profile'))

    return render_template('profile.html', user=request.current_user)


@main.route('/upload', methods=['GET', 'POST'])
@jwt_required
def upload():
    """File upload page with validation"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)

        if file:
            try:
                validation_result = EnhancedFileValidator.validate_file_advanced(
                    file, file.filename)

                if not validation_result['valid']:
                    error_msg = ('File validation failed: ' +
                                 '; '.join(validation_result['errors']))
                    flash(error_msg, 'error')
                    return redirect(request.url)

                if validation_result.get('warnings'):
                    warning_msg = ('File warnings: ' +
                                   '; '.join(validation_result['warnings']))
                    flash(warning_msg, 'warning')

                if current_app.config.get('USE_S3_STORAGE'):
                    from app.storage import upload_to_s3

                    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                    unique_id = str(uuid.uuid4())[:8]
                    name, ext = os.path.splitext(file.filename)
                    unique_filename = f"{timestamp}_{unique_id}_{secure_filename(name)}{ext}"

                    result = upload_to_s3(
                        file, f"user-{request.current_user['id']}",
                        custom_filename=f"uploads/raw/{unique_filename}")

                    if result['success']:
                        flash('File uploaded successfully!')

                        if current_app.config.get('USE_DYNAMODB'):
                            from app.dynamodb_manager import get_dynamodb_manager

                            file_id = hashlib.md5(
                                f"{file.filename}_{int(datetime.utcnow().timestamp() * 1000)}".encode()).hexdigest()[:12]

                            metadata = {
                                'file_id': file_id,
                                'user_id': request.current_user['id'],
                                'filename': result['filename'],
                                'original_filename': file.filename,
                                'file_size': validation_result['size'],
                                'file_type': validation_result.get('file_type', 'other'),
                                'file_category': validation_result['category'],
                                'detected_mime': validation_result.get('detected_mime'),
                                'storage_type': 's3',
                                'file_path': result['key'],
                                's3_url': result['url'],
                                'validation_status': 'passed',
                                'validation_warnings': validation_result.get('warnings', []),
                                'processing_status': 'pending',
                                'supports_optimization': validation_result.get('supports_optimization', False),
                                'enhanced_validation': True,
                                'upload_timestamp': datetime.utcnow().isoformat()
                            }

                            dynamodb_manager = get_dynamodb_manager()
                            if dynamodb_manager:
                                save_result = dynamodb_manager.store_file_metadata(
                                    file_id, metadata)
                                if not save_result.get('success'):
                                    flash(
                                        f'File uploaded but metadata save failed: {save_result.get("error", "Unknown error")}')
                            else:
                                flash(
                                    'File uploaded but DynamoDB not available for metadata storage')
                    else:
                        flash(f'Upload failed: {result["error"]}')
                else:
                    flash('S3 storage not configured')

            except Exception as e:
                flash(f'Upload error: {str(e)}')

        return redirect(url_for('main.upload'))

    from app.file_validator import get_allowed_file_info
    allowed_files = get_allowed_file_info()

    enhanced_formats = {}
    for file_type, config in SUPPORTED_FORMATS.items():
        enhanced_formats[file_type] = {
            'description': config['description'],
            'extensions': config['extensions'],
            'max_size_mb': round(config['max_size'] / (1024 * 1024), 1),
            'supports_optimization': file_type in ['image', 'video', 'audio']
        }

    return render_template('upload.html',
                           user=request.current_user,
                           allowed_files=allowed_files,
                           enhanced_formats=enhanced_formats)


@main.route('/files')
@jwt_required
def files():
    """List user's files"""
    user_files = []

    try:
        if current_app.config.get('USE_DYNAMODB'):
            from app.dynamodb_manager import get_user_files
            user_files = get_user_files(request.current_user['id'])
    except Exception as e:
        flash(f'Error loading files: {str(e)}')

    return render_template('my_files.html', files=user_files, user=request.current_user)


@main.route('/api/register', methods=['POST'])
@validate_request_json(UserRegistrationSchema)
def api_register():
    """API endpoint for user registration with marshmallow validation"""
    try:
        validated_data = request.validated_data

        from app.jwt_auth import UserManager
        result = UserManager.create_user(
            validated_data['username'],
            validated_data['email'],
            validated_data['password']
        )

        if result['success']:
            user_data = serialize_response(result['user'], UserResponseSchema)
            return jsonify(create_success_response(
                message='User created successfully',
                data={'user': user_data}
            )), 201
        else:
            return jsonify(*create_error_response(result['error'], status_code=400))

    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify(*create_error_response('Registration failed', status_code=500))


@main.route('/api/login', methods=['POST'])
@validate_request_json(UserLoginSchema)
def api_login():
    """API endpoint for user login with marshmallow validation"""
    try:
        validated_data = request.validated_data

        user = authenticate_user(
            validated_data['username'], validated_data['password'])
        if user:
            login_response = create_login_response(user)
            if login_response['success']:
                user_data = serialize_response(user, UserResponseSchema)
                return jsonify({
                    'success': True,
                    'message': 'Login successful',
                    'user': user_data,
                    'token': login_response['token']
                })
            else:
                return jsonify(*create_error_response('Login failed', status_code=500))
        else:
            return jsonify(*create_error_response('Invalid credentials', status_code=401))

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify(*create_error_response('Login failed', status_code=500))


@main.route('/api/change-password', methods=['POST'])
@jwt_required
@validate_request_json(PasswordChangeSchema)
def api_change_password():
    """API endpoint for password change with marshmallow validation"""
    try:
        validated_data = request.validated_data

        from app.jwt_auth import UserManager
        result = UserManager.update_password(
            request.current_user['username'],
            validated_data['current_password'],
            validated_data['new_password']
        )

        if result['success']:
            return jsonify(create_success_response('Password updated successfully'))
        else:
            return jsonify(*create_error_response(result['error'], status_code=400))

    except Exception as e:
        logger.error(f"Password change error: {e}")
        return jsonify(*create_error_response('Password change failed', status_code=500))


@main.route('/api/upload', methods=['POST'])
@jwt_required
def api_upload():
    """Enhanced API endpoint for file upload with multi-format support"""
    if 'file' not in request.files:
        return jsonify(*create_error_response('No file provided', status_code=400))

    file = request.files['file']
    if file.filename == '':
        return jsonify(*create_error_response('No file selected', status_code=400))

    try:
        validation_result = EnhancedFileValidator.validate_file_advanced(
            file, file.filename)

        if not validation_result['valid']:
            return jsonify(*create_error_response(
                'File validation failed',
                validation_errors={'file': validation_result['errors']},
                status_code=400
            ))

        if current_app.config.get('USE_S3_STORAGE'):
            from app.storage import upload_to_s3

            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            unique_id = str(uuid.uuid4())[:8]
            name, ext = os.path.splitext(file.filename)
            unique_filename = f"{timestamp}_{unique_id}_{secure_filename(name)}{ext}"

            result = upload_to_s3(file, f"user-{request.current_user['id']}",
                                  custom_filename=f"uploads/raw/{unique_filename}")

            if result['success']:
                if current_app.config.get('USE_DYNAMODB'):
                    from app.dynamodb_manager import get_dynamodb_manager

                    file_id = hashlib.md5(
                        f"{file.filename}_{int(datetime.utcnow().timestamp() * 1000)}".encode()).hexdigest()[:12]

                    metadata = {
                        'file_id': file_id,
                        'user_id': request.current_user['id'],
                        'filename': result['filename'],
                        'original_filename': file.filename,
                        'file_size': validation_result['size'],
                        'file_type': validation_result.get('file_type', 'other'),
                        'file_category': validation_result['category'],
                        'detected_mime': validation_result.get('detected_mime'),
                        'storage_type': 's3',
                        'file_path': result['key'],
                        's3_url': result['url'],
                        'validation_status': 'passed',
                        'validation_warnings': validation_result.get('warnings', []),
                        'processing_status': 'pending',
                        'supports_optimization': validation_result.get('supports_optimization', False),
                        'enhanced_validation': True,
                        'upload_timestamp': datetime.utcnow().isoformat()
                    }

                    dynamodb_manager = get_dynamodb_manager()
                    if dynamodb_manager:
                        metadata_result = dynamodb_manager.store_file_metadata(
                            file_id, metadata)
                    else:
                        metadata_result = {"success": False,
                                           "error": "DynamoDB not available"}

                    response_data = {
                        'success': True,
                        'file_id': file_id,
                        'filename': result['filename'],
                        's3_url': result['url'],
                        'file_info': {
                            'mime_type': validation_result.get('detected_mime', validation_result['mime_type']),
                            'category': validation_result['category'],
                            'file_type': validation_result.get('file_type', 'other'),
                            'size': validation_result['size'],
                            'supports_optimization': validation_result.get('supports_optimization', False)
                        },
                        'processing_status': 'pending',
                        'validation_warnings': validation_result.get('warnings', []),
                        'lambda_processing': validation_result.get('supports_optimization', False)
                    }

                    serialized_response = serialize_response(
                        response_data, FileUploadResponseSchema)
                    return jsonify(serialized_response), 201

                response_data = {
                    'success': True,
                    'filename': result['filename'],
                    's3_url': result['url'],
                    'file_info': {
                        'mime_type': validation_result.get('detected_mime', validation_result['mime_type']),
                        'category': validation_result['category'],
                        'file_type': validation_result.get('file_type', 'other'),
                        'size': validation_result['size']
                    },
                    'validation_warnings': validation_result.get('warnings', [])
                }
                serialized_response = serialize_response(
                    response_data, FileUploadResponseSchema)
                return jsonify(serialized_response), 201
            else:
                return jsonify(*create_error_response(f'Upload failed: {result["error"]}', status_code=500))
        else:
            return jsonify(*create_error_response('S3 storage not configured', status_code=500))

    except Exception as e:
        logger.error(f"Enhanced upload error: {e}")
        return jsonify(*create_error_response('Upload failed', status_code=500))


@main.route('/api/upload-async', methods=['POST'])
@jwt_required
def api_upload_async():
    """API endpoint for file upload with background processing"""
    if 'file' not in request.files:
        return jsonify(*create_error_response('No file provided', status_code=400))

    file = request.files['file']
    if file.filename == '':
        return jsonify(*create_error_response('No file selected', status_code=400))

    try:
        validation_result = EnhancedFileValidator.validate_file_advanced(
            file, file.filename)

        if not validation_result['valid']:
            return jsonify(*create_error_response(
                'File validation failed',
                validation_errors={'file': validation_result['errors']},
                status_code=400
            ))

        if current_app.config.get('USE_S3_STORAGE'):
            from app.storage import upload_to_s3

            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            unique_id = str(uuid.uuid4())[:8]
            name, ext = os.path.splitext(file.filename)
            unique_filename = f"{timestamp}_{unique_id}_{secure_filename(name)}{ext}"

            result = upload_to_s3(file, f"user-{request.current_user['id']}",
                                  custom_filename=f"uploads/raw/{unique_filename}")

            if result['success']:
                if current_app.config.get('USE_DYNAMODB'):
                    from app.dynamodb_manager import get_dynamodb_manager

                    file_id = hashlib.md5(
                        f"{file.filename}_{int(datetime.utcnow().timestamp() * 1000)}".encode()).hexdigest()[:12]

                    metadata = {
                        'file_id': file_id,
                        'user_id': request.current_user['id'],
                        'filename': result['filename'],
                        'original_filename': file.filename,
                        'file_size': validation_result['size'],
                        'file_type': validation_result.get('file_type', 'other'),
                        'file_category': validation_result['category'],
                        'detected_mime': validation_result.get('detected_mime'),
                        'storage_type': 's3',
                        'file_path': result['key'],
                        's3_url': result['url'],
                        'validation_status': 'passed',
                        'validation_warnings': validation_result.get('warnings', []),
                        'processing_status': 'queued',
                        'supports_optimization': validation_result.get('supports_optimization', False),
                        'enhanced_validation': True,
                        'upload_timestamp': datetime.utcnow().isoformat()
                    }

                    dynamodb_manager = get_dynamodb_manager()
                    if dynamodb_manager:
                        metadata_result = dynamodb_manager.store_file_metadata(
                            file_id, metadata)
                        file_id = metadata_result.get('file_id')
                    else:
                        metadata_result = {"success": False,
                                           "error": "DynamoDB not available"}

                    try:
                        from app.celery_tasks import process_uploaded_file, send_processing_complete_notification

                        process_task = process_uploaded_file.delay(
                            file_id,
                            request.current_user['id'],
                            result['key'],
                            validation_result['mime_type']
                        )

                        notification_task = send_processing_complete_notification.delay(
                            request.current_user['id'],
                            file_id,
                            file.filename
                        )

                        response_data = {
                            'success': True,
                            'file_id': file_id,
                            'filename': result['filename'],
                            's3_url': result['url'],
                            'processing_task_id': process_task.id,
                            'notification_task_id': notification_task.id,
                            'status': 'uploaded_queued_for_processing',
                            'file_info': {
                                'mime_type': validation_result.get('detected_mime', validation_result['mime_type']),
                                'category': validation_result['category'],
                                'file_type': validation_result.get('file_type', 'other'),
                                'size': validation_result['size']
                            },
                            'validation_warnings': validation_result.get('warnings', [])
                        }

                        serialized_response = serialize_response(
                            response_data, FileUploadResponseSchema)
                        return jsonify(serialized_response), 202

                    except Exception as e:
                        logger.error(f"Failed to queue background task: {e}")
                        response_data = {
                            'success': True,
                            'file_id': file_id,
                            'filename': result['filename'],
                            's3_url': result['url'],
                            'status': 'uploaded_processing_unavailable',
                            'warning': 'File uploaded but background processing is unavailable',
                            'file_info': {
                                'mime_type': validation_result.get('detected_mime', validation_result['mime_type']),
                                'category': validation_result['category'],
                                'file_type': validation_result.get('file_type', 'other'),
                                'size': validation_result['size']
                            }
                        }
                        serialized_response = serialize_response(
                            response_data, FileUploadResponseSchema)
                        return jsonify(serialized_response), 201
                else:
                    return jsonify(*create_error_response('Database metadata save failed', status_code=500))
            else:
                return jsonify(*create_error_response(f'Upload failed: {result["error"]}', status_code=500))
        else:
            return jsonify(*create_error_response('S3 storage not configured', status_code=500))

    except Exception as e:
        logger.error(f"Async upload error: {e}")
        return jsonify(*create_error_response('Upload failed', status_code=500))


@main.route('/api/files')
@jwt_required
def api_files():
    """API endpoint to list user's files with marshmallow serialization"""
    try:
        user_files = []
        if current_app.config.get('USE_DYNAMODB'):
            from app.dynamodb_manager import get_user_files
            user_files = get_user_files(request.current_user['id'])

        response_data = {
            'files': user_files,
            'total_count': len(user_files),
            'user_id': str(request.current_user['id'])
        }

        serialized_response = serialize_response(
            response_data, FileListResponseSchema)
        return jsonify(serialized_response)

    except Exception as e:
        logger.error(f"File list error: {e}")
        return jsonify(*create_error_response('Failed to retrieve files', status_code=500))


@main.route('/api/validate-file', methods=['POST'])
@jwt_required
def api_validate_file():
    """API endpoint to validate a file without uploading"""
    if 'file' not in request.files:
        return jsonify(*create_error_response('No file provided', status_code=400))

    file = request.files['file']
    if file.filename == '':
        return jsonify(*create_error_response('No file selected', status_code=400))

    try:
        validation_result = EnhancedFileValidator.validate_file_advanced(
            file, file.filename)

        serialized_response = serialize_response(
            validation_result, FileValidationResponseSchema)
        return jsonify(serialized_response)

    except Exception as e:
        logger.error(f"File validation error: {e}")
        return jsonify(*create_error_response('File validation failed', status_code=500))


@main.route('/api/status')
def api_status():
    """Enhanced status endpoint with celery information"""
    try:
        celery_status = 'unavailable'
        try:
            from app.celery_tasks import celery
            if celery:
                inspect = celery.control.inspect()
                stats = inspect.stats()
                if stats:
                    celery_status = 'online'
                else:
                    celery_status = 'no_workers'
        except Exception:
            celery_status = 'error'

        status_data = {
            'status': 'online',
            'message': 'Flask upload application running',
            'services': {
                's3': current_app.config.get('USE_S3_STORAGE', False),
                'dynamodb': current_app.config.get('USE_DYNAMODB', False),
                'file_validation': True,
                'authentication': True,
                'marshmallow_validation': True,
                'celery': celery_status,
                'redis': celery_status in ['online', 'no_workers'],
                'enhanced_processing': True,
                'lambda_integration': True
            },
            'version': '1.0.0',
            'environment': current_app.config.get('FLASK_ENV', 'unknown'),
            'background_processing': celery_status == 'online',
            'supported_formats': list(SUPPORTED_FORMATS.keys())
        }

        return jsonify(create_success_response(
            message='System operational',
            data=status_data
        ))
    except Exception as e:
        logger.error(f"Status check error: {e}")
        return jsonify(*create_error_response('Status check failed', status_code=500))


@main.route('/status')
def status():
    """Public status endpoint"""
    return jsonify({
        'status': 'online',
        'message': 'Flask app running on AWS Lambda',
        'services': {
            's3': current_app.config.get('USE_S3_STORAGE', False),
            'dynamodb': current_app.config.get('USE_DYNAMODB', False),
            'enhanced_processing': True
        },
        'supported_formats': list(SUPPORTED_FORMATS.keys())
    })
