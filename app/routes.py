from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, make_response, current_app
from app.jwt_auth import jwt_required, authenticate_user, create_login_response, get_current_user
from app.schemas import (
    UserRegistrationSchema, UserLoginSchema, PasswordChangeSchema,
    FileUploadResponseSchema, FileListResponseSchema, UserResponseSchema,
    FileValidationResponseSchema, TaskStatusSchema, BatchProcessSchema,
    validate_request_json, serialize_response, create_error_response, create_success_response
)
from marshmallow import Schema, fields
import logging

logger = logging.getLogger(__name__)
main = Blueprint('main', __name__)


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
            # For web requests, redirect to upload page
            if request.content_type != 'application/json':
                response = make_response(redirect(url_for('main.upload')))
                # Set JWT token cookie
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
                # For API requests, return JSON
                return create_login_response(user)
        else:
            if request.content_type != 'application/json':
                flash('Invalid username or password')
                return render_template('login.html')
            else:
                return jsonify({'error': 'Invalid credentials'}), 401

    # GET request - show login form
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

        # Validate passwords match
        if password != confirm_password:
            if request.content_type == 'application/json':
                return jsonify({'error': 'Passwords do not match'}), 400
            else:
                flash('Passwords do not match', 'error')
                return render_template('register.html')

        # Create user
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

    # GET request - show registration form
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
            # User wants to change password
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

    # GET request - show profile form
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
                # Validate file with file validator
                from app.file_validator import validate_uploaded_file
                validation_result = validate_uploaded_file(file)

                if not validation_result['valid']:
                    error_msg = 'File validation failed: ' + \
                        '; '.join(validation_result['errors'])
                    flash(error_msg, 'error')
                    return redirect(request.url)

                # Show warnings if any
                if validation_result['warnings']:
                    warning_msg = 'File warnings: ' + \
                        '; '.join(validation_result['warnings'])
                    flash(warning_msg, 'warning')

                # File is valid, proceed with upload
                if current_app.config.get('USE_S3_STORAGE'):
                    from app.storage import upload_to_s3
                    result = upload_to_s3(
                        file, f"user-{request.current_user['id']}")

                    if result['success']:
                        flash('File uploaded successfully!')

                        # Save metadata to DynamoDB with validation info
                        if current_app.config.get('USE_DYNAMODB'):
                            from app.dynamodb_manager import save_file_metadata
                            metadata = {
                                'user_id': request.current_user['id'],
                                'filename': result['filename'],
                                'original_filename': file.filename,
                                'file_size': validation_result['size'],
                                'file_type': validation_result['mime_type'],
                                'file_category': validation_result['category'],
                                'storage_type': 's3',
                                'file_path': result['key'],
                                's3_url': result['url'],
                                'validation_status': 'passed',
                                'validation_warnings': validation_result['warnings']
                            }
                            save_result = save_file_metadata(metadata)
                            if not save_result['success']:
                                flash(
                                    f'File uploaded but metadata save failed: {save_result["error"]}')
                    else:
                        flash(f'Upload failed: {result["error"]}')
                else:
                    flash('S3 storage not configured')

            except Exception as e:
                flash(f'Upload error: {str(e)}')

        return redirect(url_for('main.upload'))

    # GET request - show upload form with allowed file info
    from app.file_validator import get_allowed_file_info
    allowed_files = get_allowed_file_info()

    return render_template('upload.html',
                           user=request.current_user,
                           allowed_files=allowed_files)


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


# ===== ENHANCED API ROUTES WITH MARSHMALLOW =====

@main.route('/api/register', methods=['POST'])
@validate_request_json(UserRegistrationSchema)
def api_register():
    """API endpoint for user registration with marshmallow validation"""
    try:
        # request.validated_data contains clean, validated data
        validated_data = request.validated_data

        from app.jwt_auth import UserManager
        result = UserManager.create_user(
            validated_data['username'],
            validated_data['email'],
            validated_data['password']
        )

        if result['success']:
            # Serialize user data for response
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
            # Create login response with token
            login_response = create_login_response(user)
            if login_response['success']:
                # Serialize user data
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
    """API endpoint for file upload with marshmallow response formatting"""
    if 'file' not in request.files:
        return jsonify(*create_error_response('No file provided', status_code=400))

    file = request.files['file']
    if file.filename == '':
        return jsonify(*create_error_response('No file selected', status_code=400))

    try:
        # Validate file
        from app.file_validator import validate_uploaded_file
        validation_result = validate_uploaded_file(file)

        if not validation_result['valid']:
            return jsonify(*create_error_response(
                'File validation failed',
                validation_errors={'file': validation_result['errors']},
                status_code=400
            ))

        if current_app.config.get('USE_S3_STORAGE'):
            from app.storage import upload_to_s3
            result = upload_to_s3(file, f"user-{request.current_user['id']}")

            if result['success']:
                # Save metadata to DynamoDB with validation info
                if current_app.config.get('USE_DYNAMODB'):
                    from app.dynamodb_manager import save_file_metadata
                    metadata = {
                        'user_id': request.current_user['id'],
                        'filename': result['filename'],
                        'original_filename': file.filename,
                        'file_size': validation_result['size'],
                        'file_type': validation_result['mime_type'],
                        'file_category': validation_result['category'],
                        'storage_type': 's3',
                        'file_path': result['key'],
                        's3_url': result['url'],
                        'validation_status': 'passed',
                        'validation_warnings': validation_result['warnings']
                    }
                    metadata_result = save_file_metadata(metadata)

                    # Serialize response using marshmallow
                    response_data = {
                        'success': True,
                        'file_id': metadata_result.get('file_id'),
                        'filename': result['filename'],
                        's3_url': result['url'],
                        'file_info': {
                            'mime_type': validation_result['mime_type'],
                            'category': validation_result['category'],
                            'size': validation_result['size']
                        },
                        'validation_warnings': validation_result['warnings']
                    }

                    serialized_response = serialize_response(
                        response_data, FileUploadResponseSchema)
                    return jsonify(serialized_response), 201

                # Fallback if no DynamoDB
                response_data = {
                    'success': True,
                    'filename': result['filename'],
                    's3_url': result['url'],
                    'file_info': {
                        'mime_type': validation_result['mime_type'],
                        'category': validation_result['category'],
                        'size': validation_result['size']
                    },
                    'validation_warnings': validation_result['warnings']
                }
                serialized_response = serialize_response(
                    response_data, FileUploadResponseSchema)
                return jsonify(serialized_response), 201
            else:
                return jsonify(*create_error_response(f'Upload failed: {result["error"]}', status_code=500))
        else:
            return jsonify(*create_error_response('S3 storage not configured', status_code=500))

    except Exception as e:
        logger.error(f"Upload error: {e}")
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
        # Validate file
        from app.file_validator import validate_uploaded_file
        validation_result = validate_uploaded_file(file)

        if not validation_result['valid']:
            return jsonify(*create_error_response(
                'File validation failed',
                validation_errors={'file': validation_result['errors']},
                status_code=400
            ))

        if current_app.config.get('USE_S3_STORAGE'):
            from app.storage import upload_to_s3
            result = upload_to_s3(file, f"user-{request.current_user['id']}")

            if result['success']:
                # Save basic metadata to DynamoDB
                if current_app.config.get('USE_DYNAMODB'):
                    from app.dynamodb_manager import save_file_metadata
                    metadata = {
                        'user_id': request.current_user['id'],
                        'filename': result['filename'],
                        'original_filename': file.filename,
                        'file_size': validation_result['size'],
                        'file_type': validation_result['mime_type'],
                        'file_category': validation_result['category'],
                        'storage_type': 's3',
                        'file_path': result['key'],
                        's3_url': result['url'],
                        'validation_status': 'passed',
                        'validation_warnings': validation_result['warnings'],
                        'processing_status': 'queued'
                    }
                    metadata_result = save_file_metadata(metadata)
                    file_id = metadata_result.get('file_id')

                    # Queue background processing task
                    try:
                        from app.celery_tasks import process_uploaded_file, send_processing_complete_notification

                        # Start file processing in background
                        process_task = process_uploaded_file.delay(
                            file_id,
                            request.current_user['id'],
                            result['key'],
                            validation_result['mime_type']
                        )

                        # Queue notification task to run after processing
                        notification_task = send_processing_complete_notification.delay(
                            request.current_user['id'],
                            file_id,
                            file.filename
                        )

                        # Serialize response
                        response_data = {
                            'success': True,
                            'file_id': file_id,
                            'filename': result['filename'],
                            's3_url': result['url'],
                            'processing_task_id': process_task.id,
                            'notification_task_id': notification_task.id,
                            'status': 'uploaded_queued_for_processing',
                            'file_info': {
                                'mime_type': validation_result['mime_type'],
                                'category': validation_result['category'],
                                'size': validation_result['size']
                            },
                            'validation_warnings': validation_result['warnings']
                        }

                        serialized_response = serialize_response(
                            response_data, FileUploadResponseSchema)
                        # 202 Accepted
                        return jsonify(serialized_response), 202

                    except Exception as e:
                        logger.error(f"Failed to queue background task: {e}")
                        # File uploaded successfully, but background processing failed
                        response_data = {
                            'success': True,
                            'file_id': file_id,
                            'filename': result['filename'],
                            's3_url': result['url'],
                            'status': 'uploaded_processing_unavailable',
                            'warning': 'File uploaded but background processing is unavailable',
                            'file_info': {
                                'mime_type': validation_result['mime_type'],
                                'category': validation_result['category'],
                                'size': validation_result['size']
                            }
                        }
                        serialized_response = serialize_response(
                            response_data, FileUploadResponseSchema)
                        return jsonify(serialized_response), 201

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

        # Serialize response
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


@main.route('/api/task-status/<task_id>')
@jwt_required
def api_task_status(task_id):
    """Get the status of a background task"""
    try:
        from app.celery_tasks import get_task_status
        status = get_task_status(task_id)

        return jsonify(create_success_response(
            message='Task status retrieved',
            data=status
        ))

    except Exception as e:
        logger.error(f"Task status error: {e}")
        return jsonify(*create_error_response('Failed to get task status', status_code=500))


@main.route('/api/task-cancel/<task_id>', methods=['POST'])
@jwt_required
def api_cancel_task(task_id):
    """Cancel a background task"""
    try:
        from app.celery_tasks import cancel_task
        result = cancel_task(task_id)

        if result['success']:
            return jsonify(create_success_response(
                message=result['message']
            ))
        else:
            return jsonify(*create_error_response(result['error'], status_code=400))

    except Exception as e:
        logger.error(f"Task cancellation error: {e}")
        return jsonify(*create_error_response('Failed to cancel task', status_code=500))


@main.route('/api/batch-process', methods=['POST'])
@jwt_required
@validate_request_json(BatchProcessSchema)
def api_batch_process():
    """Process multiple files in batch"""
    try:
        file_ids = request.validated_data['file_ids']

        if len(file_ids) > 50:  # Limit batch size
            return jsonify(*create_error_response('Batch size cannot exceed 50 files', status_code=400))

        from app.celery_tasks import batch_process_files
        batch_task = batch_process_files.delay(file_ids)

        return jsonify(create_success_response(
            message=f'Batch processing started for {len(file_ids)} files',
            data={
                'batch_task_id': batch_task.id,
                'file_count': len(file_ids),
                'status': 'queued'
            }
        )), 202

    except Exception as e:
        logger.error(f"Batch processing error: {e}")
        return jsonify(*create_error_response('Batch processing failed', status_code=500))


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
        from app.file_validator import validate_uploaded_file
        validation_result = validate_uploaded_file(file)

        # Serialize response using marshmallow
        serialized_response = serialize_response(
            validation_result, FileValidationResponseSchema)
        return jsonify(serialized_response)

    except Exception as e:
        logger.error(f"File validation error: {e}")
        return jsonify(*create_error_response('File validation failed', status_code=500))


@main.route('/api/user/profile')
@jwt_required
def api_user_profile():
    """API endpoint to get current user profile"""
    try:
        # Serialize user data
        user_data = serialize_response(
            request.current_user, UserResponseSchema)
        return jsonify(create_success_response(
            message='Profile retrieved successfully',
            data={'user': user_data}
        ))
    except Exception as e:
        logger.error(f"Profile retrieval error: {e}")
        return jsonify(*create_error_response('Failed to retrieve profile', status_code=500))


@main.route('/api/admin/maintenance', methods=['POST'])
@jwt_required
def api_trigger_maintenance():
    """Trigger maintenance tasks (admin only)"""
    try:
        # In real app, check if user is admin
        # if not request.current_user.get('is_admin'):
        #     return jsonify(*create_error_response('Admin access required', status_code=403))

        from app.celery_tasks import daily_maintenance
        maintenance_task = daily_maintenance.delay()

        return jsonify(create_success_response(
            message='Maintenance tasks started',
            data={
                'maintenance_task_id': maintenance_task.id,
                'status': 'queued'
            }
        )), 202

    except Exception as e:
        logger.error(f"Maintenance trigger error: {e}")
        return jsonify(*create_error_response('Failed to start maintenance', status_code=500))


@main.route('/api/admin/cleanup', methods=['POST'])
@jwt_required
def api_trigger_cleanup():
    """Trigger file cleanup (admin only)"""
    try:
        days_old = request.json.get('days_old', 30) if request.is_json else 30

        from app.celery_tasks import cleanup_old_files
        cleanup_task = cleanup_old_files.delay(days_old)

        return jsonify(create_success_response(
            message=f'Cleanup started for files older than {days_old} days',
            data={
                'cleanup_task_id': cleanup_task.id,
                'days_old': days_old,
                'status': 'queued'
            }
        )), 202

    except Exception as e:
        logger.error(f"Cleanup trigger error: {e}")
        return jsonify(*create_error_response('Failed to start cleanup', status_code=500))


@main.route('/api/file-info')
def api_file_info():
    """API endpoint to get allowed file types and limits"""
    try:
        from app.file_validator import get_allowed_file_info
        file_info = get_allowed_file_info()
        return jsonify(create_success_response(
            message='File information retrieved successfully',
            data=file_info
        ))
    except Exception as e:
        logger.error(f"File info error: {e}")
        return jsonify(*create_error_response('Failed to retrieve file info', status_code=500))


@main.route('/api/status')
def api_status():
    """Enhanced status endpoint with celery information"""
    try:
        # Check if celery is working
        celery_status = 'unavailable'
        try:
            from app.celery_tasks import celery
            if celery:
                # Try to get celery stats
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
            'message': 'Flask uptake application running',
            'services': {
                's3': current_app.config.get('USE_S3_STORAGE', False),
                'dynamodb': current_app.config.get('USE_DYNAMODB', False),
                'file_validation': True,
                'authentication': True,
                'marshmallow_validation': True,
                'celery': celery_status,
                # If celery connects, redis is working
                'redis': celery_status in ['online', 'no_workers']
            },
            'version': '1.0.0',
            'environment': current_app.config.get('FLASK_ENV', 'unknown'),
            'background_processing': celery_status == 'online'
        }

        return jsonify(create_success_response(
            message='System operational',
            data=status_data
        ))
    except Exception as e:
        logger.error(f"Status check error: {e}")
        return jsonify(*create_error_response('Status check failed', status_code=500))


# Legacy status endpoint for backward compatibility
@main.route('/status')
def status():
    """Public status endpoint"""
    return jsonify({
        'status': 'online',
        'message': 'Flask app running on AWS Lambda',
        'services': {
            's3': current_app.config.get('USE_S3_STORAGE', False),
            'dynamodb': current_app.config.get('USE_DYNAMODB', False)
        }
    })
