from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, make_response, current_app
from app.jwt_auth import jwt_required, authenticate_user, create_login_response, get_current_user
import os

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


@main.route('/upload', methods=['GET', 'POST'])
@jwt_required
def upload():
    """File upload page"""
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
                # Use S3 storage if available
                if current_app.config.get('USE_S3_STORAGE'):
                    from app.storage import upload_to_s3
                    result = upload_to_s3(
                        file, f"user-{request.current_user['user_id']}")

                    if result['success']:
                        flash('File uploaded successfully!')

                        # Save metadata to DynamoDB if available
                        if current_app.config.get('USE_DYNAMODB'):
                            from app.dynamodb_manager import save_file_metadata
                            file.seek(0)  # Reset file pointer to read size
                            metadata = {
                                'user_id': request.current_user['user_id'],
                                'filename': result['filename'],
                                'original_filename': file.filename,
                                'file_size': len(file.read()),
                                'file_type': file.content_type,
                                'storage_type': 's3',
                                'file_path': result['key'],
                                's3_url': result['url']
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

    # GET request - show upload form
    return render_template('upload.html', user=request.current_user)


@main.route('/files')
@jwt_required
def files():
    """List user's files"""
    user_files = []

    try:
        if current_app.config.get('USE_DYNAMODB'):
            from app.dynamodb_manager import get_user_files
            user_files = get_user_files(request.current_user['user_id'])
    except Exception as e:
        flash(f'Error loading files: {str(e)}')

    return render_template('my_files.html', files=user_files, user=request.current_user)


@main.route('/api/upload', methods=['POST'])
@jwt_required
def api_upload():
    """API endpoint for file upload"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        if current_app.config.get('USE_S3_STORAGE'):
            from app.storage import upload_to_s3
            result = upload_to_s3(
                file, f"user-{request.current_user['user_id']}")

            if result['success']:
                # Save metadata to DynamoDB
                if current_app.config.get('USE_DYNAMODB'):
                    from app.dynamodb_manager import save_file_metadata
                    file.seek(0)  # Reset file pointer
                    metadata = {
                        'user_id': request.current_user['user_id'],
                        'filename': result['filename'],
                        'original_filename': file.filename,
                        'file_size': len(file.read()),
                        'file_type': file.content_type,
                        'storage_type': 's3',
                        'file_path': result['key'],
                        's3_url': result['url']
                    }
                    metadata_result = save_file_metadata(metadata)
                    return jsonify({
                        'success': True,
                        'file_id': metadata_result.get('file_id'),
                        'filename': result['filename'],
                        's3_url': result['url']
                    })

                return jsonify(result)
            else:
                return jsonify(result), 500
        else:
            return jsonify({'error': 'S3 storage not configured'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@main.route('/api/files')
@jwt_required
def api_files():
    """API endpoint to list user's files"""
    try:
        if current_app.config.get('USE_DYNAMODB'):
            from app.dynamodb_manager import get_user_files
            user_files = get_user_files(request.current_user['user_id'])
            return jsonify({'files': user_files})
        else:
            return jsonify({'files': []})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
