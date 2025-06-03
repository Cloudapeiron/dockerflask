# app/routes.py - CLEAN VERSION
import os
import uuid
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_file, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from app.models import db, User, UploadedFile

main = Blueprint('main', __name__)

# Configuration for file uploads
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif',
                      'doc', 'docx', 'xlsx', 'csv', 'zip', 'py', 'js', 'html', 'css', 'md'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_file_size(file):
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    return size


@main.route('/')
def home():
    return "Hello from Docker!"


@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            flash("Login successful!", "success")

            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
        else:
            flash("Invalid credentials.", "error")

    return render_template('login.html')


@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "error")
        elif User.query.filter_by(email=email).first():
            flash("Email already in use.", "error")
        else:
            hashed_pw = generate_password_hash(password)
            user = User(username=username, email=email, password=hashed_pw)
            db.session.add(user)
            db.session.commit()
            flash("Registration successful.", "success")
            return redirect(url_for('main.login'))

    return render_template('register.html')


@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)


@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if new_username:
            current_user.username = new_username
        if new_password:
            if new_password == confirm:
                current_user.password = generate_password_hash(new_password)
            else:
                flash("Passwords do not match.", "error")
                return render_template('profile.html', user=current_user)

        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for('main.profile'))

    return render_template('profile.html', user=current_user)


@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('main.login'))

# FILE UPLOAD ROUTES


@main.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash('File type not allowed', 'error')
            return redirect(request.url)

        file_size = get_file_size(file)
        if file_size > MAX_FILE_SIZE:
            flash('File too large (max 16MB)', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            file_extension = original_filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{uuid.uuid4().hex}.{file_extension}"

            upload_dir = os.path.join(
                current_app.root_path, 'uploads', str(current_user.id))
            os.makedirs(upload_dir, exist_ok=True)

            file_path = os.path.join(upload_dir, unique_filename)

            try:
                file.save(file_path)

                uploaded_file = UploadedFile(
                    filename=unique_filename,
                    original_filename=original_filename,
                    file_size=file_size,
                    file_type=file_extension,
                    user_id=current_user.id,
                    file_path=file_path
                )

                db.session.add(uploaded_file)
                db.session.commit()

                flash('File uploaded successfully!', 'success')
                return redirect(url_for('main.my_files'))

            except Exception as e:
                flash('Error uploading file', 'error')
                return redirect(request.url)

    return render_template('upload.html')


@main.route('/my-files')
@login_required
def my_files():
    files = UploadedFile.query.filter_by(user_id=current_user.id).order_by(
        UploadedFile.upload_date.desc()).all()

    total_files = len(files)
    total_size = sum(f.file_size for f in files)

    def format_total_size(size_bytes):
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        size = float(size_bytes)
        while size >= 1024 and i < len(size_names) - 1:
            size /= 1024.0
            i += 1
        return f"{size:.1f} {size_names[i]}"

    stats = {
        'total_files': total_files,
        'total_size': format_total_size(total_size),
        'recent_uploads': len([f for f in files[:5]])
    }

    return render_template('my_files.html', files=files, stats=stats)


@main.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = UploadedFile.query.get_or_404(file_id)

    if file_record.user_id != current_user.id:
        abort(403)

    if not os.path.exists(file_record.file_path):
        flash('File not found', 'error')
        return redirect(url_for('main.my_files'))

    return send_file(file_record.file_path,
                     as_attachment=True,
                     download_name=file_record.original_filename)


@main.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_record = UploadedFile.query.get_or_404(file_id)

    if file_record.user_id != current_user.id:
        abort(403)

    try:
        if os.path.exists(file_record.file_path):
            os.remove(file_record.file_path)

        db.session.delete(file_record)
        db.session.commit()

        flash('File deleted successfully', 'success')
    except Exception as e:
        flash('Error deleting file', 'error')

    return redirect(url_for('main.my_files'))
