from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
# Replace with a real secret in production
app.secret_key = 'your_secret_key_here'

db = SQLAlchemy(app)

# --- User model ---


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


@app.route('/')
def hello():
    return "Hello from Docker!"


@app.route('/test')
def test():
    return "Test from Docker!"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            # ✅ This line sets the login session
            session['user'] = user.username
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))  # or 'profile' if you prefer
        else:
            flash("Invalid credentials.", "error")
            return render_template('login.html')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists. Choose a different one.", "error")
            return render_template('register.html')

        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for('login'))

    return render_template('dashboard.html', username=session['user'])


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        flash("Please log in to access your profile.", "error")
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['user']).first()

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if new_username:
            user.username = new_username
            session['user'] = new_username  # update session value too

        if new_password:
            if new_password != confirm_password:
                flash("Passwords do not match.", "error")
                return render_template('profile.html', user=user)
            user.password = generate_password_hash(new_password)

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Line 33 is here ⬇
        if not User.query.filter_by(username='admin').first():
            hashed_pw = generate_password_hash('password')
            test_user = User(username='admin', password=hashed_pw)
            db.session.add(test_user)
            db.session.commit()

    app.run(host='0.0.0.0', port=5000)
