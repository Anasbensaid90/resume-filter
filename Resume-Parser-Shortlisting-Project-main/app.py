#importing libraries
from extract_txt import read_files
from txt_processing import preprocess
from txt_to_features import txt_features, feats_reduce
from extract_entities import get_number, get_email, rm_email, rm_number, get_name, get_skills
from model import simil
import pandas as pd
import json
import os
import uuid
from flask import Flask, flash, request, redirect, url_for, render_template, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash


# used directories for data, downloading and uploading files
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files/resumes/')
DOWNLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files/outputs/')
DATA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Data/')

# Make directory if UPLOAD_FOLDER does not exist
if not os.path.isdir(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)

# Make directory if DOWNLOAD_FOLDER does not exist
if not os.path.isdir(DOWNLOAD_FOLDER):
    os.mkdir(DOWNLOAD_FOLDER)

# Flask app config
app = Flask(__name__, instance_relative_config=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
app.config['DATA_FOLDER'] = DATA_FOLDER
app.config['SECRET_KEY'] = 'nani?!'
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(app.instance_path, 'users.db')}"
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Allowed extension you can set your own
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'doc', 'docx'])

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/main', methods=['GET'])
def main_page():
    return redirect(url_for('home'))

@app.route('/', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    app.logger.info(request.files)
    upload_files = request.files.getlist('file')
    app.logger.info(upload_files)
    if not upload_files:
        flash('No selected file')
        return redirect(request.url)
    for file in upload_files:
        original_filename = file.filename
        if allowed_file(original_filename):
            extension = original_filename.rsplit('.', 1)[1].lower()
            filename = str(uuid.uuid1()) + '.' + extension
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            file_list = os.path.join(UPLOAD_FOLDER, 'files.json')
            files = _get_files()
            files[filename] = original_filename
            with open(file_list, 'w') as fh:
                json.dump(files, fh)

    flash('Upload succeeded')
    return redirect(url_for('upload_file'))

@app.route('/download/<code>', methods=['GET'])
def download(code):
    files = _get_files()
    if code in files:
        path = os.path.join(UPLOAD_FOLDER, code)
        if os.path.exists(path):
            return send_file(path)
    abort(404)

def _show_page():
    files = _get_files()
    return render_template('index.html', files=files)

def _get_files():
    file_list = os.path.join(UPLOAD_FOLDER, 'files.json')
    if os.path.exists(file_list):
        with open(file_list) as fh:
            return json.load(fh)
    return {}

@app.route('/process', methods=["POST"])
@login_required
def process():
    if request.method == 'POST':
        rawtext = request.form['rawtext']
        jdtxt = [rawtext]
        resumetxt = read_files(UPLOAD_FOLDER)
        p_resumetxt = preprocess(resumetxt)
        p_jdtxt = preprocess(jdtxt)

        feats = txt_features(p_resumetxt, p_jdtxt)
        feats_red = feats_reduce(feats)

        df = simil(feats_red, p_resumetxt, p_jdtxt)

        t = pd.DataFrame({'Original Resume': resumetxt})
        dt = pd.concat([df, t], axis=1)

        dt['Phone No.'] = dt['Original Resume'].apply(lambda x: get_number(x))
        dt['E-Mail ID'] = dt['Original Resume'].apply(lambda x: get_email(x))

        dt['Original'] = dt['Original Resume'].apply(lambda x: rm_number(x))
        dt['Original'] = dt['Original'].apply(lambda x: rm_email(x))
        dt['Candidate\'s Name'] = dt['Original'].apply(lambda x: get_name(x))

        skills = pd.read_csv(DATA_FOLDER + 'skill_red.csv')
        skills = skills.values.flatten().tolist()
        skill = [z.lower() for z in skills]

        dt['Skills'] = dt['Original'].apply(lambda x: get_skills(x, skill))
        dt = dt.drop(columns=['Original', 'Original Resume'])
        sorted_dt = dt.sort_values(by=['JD 1'], ascending=False)

        out_path = DOWNLOAD_FOLDER + "Candidates.csv"
        sorted_dt.to_csv(out_path, index=False)

        return send_file(out_path, as_attachment=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            role = 'user'  # Set default role to 'user'

            # Check if the username already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists', 'danger')
                app.logger.info(f"Registration failed: Username already exists for {username}")
                return redirect(url_for('register'))

            # Hash the password
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()

            app.logger.info(f"Successfully registered user: {username}, Role: {role}")
            flash('Registration Successful!', 'success')

            # Redirect to the login page
            return redirect(url_for('login'))

        except Exception as e:
            app.logger.error(f"Error during registration: {e}")
            flash(f'An error occurred during registration. Please try again. Error: {e}', 'danger')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied. Only admins can access this page.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_user':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'danger')
            else:
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                new_user = User(username=username, password=hashed_password, role=role)
                db.session.add(new_user)
                db.session.commit()
                flash('User added successfully', 'success')
        elif action == 'update_role':
            user_id = request.form['user_id']
            new_role = request.form['new_role']
            user = User.query.get(user_id)
            if user:
                user.role = new_role
                db.session.commit()
                flash(f"Role updated for {user.username} to {new_role}", 'success')
            else:
                flash('User not found', 'danger')
        elif action == 'delete_user':
            user_id = request.form['user_id']
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                flash(f"User {user.username} deleted", 'success')
            else:
                flash('User not found', 'danger')

    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return render_template('admin_dashboard.html')
    elif current_user.role == 'project_manager':
        return render_template('index.html')
    else:
        return render_template('user_dashboard.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        full_name = request.form['full-name']
        email = request.form['email']
        message = request.form['message']

        # Process the contact form data here (e.g., send an email or save to a database)
        flash('Message sent successfully!', 'success')
        return redirect(url_for('contact'))

    return render_template('contact.html')

@app.route('/password-reset', methods=['GET', 'POST'])
def password_reset():
    if request.method == 'POST':
        email = request.form['email']

        # Process the password reset request here (e.g., send a password reset link)
        flash('Password reset instructions have been sent to your email!', 'success')
        return redirect(url_for('password_reset'))

    return render_template('password-reset.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(port=8080, debug=True)
