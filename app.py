import bcrypt
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash, session
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import FileField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.file import FileAllowed
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', 'tar.gz', 'tar.bz2', 'tar'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

user_info = {
    "username": "test",
    # Password hashed using bcrypt for "test"
    "password_hash": bcrypt.hashpw("test".encode('utf-8'), bcrypt.gensalt())
}

class UploadForm(FlaskForm):
    file = FileField('File', validators=[
        DataRequired(),
        FileAllowed(ALLOWED_EXTENSIONS, 'Only specific file types allowed!')
    ])
    submit = SubmitField('Upload')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Decorator to check if the user is logged in
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__  # Needed for Flask internals
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File successfully uploaded!', 'success')
            return redirect(url_for('list_files'))
    return render_template('upload.html', form=form)

@app.route('/uploads/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/files')
@login_required
def list_files():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('files.html', files=files)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        return redirect(url_for('upload_file'))  # Redirect to the home page if already logged in

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data.encode('utf-8')
        
        # Verify the username
        if username == user_info['username']:
            # Verify the password
            if bcrypt.checkpw(password, user_info['password_hash']):
                session['logged_in'] = True  # Set session flag
                flash('Login successful for user: {}'.format(username), 'success')
                return redirect(url_for('upload_file'))  # Redirect to the home page
            else:
                flash('Invalid password', 'danger')
        else:
            flash('Invalid username', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)  # Remove session flag
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
