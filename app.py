from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
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

class UploadForm(FlaskForm):
    file = FileField('File', validators=[
        DataRequired(),
        FileAllowed(ALLOWED_EXTENSIONS, 'Only specific file types allowed!')
    ])
    submit = SubmitField('Upload')

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File successfully uploaded!', 'success')
            return redirect(url_for('list_files', filename=filename))
    return render_template('upload.html', form=form)

@app.route('/uploads/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/files')
def list_files():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('files.html', files=files)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
