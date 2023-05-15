
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
import os
import subprocess


app = Flask(__name__, template_folder='templates', static_folder='static')

tmp_upload_dir = './uploads'

app.config['UPLOAD_FOLDER'] = tmp_upload_dir
app.config['MAX_CONTENT_PATH'] = 1024 * 1024 * 3


# allow all file types
app.config['UPLOAD_EXTENSIONS'] = ['*']



@app.route('/index', methods=['GET'])
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/css/tailwind.css')
def tailwind():
    return app.send_static_file('css/tailwind.css')


# Process uploaded file and return result


@app.route('/process', methods=['POST'])
def process():
    # Get the uploaded file
    file_upload = request.files['file']

    filename = secure_filename(file_upload.filename.replace(" ", "_"))
    filepath = os.path.abspath(os.path.join(tmp_upload_dir, filename))
    file_upload.save(filepath)
    print("File saved to", filepath)
    # Process the uploaded file and return the result
    return process_uploaded_file(filepath)

# Process the uploaded file


def secure_delete(filepath):
    subprocess.run(['shred', '-uzf', filepath])


def process_uploaded_file(filepath):
    # Perform the necessary operations on the file
    # and return the result
    p = subprocess.Popen(['/usr/bin/python3', 'ssh-keyfinder.py', filepath],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='../')
    _, err = p.communicate()
    output = err.decode('utf-8')
    tmp_key = ""
    private_keys = []
    building = False
    for line in output.splitlines():
        if line.startswith('-----END OPENSSH PRIVATE KEY-----'):
            tmp_key += line + "\n"
            building = False
            private_keys.append(tmp_key)
            tmp_key = ""
        elif line.startswith('-----BEGIN OPENSSH PRIVATE KEY-----'):
            tmp_key += line + "\n"
            building = True
        elif building:
            tmp_key += line + "\n"

    if len(private_keys) == 0:
        private_keys.append("No private keys found in file")
    secure_delete(filepath)

    return render_template('keyview.html', openssh_privatekeys=private_keys)


if __name__ == "__main__":
    os.makedirs(tmp_upload_dir, exist_ok=True)
    app.run(host='0.0.0.0', port=3000, debug=True)
