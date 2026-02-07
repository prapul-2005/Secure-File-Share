from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import io

# =======================
# Hashing (BLAKE3 fallback)
# =======================
try:
    import blake3
    USE_BLAKE3 = True
except ImportError:
    import hashlib
    USE_BLAKE3 = False

# =======================
# Google APIs
# =======================
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

# =======================
# App Config
# =======================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_drive.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")
REDIRECT_URI = f"{BASE_URL}/callback"
SCOPES = ['https://www.googleapis.com/auth/drive.file']
CLIENT_SECRETS_FILE = 'client_secret.json'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# =======================
# Database Models
# =======================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    drive_credentials = db.Column(db.Text, nullable=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(128), nullable=True)
    encrypted_data = db.Column(db.Text, nullable=True)
    file_data = db.Column(db.Text, nullable=True)
    security_mode = db.Column(db.String(20), default='hash_encrypt')
    file_size = db.Column(db.Integer, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class FileShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    shared_with_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encryption_key = db.Column(db.Text, nullable=False)
    shared_date = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# =======================
# Crypto Utilities
# =======================
def generate_key_from_password(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file(data: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(data)

def decrypt_file(data: bytes, key: bytes) -> bytes:
    return Fernet(key).decrypt(data)

def hash_file(data: bytes) -> str:
    if USE_BLAKE3:
        return blake3.blake3(data).hexdigest()
    else:
        return hashlib.sha256(data).hexdigest()

# =======================
# Routes
# =======================
@app.route('/')
def home():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else render_template('home.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        user = User(
            username=data['username'],
            email=data['email'],
            password_hash=generate_password_hash(data['password'])
        )
        db.session.add(user)
        db.session.commit()
        return jsonify(success=True)
    return render_template('register.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        if user and check_password_hash(user.password_hash, data['password']):
            login_user(user)
            return jsonify(success=True, redirect=url_for('dashboard'))
        return jsonify(success=False), 401
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    file = request.files['file']
    mode = request.form.get('security_mode', 'hash_encrypt')
    data = file.read()

    file_hash = None
    encrypted_data = None
    key_b64 = None

    if mode in ['hash', 'hash_encrypt']:
        file_hash = hash_file(data)

    if mode in ['encrypt', 'hash_encrypt']:
        key, _ = generate_key_from_password(current_user.username)
        encrypted_data = base64.b64encode(encrypt_file(data, key)).decode()
        key_b64 = base64.b64encode(key).decode()

    db_file = File(
        filename=secure_filename(file.filename),
        original_filename=file.filename,
        file_hash=file_hash,
        encrypted_data=encrypted_data,
        file_data=base64.b64encode(data).decode() if mode == 'hash' else None,
        security_mode=mode,
        file_size=len(data),
        owner_id=current_user.id
    )
    db.session.add(db_file)
    db.session.commit()

    return jsonify(success=True, encryption_key=key_b64, file_hash=file_hash)

# =======================
# Google Drive
# =======================
@app.route('/auth/google')
@login_required
def google_auth():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, state = flow.authorization_url(access_type='offline')
    session['state'] = state
    return redirect(auth_url)

@app.route('/callback')
@login_required
def callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
        state=session['state']
    )
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    current_user.drive_credentials = json.dumps({
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    })
    db.session.commit()
    return redirect(url_for('dashboard'))

# =======================
# Main (Render-safe)
# =======================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    port = int(os.environ.get("PORT", 5000))
    print(f"Running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
