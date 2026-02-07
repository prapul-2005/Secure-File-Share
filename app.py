from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
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
import blake3
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_drive.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Google Drive OAuth settings
SCOPES = ['https://www.googleapis.com/auth/drive.file']
CLIENT_SECRETS_FILE = 'client_secret.json'
REDIRECT_URI = 'http://localhost:5000/callback'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Google Drive credentials
    drive_credentials = db.Column(db.Text, nullable=True)
    
    # Relationships
    uploaded_files = db.relationship('File', backref='owner', lazy=True, foreign_keys='File.owner_id')
    shared_files = db.relationship('FileShare', backref='shared_with_user', lazy=True, foreign_keys='FileShare.shared_with_id')

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(128), nullable=True)  # Blake3 hash (nullable for Encrypt-only mode)
    encrypted_data = db.Column(db.Text, nullable=True)  # Base64 encoded encrypted data (nullable for Hash-only mode)
    file_data = db.Column(db.Text, nullable=True)  # Base64 encoded unencrypted data (for Hash-only mode)
    security_mode = db.Column(db.String(20), nullable=False, default='hash_encrypt')  # 'hash', 'encrypt', 'hash_encrypt'
    file_size = db.Column(db.Integer, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    drive_file_id = db.Column(db.String(255), nullable=True)  # Google Drive file ID

class FileShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    shared_with_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encryption_key = db.Column(db.Text, nullable=False)  # Encrypted key for sharing
    shared_date = db.Column(db.DateTime, default=datetime.utcnow)
    file = db.relationship('File', backref='shares')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Encryption Utilities
def generate_key_from_password(password: str, salt: bytes = None) -> bytes:
    """Generate AES key from password using PBKDF2"""
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
    """Encrypt file data using AES (Fernet)"""
    f = Fernet(key)
    return f.encrypt(data)

def decrypt_file(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt file data using AES (Fernet)"""
    f = Fernet(key)
    return f.decrypt(encrypted_data)

def hash_file(data: bytes) -> str:
    """Generate Blake3 hash of file"""
    hasher = blake3.blake3(data)
    return hasher.hexdigest()

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already exists'}), 400
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registration successful'})
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return jsonify({'success': True, 'message': 'Login successful', 'redirect': url_for('dashboard')})
        else:
            return jsonify({'success': False, 'message': 'Invalid username or password'}), 401
    
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
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    # Get security mode from form data (default to 'hash_encrypt')
    security_mode = request.form.get('security_mode', 'hash_encrypt')
    if security_mode not in ['hash', 'encrypt', 'hash_encrypt']:
        return jsonify({'success': False, 'message': 'Invalid security mode'}), 400
    
    try:
        # Read file data
        file_data = file.read()
        file_size = len(file_data)
        
        file_hash = None
        encrypted_data = None
        file_data_b64 = None
        encryption_key = None
        key_b64 = None
        
        # Process based on security mode
        if security_mode == 'hash':
            # Hash Mode: Only generate hash, store file unencrypted
            file_hash = hash_file(file_data)
            file_data_b64 = base64.b64encode(file_data).decode('utf-8')
            
        elif security_mode == 'encrypt':
            # Encrypt Mode: Only encrypt, no hash
            encryption_key, salt = generate_key_from_password(current_user.username + str(current_user.id))
            encrypted_data_bytes = encrypt_file(file_data, encryption_key)
            encrypted_data = base64.b64encode(encrypted_data_bytes).decode('utf-8')
            key_b64 = base64.b64encode(encryption_key).decode('utf-8')
            
        elif security_mode == 'hash_encrypt':
            # Hash + Encrypt Mode: Both hash and encrypt (recommended)
            file_hash = hash_file(file_data)
            encryption_key, salt = generate_key_from_password(current_user.username + str(current_user.id))
            encrypted_data_bytes = encrypt_file(file_data, encryption_key)
            encrypted_data = base64.b64encode(encrypted_data_bytes).decode('utf-8')
            key_b64 = base64.b64encode(encryption_key).decode('utf-8')
        
        # Save to database
        db_file = File(
            filename=secure_filename(file.filename),
            original_filename=file.filename,
            file_hash=file_hash,
            encrypted_data=encrypted_data,
            file_data=file_data_b64,
            security_mode=security_mode,
            file_size=file_size,
            owner_id=current_user.id
        )
        db.session.add(db_file)
        db.session.commit()
        
        # Upload to Google Drive if credentials available
        # For Drive upload, use encrypted data if available, otherwise use original data
        drive_upload_data = encrypted_data_bytes if encrypted_data else file_data
        if current_user.drive_credentials:
            try:
                drive_file_id = upload_to_drive(drive_upload_data, file.filename, current_user)
                db_file.drive_file_id = drive_file_id
                db.session.commit()
            except Exception as e:
                print(f"Google Drive upload failed: {e}")
        
        # Prepare response
        response_data = {
            'success': True,
            'message': 'File uploaded successfully',
            'file_id': db_file.id,
            'security_mode': security_mode
        }
        
        # Include hash if available
        if file_hash:
            response_data['file_hash'] = file_hash
        
        # Include encryption key if available
        if key_b64:
            response_data['encryption_key'] = key_b64
        
        return jsonify(response_data)
    
    except Exception as e:
        return jsonify({'success': False, 'message': f'Upload failed: {str(e)}'}), 500

@app.route('/files')
@login_required
def list_files():
    # Get user's own files
    own_files = File.query.filter_by(owner_id=current_user.id).all()
    
    # Get shared files
    shared_file_ids = [share.file_id for share in FileShare.query.filter_by(shared_with_id=current_user.id).all()]
    shared_files = File.query.filter(File.id.in_(shared_file_ids)).all() if shared_file_ids else []
    
    files_data = []
    for f in own_files:
        files_data.append({
            'id': f.id,
            'filename': f.original_filename,
            'size': f.file_size,
            'upload_date': f.upload_date.isoformat(),
            'type': 'own',
            'security_mode': f.security_mode or 'hash_encrypt'
        })
    
    for f in shared_files:
        share = FileShare.query.filter_by(file_id=f.id, shared_with_id=current_user.id).first()
        files_data.append({
            'id': f.id,
            'filename': f.original_filename,
            'size': f.file_size,
            'upload_date': f.upload_date.isoformat(),
            'type': 'shared',
            'shared_date': share.shared_date.isoformat() if share else None,
            'security_mode': f.security_mode or 'hash_encrypt'
        })
    
    return jsonify({'success': True, 'files': files_data})

@app.route('/share', methods=['POST'])
@login_required
def share_file():
    data = request.get_json()
    file_id = data.get('file_id')
    shared_with_username = data.get('shared_with_username')
    encryption_key = data.get('encryption_key')
    
    file = File.query.filter_by(id=file_id, owner_id=current_user.id).first()
    if not file:
        return jsonify({'success': False, 'message': 'File not found'}), 404
    
    shared_with_user = User.query.filter_by(username=shared_with_username).first()
    if not shared_with_user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # Check if already shared
    existing_share = FileShare.query.filter_by(file_id=file_id, shared_with_id=shared_with_user.id).first()
    if existing_share:
        return jsonify({'success': False, 'message': 'File already shared with this user'}), 400
    
    # For encrypt and hash_encrypt modes, encryption key is required
    if file.security_mode in ['encrypt', 'hash_encrypt']:
        if not encryption_key:
            return jsonify({'success': False, 'message': 'Encryption key is required for sharing encrypted files'}), 400
    
    # Create share record
    # For hash-only mode, store empty string or placeholder (no key needed)
    share = FileShare(
        file_id=file_id,
        shared_with_id=shared_with_user.id,
        encryption_key=encryption_key or ''  # In production, encrypt this key
    )
    db.session.add(share)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'File shared successfully'})

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    # Check if user owns the file or has access
    file = File.query.get_or_404(file_id)
    
    is_owner = file.owner_id == current_user.id
    share = FileShare.query.filter_by(file_id=file_id, shared_with_id=current_user.id).first()
    
    if not is_owner and not share:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        file_data = None
        
        if file.security_mode == 'hash':
            # Hash Mode: Return unencrypted file (no key needed)
            if not file.file_data:
                return jsonify({'success': False, 'message': 'File data not found'}), 404
            file_data = base64.b64decode(file.file_data)
            
        elif file.security_mode == 'encrypt':
            # Encrypt Mode: Decrypt file and verify integrity (size check)
            if not file.encrypted_data:
                return jsonify({'success': False, 'message': 'Encrypted data not found'}), 404
            
            # Get encryption key - ALWAYS use the key provided by the user
            # For shared files, user must provide the key (stored key is just for reference)
            key_b64 = request.args.get('key')
            if not key_b64:
                return jsonify({'success': False, 'message': 'Encryption key required'}), 400
            try:
                encryption_key = base64.b64decode(key_b64)
            except Exception as e:
                return jsonify({'success': False, 'message': 'Invalid encryption key format'}), 400
            
            try:
                encrypted_data = base64.b64decode(file.encrypted_data)
                file_data = decrypt_file(encrypted_data, encryption_key)
            except InvalidToken:
                return jsonify({
                    'success': False, 
                    'message': 'Invalid encryption key. Please provide the correct key used to encrypt this file.'
                }), 400
            except Exception as e:
                return jsonify({
                    'success': False, 
                    'message': f'Decryption failed: {str(e)}. File may be corrupted or key is incorrect.'
                }), 400
            
            # Verify file size matches (integrity check)
            if len(file_data) != file.file_size:
                return jsonify({
                    'success': False, 
                    'message': f'File integrity verification failed. Expected size: {file.file_size} bytes, Got: {len(file_data)} bytes. File may have been tampered with.'
                }), 400
            
        elif file.security_mode == 'hash_encrypt':
            # Hash + Encrypt Mode: Decrypt and verify hash
            if not file.encrypted_data or not file.file_hash:
                return jsonify({'success': False, 'message': 'File data or hash not found'}), 404
            
            # Get encryption key - ALWAYS use the key provided by the user
            # For shared files, user must provide the key (stored key is just for reference)
            key_b64 = request.args.get('key')
            if not key_b64:
                return jsonify({'success': False, 'message': 'Encryption key required'}), 400
            try:
                encryption_key = base64.b64decode(key_b64)
            except Exception as e:
                return jsonify({'success': False, 'message': 'Invalid encryption key format'}), 400
            
            try:
                # Decrypt file
                encrypted_data = base64.b64decode(file.encrypted_data)
                file_data = decrypt_file(encrypted_data, encryption_key)
            except InvalidToken:
                return jsonify({
                    'success': False, 
                    'message': 'Invalid encryption key. Please provide the correct key used to encrypt this file.'
                }), 400
            except Exception as e:
                return jsonify({
                    'success': False, 
                    'message': f'Decryption failed: {str(e)}. File may be corrupted or key is incorrect.'
                }), 400
            
            # Verify hash
            computed_hash = hash_file(file_data)
            if computed_hash != file.file_hash:
                return jsonify({'success': False, 'message': 'File integrity verification failed. File may have been tampered with.'}), 400
        
        # Return file
        return send_file(
            io.BytesIO(file_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=file.original_filename
        )
    
    except Exception as e:
        return jsonify({'success': False, 'message': f'Download failed: {str(e)}'}), 500

@app.route('/verify/<int:file_id>', methods=['POST'])
@login_required
def verify_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check access
    is_owner = file.owner_id == current_user.id
    share = FileShare.query.filter_by(file_id=file_id, shared_with_id=current_user.id).first()
    
    if not is_owner and not share:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        if file.security_mode == 'hash':
            # Hash Mode: Compare stored hash with current file data
            if not file.file_hash or not file.file_data:
                return jsonify({'success': False, 'message': 'Hash or file data not found'}), 404
            
            file_data = base64.b64decode(file.file_data)
            computed_hash = hash_file(file_data)
            is_valid = computed_hash == file.file_hash
            
            return jsonify({
                'success': True,
                'is_valid': is_valid,
                'stored_hash': file.file_hash,
                'computed_hash': computed_hash,
                'message': 'File integrity verified' if is_valid else 'File integrity check failed. File may have been tampered with.'
            })
            
        elif file.security_mode == 'encrypt':
            # Encrypt Mode: Verify decryption integrity and file size
            data = request.get_json()
            key_b64 = data.get('key')
            
            if not key_b64:
                return jsonify({'success': False, 'message': 'Encryption key required'}), 400
            
            if not file.encrypted_data:
                return jsonify({'success': False, 'message': 'Encrypted data not found'}), 404
            
            # Get encryption key - ALWAYS use the key provided by the user for verification
            # This ensures verification actually checks the key the user provides
            try:
                encryption_key = base64.b64decode(key_b64)
            except Exception as e:
                return jsonify({'success': False, 'message': 'Invalid encryption key format'}), 400
            
            try:
                # Decrypt file
                encrypted_data = base64.b64decode(file.encrypted_data)
                decrypted_data = decrypt_file(encrypted_data, encryption_key)
                
                # Verify file size matches
                decrypted_size = len(decrypted_data)
                expected_size = file.file_size
                size_match = decrypted_size == expected_size
                
                # If decryption succeeded and size matches, integrity is verified
                is_valid = size_match
                
                return jsonify({
                    'success': True,
                    'is_valid': is_valid,
                    'expected_size': expected_size,
                    'decrypted_size': decrypted_size,
                    'message': 'File integrity verified (decryption successful and size matches)' if is_valid else f'File integrity check failed. Expected size: {expected_size} bytes, Got: {decrypted_size} bytes. File may have been tampered with.'
                })
            except InvalidToken:
                # Wrong encryption key - Fernet raises InvalidToken for incorrect keys
                return jsonify({
                    'success': False,
                    'is_valid': False,
                    'message': 'Invalid encryption key. Please provide the correct key used to encrypt this file.'
                }), 400
            except Exception as decrypt_error:
                # Other decryption errors (corrupted data, etc.)
                return jsonify({
                    'success': False,
                    'is_valid': False,
                    'message': f'File integrity check failed. Decryption error: {str(decrypt_error)}. File may have been tampered with or corrupted.'
                }), 400
            
        elif file.security_mode == 'hash_encrypt':
            # Hash + Encrypt Mode: Decrypt and verify hash
            data = request.get_json()
            key_b64 = data.get('key')
            
            if not key_b64:
                return jsonify({'success': False, 'message': 'Encryption key required'}), 400
            
            if not file.file_hash or not file.encrypted_data:
                return jsonify({'success': False, 'message': 'Hash or encrypted data not found'}), 404
            
            # Get encryption key - ALWAYS use the key provided by the user for verification
            # This ensures verification actually checks the key the user provides
            try:
                encryption_key = base64.b64decode(key_b64)
            except Exception as e:
                return jsonify({'success': False, 'message': 'Invalid encryption key format'}), 400
            
            try:
                encrypted_data = base64.b64decode(file.encrypted_data)
                decrypted_data = decrypt_file(encrypted_data, encryption_key)
            except InvalidToken:
                # Wrong encryption key - Fernet raises InvalidToken for incorrect keys
                return jsonify({
                    'success': False,
                    'is_valid': False,
                    'message': 'Invalid encryption key. Please provide the correct key used to encrypt this file.'
                }), 400
            except Exception as e:
                return jsonify({
                    'success': False,
                    'is_valid': False,
                    'message': f'Decryption failed: {str(e)}. File may be corrupted or key is incorrect.'
                }), 400
            
            # Verify hash - if hash doesn't match, the key was wrong or file was tampered with
            computed_hash = hash_file(decrypted_data)
            is_valid = computed_hash == file.file_hash
            
            # If hash doesn't match, treat as wrong key or tampered file
            if not is_valid:
                return jsonify({
                    'success': False,
                    'is_valid': False,
                    'stored_hash': file.file_hash,
                    'computed_hash': computed_hash,
                    'message': 'File integrity verification failed. The encryption key may be incorrect or the file has been tampered with.'
                }), 400
            
            # Only return success if hash matches
            return jsonify({
                'success': True,
                'is_valid': True,
                'stored_hash': file.file_hash,
                'computed_hash': computed_hash,
                'message': 'File integrity verified'
            })
        
        else:
            return jsonify({'success': False, 'message': 'Unknown security mode'}), 400
    
    except Exception as e:
        return jsonify({'success': False, 'message': f'Verification failed: {str(e)}'}), 500

# Google Drive Integration
def upload_to_drive(file_data, filename, user):
    """Upload encrypted file to Google Drive"""
    creds_data = json.loads(user.drive_credentials)
    creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
    
    service = build('drive', 'v3', credentials=creds)
    
    file_metadata = {'name': f'encrypted_{filename}'}
    media = MediaIoBaseUpload(io.BytesIO(file_data), mimetype='application/octet-stream', resumable=True)
    
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    return file.get('id')

@app.route('/auth/google')
@login_required
def google_auth():
    """Initiate Google OAuth flow"""
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
@login_required
def oauth_callback():
    """Handle Google OAuth callback"""
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
        state=session['state']
    )
    flow.fetch_token(authorization_response=request.url)
    
    credentials = flow.credentials
    current_user.drive_credentials = json.dumps({
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    })
    db.session.commit()
    
    return redirect(url_for('dashboard'))

def migrate_database():
    """Migrate database schema to add new columns if they don't exist"""
    import sqlite3
    import os
    
    # Extract database path from SQLAlchemy URI
    db_uri = app.config['SQLALCHEMY_DATABASE_URI']
    if db_uri.startswith('sqlite:///'):
        db_path = db_uri.replace('sqlite:///', '')
    elif db_uri.startswith('sqlite://'):
        db_path = db_uri.replace('sqlite://', '')
    else:
        print(f"Unknown database URI format: {db_uri}")
        return
    
    # Handle absolute paths on Windows
    if os.path.isabs(db_path):
        pass  # Already absolute
    else:
        # Make path relative to app root
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), db_path)
    
    print(f"Checking database at: {db_path}")
    
    if not os.path.exists(db_path):
        print(f"Database file not found at {db_path}, will be created with new schema.")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='file'")
        table_exists = cursor.fetchone()
        
        if not table_exists:
            print("File table does not exist. It will be created with the new schema.")
            conn.close()
            return
        
        # Get table info
        cursor.execute("PRAGMA table_info(file)")
        columns = [column[1] for column in cursor.fetchall()]
        print(f"Existing columns in file table: {columns}")
        
        migrations_applied = False
        
        # Add file_data column if it doesn't exist
        if 'file_data' not in columns:
            print("Adding file_data column to file table...")
            try:
                cursor.execute("ALTER TABLE file ADD COLUMN file_data TEXT")
                conn.commit()
                migrations_applied = True
                print("✓ file_data column added successfully")
            except sqlite3.OperationalError as e:
                print(f"Error adding file_data column: {e}")
        
        # Add security_mode column if it doesn't exist
        if 'security_mode' not in columns:
            print("Adding security_mode column to file table...")
            try:
                cursor.execute("ALTER TABLE file ADD COLUMN security_mode VARCHAR(20) DEFAULT 'hash_encrypt'")
                conn.commit()
                migrations_applied = True
                print("✓ security_mode column added successfully")
            except sqlite3.OperationalError as e:
                print(f"Error adding security_mode column: {e}")
        
        # Update existing rows to have default security_mode if it's NULL
        cursor.execute("PRAGMA table_info(file)")
        updated_columns = [column[1] for column in cursor.fetchall()]
        if 'security_mode' in updated_columns:
            cursor.execute("UPDATE file SET security_mode = 'hash_encrypt' WHERE security_mode IS NULL")
            conn.commit()
            if cursor.rowcount > 0:
                print(f"✓ Updated {cursor.rowcount} existing records with default security_mode")
        
        conn.close()
        
        if migrations_applied:
            print("=" * 50)
            print("Database migration completed successfully!")
            print("=" * 50)
        else:
            print("Database schema is up to date.")
            
    except sqlite3.OperationalError as e:
        print("=" * 50)
        print(f"Migration error: {e}")
        print("=" * 50)
        print("\nTrying alternative approach: recreating database...")
        try:
            conn.close()
        except:
            pass
        # As a last resort, recreate the database
        try:
            with app.app_context():
                db.drop_all()
                db.create_all()
                print("Database recreated successfully with new schema!")
        except Exception as recreate_error:
            print(f"Failed to recreate database: {recreate_error}")
            print("\nPlease manually delete the database file and restart the application.")
    except Exception as e:
        print("=" * 50)
        print(f"Unexpected migration error: {e}")
        print("=" * 50)
        import traceback
        traceback.print_exc()

@app.route('/migrate', methods=['GET'])
def manual_migrate():
    """Manual migration route for troubleshooting"""
    try:
        migrate_database()
        return jsonify({'success': True, 'message': 'Migration completed. Check console for details.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Migration failed: {str(e)}'}), 500

if __name__ == '__main__':
    print("=" * 60)
    print("Starting SecureDrive Application")
    print("=" * 60)
    with app.app_context():
        print("\n1. Creating database tables...")
        db.create_all()
        print("2. Running database migration...")
        migrate_database()
        print("\n3. Application ready!")
    print("=" * 60)
    print("\nStarting Flask server...\n")
    app.run(debug=True)

