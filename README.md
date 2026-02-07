# SecureDrive - Secure File Sharing Application

A secure file sharing application that uses AES-256 encryption and Blake3 hashing to protect files shared through Google Drive.

## Features

- 🔐 **AES-256 Encryption**: Military-grade encryption for all uploaded files
- 🔒 **Blake3 Hashing**: Fast and secure integrity verification
- 👥 **User Authentication**: Secure registration and login system
- 📤 **File Upload**: Encrypt and upload files with automatic hashing
- 🔑 **Key Management**: Secure encryption key sharing between users
- 📥 **File Download**: Download and verify file integrity
- ☁️ **Google Drive Integration**: Seamless cloud storage integration
- 🎨 **Modern UI**: Beautiful, responsive interface

## Technology Stack

- **Backend**: Python 3.x, Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **Encryption**: AES-256 (via Fernet)
- **Hashing**: Blake3
- **Database**: SQLite (SQLAlchemy)
- **Cloud Storage**: Google Drive API

## Installation

1. **Clone the repository**:
   ```bash
   cd secure
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up Google Drive API** (Optional):
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project
   - Enable Google Drive API
   - Create OAuth 2.0 credentials
   - Download credentials as `client_secret.json` and place in project root

4. **Run the application**:
   ```bash
   python app.py
   ```

5. **Access the application**:
   - Open your browser and navigate to `http://localhost:5000`

## Usage

### 1. Registration
- Navigate to the Register page
- Create an account with username, email, and password

### 2. Login
- Sign in with your credentials

### 3. Upload File
- Go to Dashboard → Upload File tab
- Select or drag & drop files
- **IMPORTANT**: Save the encryption key provided after upload
- Files are automatically encrypted and hashed

### 4. Share File
- Go to Dashboard → Share File tab
- Select the file you want to share
- Enter the recipient's username
- Provide the encryption key (from upload)
- Click Share

### 5. Download & Verify
- Go to Dashboard → Download & Verify tab
- Select the file
- Enter the encryption key
- Click "Verify Integrity" to check file integrity
- Click "Download File" to download and decrypt

## Security Features

- **AES-256 Encryption**: All files are encrypted using AES-256 before storage
- **Blake3 Hashing**: Files are hashed for integrity verification
- **Password Hashing**: User passwords are hashed using Werkzeug's secure hashing
- **Key Management**: Encryption keys are securely shared between users
- **Access Control**: Only file owners and authorized users can access files

## Project Structure

```
secure/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/            # HTML templates
│   ├── base.html
│   ├── home.html
│   ├── register.html
│   ├── login.html
│   └── dashboard.html
├── static/               # Static files
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── main.js
├── uploads/              # Upload directory (created automatically)
└── secure_drive.db       # SQLite database (created automatically)
```

## Important Notes

- **Encryption Keys**: Always save encryption keys when uploading files. Without the key, files cannot be decrypted.
- **Google Drive**: Google Drive integration is optional. Files are stored locally if Google Drive credentials are not configured.
- **Production**: Change the `SECRET_KEY` in `app.py` before deploying to production.
- **File Size**: Maximum file size is set to 100MB (configurable in `app.py`).

## Development

To run in development mode:
```bash
export FLASK_ENV=development
python app.py
```

## License

This project is for educational purposes.

## Contributing

Feel free to submit issues and enhancement requests!

