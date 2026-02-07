# Setup Guide

## Quick Start

1. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the Application**:
   ```bash
   python app.py
   ```

3. **Access the Application**:
   - Open browser: `http://localhost:5000`
   - Register a new account
   - Start uploading and sharing files!

## Google Drive Setup (Optional)

To enable Google Drive integration:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable "Google Drive API"
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client ID"
5. Choose "Web application"
6. Add authorized redirect URI: `http://localhost:5000/callback`
7. Download the JSON file and save as `client_secret.json` in the project root
8. In the dashboard, click "Connect Google Drive" to authorize

**Note**: Without Google Drive setup, files will still be encrypted and stored locally in the database.

## Security Notes

- **Encryption Keys**: Always save the encryption key when uploading files. Without it, files cannot be decrypted.
- **Secret Key**: Change `SECRET_KEY` in `app.py` before production deployment.
- **Database**: The SQLite database (`secure_drive.db`) is created automatically on first run.

## Troubleshooting

### Import Errors
- Make sure all dependencies are installed: `pip install -r requirements.txt`
- Use Python 3.8 or higher

### Google Drive Issues
- Verify `client_secret.json` is in the project root
- Check that redirect URI matches exactly: `http://localhost:5000/callback`
- Ensure Google Drive API is enabled in your Google Cloud project

### File Upload Issues
- Check file size (max 100MB by default)
- Ensure `uploads/` directory has write permissions
- Verify database is accessible

