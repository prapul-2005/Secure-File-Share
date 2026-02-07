"""
Database Migration Script
Run this script to update your database schema with the new columns.
"""
import sqlite3
import os
import sys

# Get the database path from app config
try:
    # Try to import app to get the database path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from app import app
    
    with app.app_context():
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        if db_uri.startswith('sqlite:///'):
            DB_PATH = db_uri.replace('sqlite:///', '')
        elif db_uri.startswith('sqlite://'):
            DB_PATH = db_uri.replace('sqlite://', '')
        else:
            DB_PATH = 'secure_drive.db'
        
        # Handle relative paths
        if not os.path.isabs(DB_PATH):
            DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_PATH)
except:
    # Fallback to default
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secure_drive.db')

def migrate_database():
    """Migrate database schema to add new columns if they don't exist"""
    
    if not os.path.exists(DB_PATH):
        print(f"Database file '{DB_PATH}' not found.")
        print("The database will be created automatically when you run the app.")
        return
    
    print(f"Migrating database: {DB_PATH}")
    print("=" * 50)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='file'")
        table_exists = cursor.fetchone()
        
        if not table_exists:
            print("File table does not exist. Run the app to create it.")
            conn.close()
            return
        
        # Get table info
        cursor.execute("PRAGMA table_info(file)")
        columns = [column[1] for column in cursor.fetchall()]
        print(f"Existing columns: {', '.join(columns)}")
        print()
        
        migrations_applied = False
        
        # Add file_data column if it doesn't exist
        if 'file_data' not in columns:
            print("Adding file_data column...")
            try:
                cursor.execute("ALTER TABLE file ADD COLUMN file_data TEXT")
                conn.commit()
                migrations_applied = True
                print("✓ file_data column added successfully")
            except sqlite3.OperationalError as e:
                print(f"✗ Error adding file_data column: {e}")
        else:
            print("✓ file_data column already exists")
        
        # Add security_mode column if it doesn't exist
        if 'security_mode' not in columns:
            print("Adding security_mode column...")
            try:
                cursor.execute("ALTER TABLE file ADD COLUMN security_mode VARCHAR(20) DEFAULT 'hash_encrypt'")
                conn.commit()
                migrations_applied = True
                print("✓ security_mode column added successfully")
            except sqlite3.OperationalError as e:
                print(f"✗ Error adding security_mode column: {e}")
        else:
            print("✓ security_mode column already exists")
        
        # Update existing rows
        cursor.execute("PRAGMA table_info(file)")
        updated_columns = [column[1] for column in cursor.fetchall()]
        if 'security_mode' in updated_columns:
            cursor.execute("UPDATE file SET security_mode = 'hash_encrypt' WHERE security_mode IS NULL")
            conn.commit()
            if cursor.rowcount > 0:
                print(f"✓ Updated {cursor.rowcount} existing records with default security_mode")
        
        # Verify final schema
        cursor.execute("PRAGMA table_info(file)")
        final_columns = [column[1] for column in cursor.fetchall()]
        print()
        print("Final schema:")
        for col in final_columns:
            print(f"  - {col}")
        
        conn.close()
        
        print()
        print("=" * 50)
        if migrations_applied:
            print("Migration completed successfully!")
        else:
            print("Database schema is already up to date.")
        print("=" * 50)
            
    except Exception as e:
        print(f"Error during migration: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    migrate_database()
