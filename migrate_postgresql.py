#!/usr/bin/env python3
"""
PostgreSQL Database migration script to add new fields to ServerConfig table.
This script adds base_directory and use_account_directories fields to support
the new account-specific directory structure for JSON file retrieval.
"""

import os
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the database models
from database import db, ServerConfig

def create_app():
    """Create Flask app for migration"""
    app = Flask(__name__)
    
    # Load configuration
    from config import SQLALCHEMY_DATABASE_URI
    app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize database
    db.init_app(app)
    
    return app

def migrate_server_config_postgresql():
    """Add new fields to ServerConfig table for PostgreSQL"""
    app = create_app()
    
    with app.app_context():
        try:
            print("🔄 Starting PostgreSQL ServerConfig migration...")
            
            # Check if the new columns already exist
            from sqlalchemy import inspect, text
            inspector = inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('server_config')]
            
            print(f"📋 Current columns: {columns}")
            
            # Add base_directory column if it doesn't exist
            if 'base_directory' not in columns:
                print("➕ Adding base_directory column...")
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE server_config ADD COLUMN base_directory VARCHAR(500) DEFAULT '/home/brightmindscampus'"))
                    conn.commit()
                print("✅ base_directory column added")
            else:
                print("ℹ️  base_directory column already exists")
            
            # Add use_account_directories column if it doesn't exist
            if 'use_account_directories' not in columns:
                print("➕ Adding use_account_directories column...")
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE server_config ADD COLUMN use_account_directories BOOLEAN DEFAULT TRUE"))
                    conn.commit()
                print("✅ use_account_directories column added")
            else:
                print("ℹ️  use_account_directories column already exists")
            
            # Update existing records to have default values
            print("🔄 Updating existing records...")
            existing_configs = ServerConfig.query.all()
            for config in existing_configs:
                if not hasattr(config, 'base_directory') or config.base_directory is None:
                    config.base_directory = '/home/brightmindscampus'
                if not hasattr(config, 'use_account_directories') or config.use_account_directories is None:
                    config.use_account_directories = True
            
            db.session.commit()
            print(f"✅ Updated {len(existing_configs)} existing configurations")
            
            # Verify the migration
            print("🔍 Verifying migration...")
            # Refresh the inspector to get updated column information
            inspector = inspect(db.engine)
            updated_columns = [col['name'] for col in inspector.get_columns('server_config')]
            print(f"📋 Updated columns: {updated_columns}")
            
            # Also check using PostgreSQL-specific query
            with db.engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'server_config' 
                    ORDER BY ordinal_position
                """))
                pg_columns = [row[0] for row in result]
                print(f"📋 PostgreSQL columns: {pg_columns}")
            
            if 'base_directory' in updated_columns and 'use_account_directories' in updated_columns:
                print("✅ Migration completed successfully!")
                print("📝 New fields added:")
                print("   - base_directory: VARCHAR(500) DEFAULT '/home/brightmindscampus'")
                print("   - use_account_directories: BOOLEAN DEFAULT TRUE")
                print("\n🎯 The system now supports:")
                print("   - Account-specific directories: /home/brightmindscampus/{account}/*.json")
                print("   - Legacy single directory support")
                print("   - Configurable base directory path")
                return True
            elif 'base_directory' in pg_columns and 'use_account_directories' in pg_columns:
                print("✅ Migration completed successfully! (Verified via PostgreSQL)")
                print("📝 New fields added:")
                print("   - base_directory: VARCHAR(500) DEFAULT '/home/brightmindscampus'")
                print("   - use_account_directories: BOOLEAN DEFAULT TRUE")
                print("\n🎯 The system now supports:")
                print("   - Account-specific directories: /home/brightmindscampus/{account}/*.json")
                print("   - Legacy single directory support")
                print("   - Configurable base directory path")
                return True
            else:
                print("❌ Migration failed - new columns not found")
                return False
                
        except Exception as e:
            print(f"❌ Migration failed with error: {e}")
            db.session.rollback()
            return False

def rollback_migration_postgresql():
    """Rollback the migration (remove new columns) for PostgreSQL"""
    app = create_app()
    
    with app.app_context():
        try:
            print("🔄 Rolling back PostgreSQL ServerConfig migration...")
            
            from sqlalchemy import inspect, text
            inspector = inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('server_config')]
            
            # Remove base_directory column if it exists
            if 'base_directory' in columns:
                print("➖ Removing base_directory column...")
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE server_config DROP COLUMN base_directory"))
                    conn.commit()
                print("✅ base_directory column removed")
            
            # Remove use_account_directories column if it exists
            if 'use_account_directories' in columns:
                print("➖ Removing use_account_directories column...")
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE server_config DROP COLUMN use_account_directories"))
                    conn.commit()
                print("✅ use_account_directories column removed")
            
            print("✅ Rollback completed successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Rollback failed with error: {e}")
            db.session.rollback()
            return False

if __name__ == "__main__":
    print("🚀 PostgreSQL ServerConfig Database Migration Tool")
    print("=" * 50)
    
    if len(sys.argv) > 1 and sys.argv[1] == "--rollback":
        success = rollback_migration_postgresql()
    else:
        success = migrate_server_config_postgresql()
    
    if success:
        print("\n🎉 Operation completed successfully!")
        sys.exit(0)
    else:
        print("\n💥 Operation failed!")
        sys.exit(1)
