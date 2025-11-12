#!/usr/bin/env python3
"""
Database Schema Update Script
Updates the database to include new columns for UsedDomain model
"""

import os
import sys
from sqlalchemy import text

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def update_database_schema():
    """Update the database schema to include new columns"""
    try:
        from app import app
        from database import db
        
        with app.app_context():
            # Check if the user_count column exists
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'used_domain' 
                AND column_name = 'user_count'
            """))
            
            if result.fetchone():
                print("✅ user_count column already exists")
            else:
                print("➕ Adding user_count column...")
                db.session.execute(text("ALTER TABLE used_domain ADD COLUMN user_count INTEGER DEFAULT 0"))
            
            # Check if is_verified column exists
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'used_domain' 
                AND column_name = 'is_verified'
            """))
            
            if result.fetchone():
                print("✅ is_verified column already exists")
            else:
                print("➕ Adding is_verified column...")
                db.session.execute(text("ALTER TABLE used_domain ADD COLUMN is_verified BOOLEAN DEFAULT FALSE"))
            
            # Check if created_at column exists
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'used_domain' 
                AND column_name = 'created_at'
            """))
            
            if result.fetchone():
                print("✅ created_at column already exists")
            else:
                print("➕ Adding created_at column...")
                db.session.execute(text("ALTER TABLE used_domain ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
            
            # Check if updated_at column exists
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'used_domain' 
                AND column_name = 'updated_at'
            """))
            
            if result.fetchone():
                print("✅ updated_at column already exists")
            else:
                print("➕ Adding updated_at column...")
                db.session.execute(text("ALTER TABLE used_domain ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
            
            # Commit the changes
            db.session.commit()
            print("✅ Database schema updated successfully!")
            
            # Verify the table structure
            result = db.session.execute(text("""
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns 
                WHERE table_name = 'used_domain'
                ORDER BY ordinal_position
            """))
            
            print("\n📋 Current used_domain table structure:")
            for row in result.fetchall():
                print(f"  - {row[0]}: {row[1]} (nullable: {row[2]}, default: {row[3]})")
                
    except Exception as e:
        print(f"❌ Error updating database schema: {e}")
        sys.exit(1)

if __name__ == "__main__":
    update_database_schema()
