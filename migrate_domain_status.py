#!/usr/bin/env python3
"""
Database migration script to add 'ever_used' column to UsedDomain table
and implement the new three-state domain status system.
"""

import os
import sys
from flask import Flask
from database import db, UsedDomain

def create_app():
    app = Flask(__name__)
    app.config.from_object('config')
    db.init_app(app)
    return app

def migrate_database():
    app = create_app()
    
    with app.app_context():
        try:
            # Check if the column already exists
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('used_domain')]
            
            if 'ever_used' not in columns:
                print("Adding 'ever_used' column to used_domain table...")
                
                # Add the new column
                db.engine.execute('ALTER TABLE used_domain ADD COLUMN ever_used BOOLEAN DEFAULT FALSE')
                
                # Update existing records: if user_count > 0, set ever_used = True
                existing_domains = UsedDomain.query.all()
                updated_count = 0
                
                for domain in existing_domains:
                    if domain.user_count > 0:
                        domain.ever_used = True
                        updated_count += 1
                
                db.session.commit()
                
                print(f"✅ Migration completed successfully!")
                print(f"   - Added 'ever_used' column")
                print(f"   - Updated {updated_count} domains with ever_used=True")
                print(f"   - Total domains in database: {len(existing_domains)}")
                
            else:
                print("✅ 'ever_used' column already exists. No migration needed.")
                
        except Exception as e:
            print(f"❌ Migration failed: {e}")
            db.session.rollback()
            return False
    
    return True

if __name__ == '__main__':
    print("🔄 Starting database migration for domain status...")
    success = migrate_database()
    
    if success:
        print("🎉 Migration completed successfully!")
        sys.exit(0)
    else:
        print("💥 Migration failed!")
        sys.exit(1)
