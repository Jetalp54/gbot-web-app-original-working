"""
Database Migration: Add execution_id to aws_generated_password table

Run this script to add the execution_id column and index:
python migrate_execution_id.py
"""

from database import db
from app import app
from sqlalchemy import text

def run_migration():
    with app.app_context():
        try:
            print("Adding execution_id column to aws_generated_password...")
            db.session.execute(text('ALTER TABLE aws_generated_password ADD COLUMN execution_id VARCHAR(100)'))
            
            print("Creating index on execution_id...")
            db.session.execute(text('CREATE INDEX idx_execution_id ON aws_generated_password(execution_id)'))
            
            db.session.commit()
            print('✓ Migration completed successfully!')
            return True
        except Exception as e:
            print(f'❌ Migration error: {e}')
            db.session.rollback()
            return False

if __name__ == '__main__':
    success = run_migration()
    exit(0 if success else 1)
