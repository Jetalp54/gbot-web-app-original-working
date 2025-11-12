#!/usr/bin/env python3
"""
Script to fix the used_domain sequence issue.
This will reset the used_domain_id_seq to the correct value.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from sqlalchemy import text
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fix_used_domain_sequence():
    """Fix the used_domain sequence to be in sync with actual data"""
    
    with app.app_context():
        try:
            logger.info("🔄 Fixing used_domain sequence...")
            
            # Get the current max ID from the table
            result = db.session.execute(text("SELECT MAX(id) FROM used_domain")).fetchone()
            max_id = result[0] if result[0] is not None else 0
            
            logger.info(f"📊 Current max ID in used_domain table: {max_id}")
            
            # Reset the sequence to max_id + 1
            new_sequence_value = max_id + 1
            db.session.execute(text(f"SELECT setval('used_domain_id_seq', {new_sequence_value}, false)"))
            db.session.commit()
            
            logger.info(f"✅ Reset used_domain_id_seq to {new_sequence_value}")
            
            # Verify the fix
            result = db.session.execute(text("SELECT last_value FROM used_domain_id_seq")).fetchone()
            current_sequence_value = result[0]
            
            logger.info(f"📊 Current sequence value: {current_sequence_value}")
            
            # Test inserting a record to make sure it works
            try:
                test_domain = f"test_sequence_fix_{max_id + 1}.example.com"
                db.session.execute(text("""
                    INSERT INTO used_domain (domain_name, user_count, is_verified, ever_used, created_at, updated_at)
                    VALUES (:domain_name, :user_count, :is_verified, :ever_used, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """), {
                    'domain_name': test_domain,
                    'user_count': 0,
                    'is_verified': True,
                    'ever_used': False
                })
                db.session.commit()
                logger.info(f"✅ Test insert successful: {test_domain}")
                
                # Clean up test record
                db.session.execute(text("DELETE FROM used_domain WHERE domain_name = :domain_name"), {
                    'domain_name': test_domain
                })
                db.session.commit()
                logger.info("🧹 Test record cleaned up")
                
            except Exception as e:
                logger.error(f"❌ Test insert failed: {e}")
                db.session.rollback()
                raise
            
            logger.info("🎉 used_domain sequence fix completed successfully!")
            
        except Exception as e:
            logger.error(f"❌ Error fixing sequence: {e}")
            db.session.rollback()
            raise

def check_all_sequences():
    """Check and fix all sequences that might be out of sync"""
    
    with app.app_context():
        try:
            logger.info("🔄 Checking all sequences...")
            
            sequences_to_check = [
                ('google_account_id_seq', 'google_account'),
                ('google_token_id_seq', 'google_token'),
                ('used_domain_id_seq', 'used_domain'),
                ('user_app_password_id_seq', 'user_app_password'),
                ('scope_id_seq', 'scope'),
                ('whitelisted_ip_id_seq', 'whitelisted_ip'),
                ('user_id_seq', 'user')
            ]
            
            def get_primary_key_column(table: str) -> str | None:
                """Return the primary key column name for a table, or None if not found."""
                # Quote table for regclass lookup (handles reserved names like user)
                query = text(
                    """
                    SELECT a.attname
                    FROM pg_index i
                    JOIN pg_attribute a
                      ON a.attrelid = i.indrelid
                     AND a.attnum = ANY(i.indkey)
                    WHERE i.indisprimary
                      AND i.indrelid = (:tbl)::regclass
                    LIMIT 1
                    """
                )
                # Use schema-qualified name if not provided
                tbl_regclass = f'public."{table}"' if not table.startswith('public.') else table
                row = db.session.execute(query, { 'tbl': tbl_regclass }).fetchone()
                return row[0] if row and len(row) > 0 else None

            for seq_name, table_name in sequences_to_check:
                try:
                    # Determine the primary key column dynamically (fallback to id)
                    pk_col = get_primary_key_column(table_name) or 'id'

                    # Build a safe, quoted table identifier (handles reserved names like user)
                    quoted_table = f'"{table_name}"' if '.' not in table_name else table_name

                    # Get max PK value from table
                    result = db.session.execute(text(f"SELECT MAX({pk_col}) FROM {quoted_table}")).fetchone()
                    max_id = result[0] if result and result[0] is not None else 0
                    
                    # Get current sequence value
                    result = db.session.execute(text(f"SELECT last_value FROM {seq_name}")).fetchone()
                    current_seq = result[0] if result[0] is not None else 0
                    
                    if current_seq <= max_id:
                        new_value = max_id + 1
                        db.session.execute(text(f"SELECT setval('{seq_name}', {new_value}, false)"))
                        logger.info(f"✅ Fixed {seq_name}: {current_seq} -> {new_value} (max_id: {max_id})")
                    else:
                        logger.info(f"📌 {seq_name} is OK: {current_seq} (max_id: {max_id})")
                        
                except Exception as e:
                    logger.warning(f"⚠️ Could not check {seq_name}: {e}")
            
            db.session.commit()
            logger.info("🎉 All sequences checked and fixed!")
            
        except Exception as e:
            logger.error(f"❌ Error checking sequences: {e}")
            db.session.rollback()
            raise

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Fix PostgreSQL sequences')
    parser.add_argument('--all', action='store_true', 
                       help='Check and fix all sequences')
    
    args = parser.parse_args()
    
    if args.all:
        check_all_sequences()
    else:
        fix_used_domain_sequence()
