#!/usr/bin/env python3
"""
Comprehensive fix for all database sequence issues
"""

import sys
import os

# Add the app directory to Python path
sys.path.insert(0, '/opt/gbot-web-app')

print("=== Comprehensive Database Sequence Fix ===")

try:
    import app
    from database import db
    
    with app.app.app_context():
        print("1. Analyzing all database sequences...")
        
        # List of all tables with auto-incrementing primary keys
        tables_to_fix = [
            'user',
            'whitelisted_ip', 
            'used_domain',
            'google_account',
            'google_token',
            'scope',
            'server_config',
            'user_app_password',
            'automation_account',
            'retrieved_user'
        ]
        
        print(f"Tables to check: {', '.join(tables_to_fix)}")
        
        for table_name in tables_to_fix:
            print(f"\n2. Checking {table_name} table...")
            
            try:
                # Get current max ID
                max_id_result = db.session.execute(db.text(f"SELECT MAX(id) FROM {table_name}")).scalar()
                max_id = max_id_result if max_id_result is not None else 0
                
                # Get current sequence value
                seq_name = f"{table_name}_id_seq"
                try:
                    current_seq = db.session.execute(db.text(f"SELECT last_value FROM {seq_name}")).scalar()
                except Exception as e:
                    print(f"   ⚠️  Sequence {seq_name} doesn't exist or has issues: {e}")
                    continue
                
                print(f"   Max ID in table: {max_id}")
                print(f"   Current sequence: {current_seq}")
                
                if current_seq <= max_id:
                    # Fix the sequence
                    new_seq_value = max_id + 1
                    print(f"   🔧 Fixing sequence: setting to {new_seq_value}")
                    
                    db.session.execute(db.text(f"SELECT setval('{seq_name}', {new_seq_value})"))
                    db.session.commit()
                    
                    print(f"   ✅ {table_name} sequence fixed")
                else:
                    print(f"   ✅ {table_name} sequence is correct")
                    
            except Exception as e:
                print(f"   ❌ Error checking {table_name}: {e}")
                continue
        
        print(f"\n3. Verifying all sequences are fixed...")
        
        for table_name in tables_to_fix:
            try:
                seq_name = f"{table_name}_id_seq"
                current_seq = db.session.execute(db.text(f"SELECT last_value FROM {seq_name}")).scalar()
                max_id = db.session.execute(db.text(f"SELECT MAX(id) FROM {table_name}")).scalar() or 0
                
                if current_seq > max_id:
                    print(f"   ✅ {table_name}: sequence {current_seq} > max_id {max_id}")
                else:
                    print(f"   ⚠️  {table_name}: sequence {current_seq} <= max_id {max_id}")
                    
            except Exception as e:
                print(f"   ❌ {table_name}: {e}")
        
        print(f"\n=== Database Sequence Fix Complete ===")
        print("✅ All sequences should now be properly synchronized")
        print("You can now try adding accounts and tokens without sequence errors")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
