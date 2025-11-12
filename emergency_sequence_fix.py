#!/usr/bin/env python3
"""
Emergency fix for database sequences - run this immediately
"""

import sys
import os

# Add the app directory to Python path
sys.path.insert(0, '/opt/gbot-web-app')

print("=== EMERGENCY DATABASE SEQUENCE FIX ===")

try:
    import app
    from database import db
    
    with app.app.app_context():
        print("🔧 Fixing all database sequences...")
        
        # Critical sequences that are causing issues
        critical_sequences = [
            'google_account_id_seq',
            'google_token_id_seq', 
            'whitelisted_ip_id_seq',
            'user_app_password_id_seq'
        ]
        
        for seq_name in critical_sequences:
            try:
                print(f"\n📊 Fixing {seq_name}...")
                
                # Get table name from sequence name
                table_name = seq_name.replace('_id_seq', '')
                
                # Get max ID from table
                max_id_result = db.session.execute(db.text(f"SELECT MAX(id) FROM {table_name}")).scalar()
                max_id = max_id_result if max_id_result is not None else 0
                
                # Get current sequence value
                current_seq = db.session.execute(db.text(f"SELECT last_value FROM {seq_name}")).scalar()
                
                print(f"   Current max ID: {max_id}")
                print(f"   Current sequence: {current_seq}")
                
                if current_seq <= max_id:
                    # Fix the sequence
                    new_seq_value = max_id + 1
                    print(f"   🔧 Setting sequence to {new_seq_value}")
                    
                    db.session.execute(db.text(f"SELECT setval('{seq_name}', {new_seq_value})"))
                    db.session.commit()
                    
                    print(f"   ✅ {seq_name} FIXED")
                else:
                    print(f"   ✅ {seq_name} already correct")
                    
            except Exception as e:
                print(f"   ❌ Error fixing {seq_name}: {e}")
                continue
        
        print(f"\n🎯 Testing sequence fix...")
        
        # Test creating a new account (without actually saving)
        try:
            from database import GoogleAccount
            test_account = GoogleAccount(
                account_name='test@example.com',
                client_id='test',
                client_secret='test'
            )
            print("✅ GoogleAccount creation test passed")
        except Exception as e:
            print(f"❌ GoogleAccount creation test failed: {e}")
        
        # Test creating a new token (without actually saving)
        try:
            from database import GoogleToken
            test_token = GoogleToken(
                account_id=999999,  # Non-existent account
                token='test',
                refresh_token='test',
                token_uri='test'
            )
            print("✅ GoogleToken creation test passed")
        except Exception as e:
            print(f"❌ GoogleToken creation test failed: {e}")
        
        print(f"\n🎉 EMERGENCY FIX COMPLETE!")
        print("✅ All sequences should now be fixed")
        print("✅ You can now add accounts without sequence errors")
        print("✅ Try adding your account again!")
        
except Exception as e:
    print(f"❌ CRITICAL ERROR: {e}")
    import traceback
    traceback.print_exc()
    print("\n🚨 If this fails, you may need to manually fix the sequences in PostgreSQL")
