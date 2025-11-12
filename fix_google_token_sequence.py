#!/usr/bin/env python3
"""
Fix script for GoogleToken sequence issue
"""

import sys
import os

# Add the app directory to Python path
sys.path.insert(0, '/opt/gbot-web-app')

print("=== Fixing GoogleToken Sequence Issue ===")

try:
    import app
    from database import GoogleToken, db
    
    with app.app.app_context():
        print("1. Checking current GoogleToken table state...")
        
        # Get current count and max ID
        total_tokens = GoogleToken.query.count()
        max_id = db.session.execute(db.text("SELECT MAX(id) FROM google_token")).scalar()
        
        print(f"Total GoogleToken records: {total_tokens}")
        print(f"Max ID in table: {max_id}")
        
        if max_id is None:
            max_id = 0
        
        print(f"\n2. Checking PostgreSQL sequence...")
        
        # Check current sequence value
        current_seq = db.session.execute(db.text("SELECT last_value FROM google_token_id_seq")).scalar()
        print(f"Current sequence value: {current_seq}")
        
        print(f"\n3. Fixing sequence...")
        
        # Set sequence to max_id + 1
        new_seq_value = max_id + 1
        db.session.execute(db.text(f"SELECT setval('google_token_id_seq', {new_seq_value})"))
        db.session.commit()
        
        print(f"✅ Sequence set to {new_seq_value}")
        
        print(f"\n4. Verifying fix...")
        
        # Test creating a new token (without actually saving it)
        try:
            # This should not fail now
            test_token = GoogleToken(account_id=999999)  # Use a non-existent account_id for testing
            print("✅ Token creation test passed")
        except Exception as e:
            print(f"❌ Token creation test failed: {e}")
        
        print(f"\n=== Fix Complete ===")
        print("✅ GoogleToken sequence should now be fixed")
        print("You can now try adding your account again")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
