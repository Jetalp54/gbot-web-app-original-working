#!/usr/bin/env python3
"""
Test script for mailer role functionality
"""

import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
from database import db, User
from werkzeug.security import generate_password_hash

def test_mailer_role():
    """Test the mailer role functionality"""
    
    with app.app_context():
        print("🧪 Testing Mailer Role Functionality")
        print("=" * 50)
        
        # Test 1: Create a mailer user
        print("\n1. Creating mailer user...")
        mailer_user = User(
            username='test_mailer',
            password=generate_password_hash('test_password', method='pbkdf2:sha256'),
            role='mailer'
        )
        
        db.session.add(mailer_user)
        db.session.commit()
        print("✅ Mailer user created successfully")
        
        # Test 2: Verify mailer user exists
        print("\n2. Verifying mailer user...")
        retrieved_user = User.query.filter_by(username='test_mailer').first()
        if retrieved_user and retrieved_user.role == 'mailer':
            print(f"✅ Mailer user verified:")
            print(f"   Username: {retrieved_user.username}")
            print(f"   Role: {retrieved_user.role}")
        else:
            print("❌ Failed to verify mailer user")
            return False
        
        # Test 3: Test role validation
        print("\n3. Testing role validation...")
        valid_roles = ['admin', 'support', 'mailer']
        for role in valid_roles:
            test_user = User(
                username=f'test_{role}',
                password=generate_password_hash('test_password', method='pbkdf2:sha256'),
                role=role
            )
            db.session.add(test_user)
            db.session.commit()
            print(f"✅ Created user with role: {role}")
        
        # Test 4: Test invalid role
        print("\n4. Testing invalid role...")
        try:
            invalid_user = User(
                username='test_invalid',
                password=generate_password_hash('test_password', method='pbkdf2:sha256'),
                role='invalid_role'
            )
            db.session.add(invalid_user)
            db.session.commit()
            print("❌ Should not allow invalid role")
            return False
        except Exception as e:
            print("✅ Correctly rejected invalid role")
        
        # Test 5: Clean up test users
        print("\n5. Cleaning up test users...")
        test_users = User.query.filter(User.username.like('test_%')).all()
        for user in test_users:
            db.session.delete(user)
        db.session.commit()
        print(f"✅ Cleaned up {len(test_users)} test users")
        
        print("\n🎉 All mailer role tests passed!")
        return True

if __name__ == '__main__':
    try:
        success = test_mailer_role()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        sys.exit(1)
