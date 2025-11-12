#!/usr/bin/env python3
"""
Test script to identify common app startup issues
"""

import sys
import os
import traceback

# Add the app directory to Python path
sys.path.insert(0, '/opt/gbot-web-app')

print("=== Testing Common App Issues ===")

def test_import(module_name, description):
    try:
        __import__(module_name)
        print(f"✅ {description}")
        return True
    except Exception as e:
        print(f"❌ {description}: {e}")
        return False

def test_app_startup():
    try:
        print("\n1. Testing basic imports...")
        test_import('flask', 'Flask')
        test_import('sqlalchemy', 'SQLAlchemy')
        test_import('psycopg2', 'PostgreSQL driver')
        
        print("\n2. Testing app.py import...")
        import app
        print("✅ app.py imported successfully")
        
        print("\n3. Testing app object...")
        print(f"App object: {app.app}")
        print(f"App type: {type(app.app)}")
        
        print("\n4. Testing app configuration...")
        print(f"Debug mode: {app.app.debug}")
        print(f"Environment: {app.app.config.get('ENV', 'Not set')}")
        
        print("\n5. Testing database connection...")
        with app.app.app_context():
            try:
                result = app.db.session.execute(app.db.text("SELECT 1")).fetchone()
                print("✅ Database connection successful")
            except Exception as e:
                print(f"❌ Database connection failed: {e}")
                traceback.print_exc()
                return False
        
        print("\n6. Testing app routes...")
        with app.app.test_client() as client:
            try:
                response = client.get('/')
                print(f"✅ Root route accessible (status: {response.status_code})")
            except Exception as e:
                print(f"❌ Root route failed: {e}")
                traceback.print_exc()
                return False
        
        print("\n=== All Tests Passed ===")
        print("✅ The app should be able to start with gunicorn")
        return True
        
    except Exception as e:
        print(f"❌ Critical error: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_app_startup()
    sys.exit(0 if success else 1)
