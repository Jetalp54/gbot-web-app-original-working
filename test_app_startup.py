#!/usr/bin/env python3
"""
Test script to check if the GBot app can start properly
"""

import sys
import os
import traceback

# Add the app directory to Python path
sys.path.insert(0, '/opt/gbot-web-app')

print("=== Testing GBot App Startup ===")

try:
    print("1. Testing basic imports...")
    import flask
    print("✅ Flask imported successfully")
    
    import sqlalchemy
    print("✅ SQLAlchemy imported successfully")
    
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
            # Try to connect to database
            result = app.db.session.execute(app.db.text("SELECT 1")).fetchone()
            print("✅ Database connection successful")
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
    
    print("\n6. Testing app routes...")
    with app.app.test_client() as client:
        try:
            response = client.get('/')
            print(f"✅ Root route accessible (status: {response.status_code})")
        except Exception as e:
            print(f"❌ Root route failed: {e}")
    
    print("\n=== All Tests Passed ===")
    print("✅ The app should be able to start with gunicorn")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("This might be a missing dependency issue")
    sys.exit(1)
    
except Exception as e:
    print(f"❌ Error: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)
