#!/usr/bin/env python3
"""
Test script for server configuration functionality
"""

import os
import sys
import json
import tempfile

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
from database import db, ServerConfig

def test_server_config():
    """Test the server configuration functionality"""
    
    with app.app_context():
        print("🧪 Testing Server Configuration Functionality")
        print("=" * 50)
        
        # Test 1: Create server configuration
        print("\n1. Creating server configuration...")
        config = ServerConfig(
            host='192.168.1.100',
            port=22,
            username='ubuntu',
            auth_method='password',
            password='test_password',
            json_path='/opt/gbot-web-app/credentials/',
            file_pattern='*.json',
            is_configured=True
        )
        
        db.session.add(config)
        db.session.commit()
        print("✅ Server configuration created successfully")
        
        # Test 2: Retrieve configuration
        print("\n2. Retrieving server configuration...")
        retrieved_config = ServerConfig.query.first()
        if retrieved_config:
            print(f"✅ Configuration retrieved:")
            print(f"   Host: {retrieved_config.host}")
            print(f"   Port: {retrieved_config.port}")
            print(f"   Username: {retrieved_config.username}")
            print(f"   Auth Method: {retrieved_config.auth_method}")
            print(f"   JSON Path: {retrieved_config.json_path}")
            print(f"   File Pattern: {retrieved_config.file_pattern}")
            print(f"   Is Configured: {retrieved_config.is_configured}")
        else:
            print("❌ Failed to retrieve configuration")
            return False
        
        # Test 3: Update configuration
        print("\n3. Updating server configuration...")
        retrieved_config.host = '192.168.1.200'
        retrieved_config.port = 2222
        db.session.commit()
        
        updated_config = ServerConfig.query.first()
        if updated_config.host == '192.168.1.200' and updated_config.port == 2222:
            print("✅ Configuration updated successfully")
        else:
            print("❌ Failed to update configuration")
            return False
        
        # Test 4: Clear configuration
        print("\n4. Clearing server configuration...")
        db.session.delete(updated_config)
        db.session.commit()
        
        cleared_config = ServerConfig.query.first()
        if cleared_config is None:
            print("✅ Configuration cleared successfully")
        else:
            print("❌ Failed to clear configuration")
            return False
        
        print("\n🎉 All tests passed!")
        return True

if __name__ == '__main__':
    try:
        success = test_server_config()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        sys.exit(1)
