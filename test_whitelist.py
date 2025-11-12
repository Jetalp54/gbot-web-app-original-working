#!/usr/bin/env python3
"""
Test script to debug IP whitelist configuration
"""
import os
import requests
import json

def test_config():
    """Test the configuration values"""
    print("=== Testing Configuration ===")
    
    # Test config.py directly
    try:
        import config
        print(f"Config.py values:")
        print(f"WHITELIST_TOKEN: {config.WHITELIST_TOKEN}")
        print(f"ENABLE_IP_WHITELIST: {config.ENABLE_IP_WHITELIST}")
        print(f"DEBUG: {config.DEBUG}")
        print(f"SECRET_KEY: {config.SECRET_KEY}")
    except Exception as e:
        print(f"Error loading config: {e}")
    
    # Test environment variables
    print(f"\nEnvironment variables:")
    print(f"WHITELIST_TOKEN: {os.environ.get('WHITELIST_TOKEN', 'None')}")
    print(f"ENABLE_IP_WHITELIST: {os.environ.get('ENABLE_IP_WHITELIST', 'None')}")
    print(f"DEBUG: {os.environ.get('DEBUG', 'None')}")
    print(f"SECRET_KEY: {os.environ.get('SECRET_KEY', 'None')}")

def test_api_endpoints(base_url):
    """Test the API endpoints"""
    print(f"\n=== Testing API Endpoints ===")
    
    # Test debug config endpoint
    try:
        response = requests.get(f"{base_url}/api/debug-config", timeout=10)
        if response.status_code == 200:
            config_data = response.json()
            print(f"Debug config endpoint: {json.dumps(config_data, indent=2)}")
        else:
            print(f"Debug config endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"Error testing debug config: {e}")
    
    # Test debug session endpoint
    try:
        response = requests.get(f"{base_url}/api/debug-session", timeout=10)
        if response.status_code == 200:
            session_data = response.json()
            print(f"Debug session endpoint: {json.dumps(session_data, indent=2)}")
        else:
            print(f"Debug session endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"Error testing debug session: {e}")
    
    # Test debug whitelist endpoint
    try:
        response = requests.get(f"{base_url}/api/debug-whitelist", timeout=10)
        if response.status_code == 200:
            whitelist_data = response.json()
            print(f"Debug whitelist endpoint: {json.dumps(whitelist_data, indent=2)}")
        else:
            print(f"Debug whitelist endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"Error testing debug whitelist: {e}")
    
    # Test emergency access endpoint
    try:
        response = requests.get(f"{base_url}/emergency_access", timeout=10)
        if response.status_code == 200:
            print(f"Emergency access endpoint: OK (200)")
        else:
            print(f"Emergency access endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"Error testing emergency access: {e}")
    
    # Test emergency access with WHITELIST_TOKEN
    try:
        response = requests.get(f"{base_url}/emergency_access?key=4cb5d7420abd8b144be9c79723905d5d", timeout=10)
        print(f"Emergency access with WHITELIST_TOKEN: {response.status_code}")
        if response.status_code == 302:  # Redirect
            print(f"Redirect location: {response.headers.get('Location', 'None')}")
        elif response.status_code == 200:
            print("Emergency access form displayed")
    except Exception as e:
        print(f"Error testing emergency access with WHITELIST_TOKEN: {e}")
    
    # Test emergency access with SECRET_KEY
    try:
        response = requests.get(f"{base_url}/emergency_access?key=4bb5d226ca429980a0f60b696388be8bc4b3797e99f23001a72d09789d7500f9", timeout=10)
        print(f"Emergency access with SECRET_KEY: {response.status_code}")
        if response.status_code == 302:  # Redirect
            print(f"Redirect location: {response.headers.get('Location', 'None')}")
        elif response.status_code == 200:
            print("Emergency access form displayed")
    except Exception as e:
        print(f"Error testing emergency access with SECRET_KEY: {e}")
    
    # Test whitelist endpoint (should fail without session)
    try:
        response = requests.get(f"{base_url}/whitelist", timeout=10)
        print(f"Whitelist endpoint: {response.status_code}")
        if response.status_code == 403:
            print("Access denied (expected without session)")
        elif response.status_code == 200:
            print("Whitelist accessible (unexpected)")
    except Exception as e:
        print(f"Error testing whitelist endpoint: {e}")

def test_emergency_add_ip(base_url, ip_address, emergency_key, key_name):
    """Test the emergency add IP endpoint"""
    print(f"\n=== Testing Emergency Add IP with {key_name} ===")
    
    try:
        data = {
            'ip_address': ip_address,
            'emergency_key': emergency_key
        }
        
        response = requests.post(
            f"{base_url}/api/emergency-add-ip",
            json=data,
            timeout=10
        )
        
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Success: {result.get('success')}")
            if not result.get('success'):
                print(f"Error: {result.get('error')}")
        
    except Exception as e:
        print(f"Error testing emergency add IP: {e}")

if __name__ == '__main__':
    # Test configuration
    test_config()
    
    # Test API endpoints (change this to your actual domain)
    base_url = "https://ecochains.online"
    
    # Test emergency add IP with both keys
    ip_address = "102.101.242.72"  # Your current IP
    whitelist_token = "4cb5d7420abd8b144be9c79723905d5d"  # Your WHITELIST_TOKEN
    secret_key = "4bb5d226ca429980a0f60b696388be8bc4b3797e99f23001a72d09789d7500f9"  # Your SECRET_KEY
    
    test_api_endpoints(base_url)
    test_emergency_add_ip(base_url, ip_address, whitelist_token, "WHITELIST_TOKEN")
    test_emergency_add_ip(base_url, ip_address, secret_key, "SECRET_KEY")
