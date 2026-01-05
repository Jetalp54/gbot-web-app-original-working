"""
Test script to verify /api/aws/get-config route works
Run this on the remote server to debug the issue.
"""
import requests
import sys

BASE_URL = "http://127.0.0.1:5000"

# Try to hit the endpoint directly (bypassing login for debug)
print("Testing /api/aws/get-config...")

try:
    # First, try without auth to see if route exists
    response = requests.get(f"{BASE_URL}/api/aws/get-config", timeout=5)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text[:500]}")
except Exception as e:
    print(f"Request failed: {e}")

# Also check what routes are registered
print("\n--- Checking if route is registered ---")
try:
    from app import app
    
    rules = list(app.url_map.iter_rules())
    aws_routes = [r for r in rules if '/api/aws' in r.rule]
    
    print(f"Found {len(aws_routes)} AWS routes:")
    for route in aws_routes[:20]:
        print(f"  {route.rule} -> {route.endpoint}")
    
    # Specifically check for get-config
    get_config_route = [r for r in rules if 'get-config' in r.rule]
    if get_config_route:
        print(f"\n✅ /api/aws/get-config route EXISTS: {get_config_route[0].rule}")
    else:
        print("\n❌ /api/aws/get-config route NOT FOUND!")
        print("Available /api/aws/* routes:")
        for r in aws_routes:
            print(f"  - {r.rule}")
            
except Exception as e:
    print(f"Error checking routes: {e}")
    import traceback
    traceback.print_exc()
