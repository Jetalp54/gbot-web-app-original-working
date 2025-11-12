import requests
import json

# Test the app password API endpoint
url = "http://localhost:5000/api/store-app-password"
data = {
    "user_alias": "test@example.com",
    "app_password": "testpassword123",
    "domain": "example.com"
}

print("Testing app password API...")
print(f"URL: {url}")
print(f"Data: {json.dumps(data, indent=2)}")

try:
    response = requests.post(url, json=data, timeout=10)
    print(f"Response status: {response.status_code}")
    print(f"Response headers: {dict(response.headers)}")
    print(f"Response text: {response.text}")
    
    if response.status_code == 200:
        result = response.json()
        print(f"Response JSON: {json.dumps(result, indent=2)}")
    else:
        print(f"❌ API call failed with status {response.status_code}")
        
except requests.exceptions.ConnectionError:
    print("❌ Connection error - is the server running?")
except requests.exceptions.Timeout:
    print("❌ Request timeout")
except Exception as e:
    print(f"❌ Error: {e}")
