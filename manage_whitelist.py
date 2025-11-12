#!/usr/bin/env python3
"""
IP Whitelist Management Tool for GBot Web App
This tool allows you to manage IP whitelist from the command line
"""

import os
import sys
import argparse
import requests
from pathlib import Path

def get_env_value(key, default=None):
    """Get value from .env file"""
    env_file = Path('.env')
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('#') and '=' in line:
                    k, v = line.strip().split('=', 1)
                    if k == key:
                        return v
    return os.environ.get(key, default)

def detect_current_ip():
    """Detect current external IP address"""
    try:
        # Try multiple IP detection services
        services = [
            'https://api.ipify.org?format=json',
            'https://ipinfo.io/ip',
            'https://icanhazip.com'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    if service.endswith('json'):
                        return response.json()['ip']
                    else:
                        return response.text.strip()
            except:
                continue
                
        return None
    except Exception as e:
        print(f"Error detecting IP: {e}")
        return None

def add_ip_to_whitelist(ip_address, emergency_key, base_url="http://localhost"):
    """Add IP to whitelist using emergency API"""
    try:
        url = f"{base_url}/api/emergency-add-ip"
        data = {
            'ip_address': ip_address,
            'emergency_key': emergency_key
        }
        
        response = requests.post(url, json=data, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                print(f"✅ Success: {result['message']}")
                return True
            else:
                print(f"❌ Error: {result['error']}")
                return False
        else:
            print(f"❌ HTTP Error: {response.status_code}")
            if response.status_code == 403:
                print("Access denied. Check your emergency key.")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"❌ Connection error: Could not connect to {base_url}")
        print("Make sure the application is running and accessible.")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def list_whitelisted_ips(base_url="http://localhost"):
    """List all whitelisted IPs"""
    try:
        url = f"{base_url}/api/list-whitelist-ips"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                ips = result.get('ips', [])
                if ips:
                    print("📋 Whitelisted IPs:")
                    for ip in ips:
                        print(f"  • {ip}")
                    print(f"\nTotal: {len(ips)} IP(s)")
                else:
                    print("📋 No IPs are currently whitelisted")
            else:
                print(f"❌ Error: {result['error']}")
        else:
            print(f"❌ HTTP Error: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print(f"❌ Connection error: Could not connect to {base_url}")
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    parser = argparse.ArgumentParser(description='GBot Web App IP Whitelist Manager')
    parser.add_argument('--add', metavar='IP', help='Add IP address to whitelist')
    parser.add_argument('--detect', action='store_true', help='Detect current external IP')
    parser.add_argument('--list', action='store_true', help='List all whitelisted IPs')
    parser.add_argument('--key', metavar='KEY', help='Emergency access key (or set WHITELIST_TOKEN env var)')
    parser.add_argument('--url', metavar='URL', default='http://localhost', help='Base URL of the application (default: http://localhost)')
    
    args = parser.parse_args()
    
    if not any([args.add, args.detect, args.list]):
        parser.print_help()
        return
    
    # Get emergency key
    emergency_key = args.key or get_env_value('WHITELIST_TOKEN')
    if not emergency_key:
        print("❌ Error: Emergency access key not provided")
        print("Use --key option or set WHITELIST_TOKEN environment variable")
        return
    
    if args.detect:
        print("🔍 Detecting current external IP...")
        current_ip = detect_current_ip()
        if current_ip:
            print(f"✅ Your current external IP: {current_ip}")
        else:
            print("❌ Could not detect current IP")
    
    if args.add:
        ip_address = args.add
        print(f"🚨 Adding IP {ip_address} to whitelist...")
        if add_ip_to_whitelist(ip_address, emergency_key, args.url):
            print("✅ IP added successfully!")
        else:
            print("❌ Failed to add IP")
    
    if args.list:
        print("📋 Fetching whitelisted IPs...")
        list_whitelisted_ips(args.url)

if __name__ == '__main__':
    main()
