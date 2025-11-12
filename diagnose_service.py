#!/usr/bin/env python3
"""
GBot Service Diagnostic Script
Run this on your Linux server to diagnose service issues
"""

import subprocess
import sys
import os

def run_command(cmd, description):
    print(f"\n=== {description} ===")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(f"Command: {cmd}")
        print(f"Exit code: {result.returncode}")
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        return result.returncode == 0
    except Exception as e:
        print(f"Error running command: {e}")
        return False

def main():
    print("=== GBot Service Diagnostic ===")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ Please run as root (use sudo)")
        sys.exit(1)
    
    # 1. Check service status
    run_command("systemctl status gbot.service", "Service Status")
    
    # 2. Check recent logs
    run_command("journalctl -u gbot.service --no-pager -n 20", "Recent Service Logs")
    
    # 3. Check if app directory exists
    app_dir = "/opt/gbot-web-app"
    if os.path.exists(app_dir):
        print(f"\n✅ App directory exists: {app_dir}")
        run_command(f"ls -la {app_dir}", "App Directory Contents")
    else:
        print(f"❌ App directory not found: {app_dir}")
        return
    
    # 4. Check virtual environment
    venv_dir = f"{app_dir}/venv"
    if os.path.exists(venv_dir):
        print(f"\n✅ Virtual environment exists: {venv_dir}")
        run_command(f"ls -la {venv_dir}/bin/", "Virtual Environment Contents")
    else:
        print(f"❌ Virtual environment not found: {venv_dir}")
        print("Creating virtual environment...")
        run_command(f"cd {app_dir} && python3 -m venv venv", "Creating Virtual Environment")
        run_command(f"cd {app_dir} && source venv/bin/activate && pip install -r requirements.txt", "Installing Dependencies")
    
    # 5. Test Python import
    run_command(f"cd {app_dir} && source venv/bin/activate && python -c 'import app; print(\"App imports successfully\")'", "Testing App Import")
    
    # 6. Test gunicorn
    run_command(f"cd {app_dir} && source venv/bin/activate && gunicorn --check-config app:app", "Testing Gunicorn Config")
    
    # 7. Check service file
    run_command("cat /etc/systemd/system/gbot.service", "Service File Contents")
    
    # 8. Try to restart service
    print("\n=== Attempting Service Restart ===")
    run_command("systemctl daemon-reload", "Reloading Systemd")
    run_command("systemctl stop gbot.service", "Stopping Service")
    run_command("systemctl start gbot.service", "Starting Service")
    run_command("systemctl status gbot.service", "Final Service Status")
    
    # 9. Final logs
    run_command("journalctl -u gbot.service --no-pager -n 10", "Final Service Logs")

if __name__ == "__main__":
    main()
