#!/bin/bash

echo "=== Quick Database Sequence Fix ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "1. Stopping gbot service..."
systemctl stop gbot.service

echo "2. Running sequence fix script..."
cd /opt/gbot-web-app
source venv/bin/activate
python fix_all_database_sequences.py

echo "3. Starting gbot service..."
systemctl start gbot.service

echo "4. Checking service status..."
systemctl status gbot.service --no-pager

echo "=== Fix Complete ==="
echo "✅ All database sequences should now be fixed"
echo "Try adding your account again!"
