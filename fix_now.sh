#!/bin/bash

echo "🚨 EMERGENCY DATABASE SEQUENCE FIX 🚨"
echo "This will fix the sequence issues immediately"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo ./fix_now.sh"
    exit 1
fi

echo "1. Stopping gbot service..."
systemctl stop gbot.service

echo "2. Running emergency fix..."
cd /opt/gbot-web-app
source venv/bin/activate
python emergency_sequence_fix.py

echo "3. Starting gbot service..."
systemctl start gbot.service

echo "4. Checking if service is running..."
if systemctl is-active --quiet gbot.service; then
    echo "✅ Service is running"
else
    echo "❌ Service failed to start"
    systemctl status gbot.service --no-pager
fi

echo ""
echo "🎉 FIX COMPLETE!"
echo "✅ Try adding your account again now!"
