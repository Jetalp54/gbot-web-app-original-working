#!/bin/bash

echo "=== GBot Service Diagnostic and Fix Script ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "1. Checking service status..."
systemctl status gbot.service

echo -e "\n2. Checking service logs..."
journalctl -u gbot.service --no-pager -n 50

echo -e "\n3. Checking if the application directory exists..."
if [ -d "/opt/gbot-web-app" ]; then
    echo "✅ Directory exists: /opt/gbot-web-app"
    ls -la /opt/gbot-web-app/
else
    echo "❌ Directory not found: /opt/gbot-web-app"
    exit 1
fi

echo -e "\n4. Checking if virtual environment exists..."
if [ -d "/opt/gbot-web-app/venv" ]; then
    echo "✅ Virtual environment exists"
    ls -la /opt/gbot-web-app/venv/bin/
else
    echo "❌ Virtual environment not found"
    echo "Creating virtual environment..."
    cd /opt/gbot-web-app
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
fi

echo -e "\n5. Checking if gunicorn is installed..."
if [ -f "/opt/gbot-web-app/venv/bin/gunicorn" ]; then
    echo "✅ Gunicorn found"
else
    echo "❌ Gunicorn not found, installing..."
    cd /opt/gbot-web-app
    source venv/bin/activate
    pip install gunicorn
fi

echo -e "\n6. Testing application startup..."
cd /opt/gbot-web-app
source venv/bin/activate

echo "Testing Python import..."
python3 -c "import app; print('✅ App imports successfully')"

echo "Testing gunicorn command..."
/opt/gbot-web-app/venv/bin/gunicorn --check-config app:app

echo -e "\n7. Checking service file..."
cat /etc/systemd/system/gbot.service

echo -e "\n8. Restarting service..."
systemctl daemon-reload
systemctl stop gbot.service
systemctl start gbot.service
systemctl status gbot.service

echo -e "\n9. Final service logs..."
journalctl -u gbot.service --no-pager -n 20

echo -e "\n=== Diagnostic Complete ==="
echo "If the service is still failing, check the logs above for specific errors."
