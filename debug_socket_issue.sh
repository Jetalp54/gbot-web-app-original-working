#!/bin/bash

echo "=== Debugging Socket Creation Issue ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "1. Checking gbot service status..."
systemctl status gbot.service --no-pager

echo -e "\n2. Checking if gbot service is actually running..."
ps aux | grep gunicorn

echo -e "\n3. Checking gbot service logs..."
journalctl -u gbot.service --no-pager -n 20

echo -e "\n4. Checking gunicorn error logs..."
if [ -f "/opt/gbot-web-app/gunicorn-error.log" ]; then
    echo "Gunicorn error log:"
    tail -n 20 /opt/gbot-web-app/gunicorn-error.log
else
    echo "No gunicorn error log found"
fi

echo -e "\n5. Testing gunicorn manually..."
cd /opt/gbot-web-app
source venv/bin/activate

echo "Testing Python import..."
python -c "import app; print('✅ App imports successfully')"

echo -e "\n6. Testing gunicorn command manually..."
echo "Running: gunicorn --bind unix:/opt/gbot-web-app/gbot.sock --workers 1 app:app"
timeout 10 gunicorn --bind unix:/opt/gbot-web-app/gbot.sock --workers 1 app:app &
GUNICORN_PID=$!

sleep 3

echo -e "\n7. Checking if socket was created..."
if [ -S /opt/gbot-web-app/gbot.sock ]; then
    echo "✅ Socket file created successfully"
    ls -la /opt/gbot-web-app/gbot.sock
    kill $GUNICORN_PID 2>/dev/null
else
    echo "❌ Socket file still not created"
    echo "Killing test gunicorn process..."
    kill $GUNICORN_PID 2>/dev/null
fi

echo -e "\n8. Checking app.py for any syntax errors..."
python -m py_compile app.py
if [ $? -eq 0 ]; then
    echo "✅ app.py compiles without syntax errors"
else
    echo "❌ app.py has syntax errors"
fi

echo -e "\n9. Checking if there are any import errors..."
python -c "
try:
    import app
    print('✅ App imports successfully')
    print('App object:', app.app)
except Exception as e:
    print('❌ App import failed:', str(e))
    import traceback
    traceback.print_exc()
"

echo -e "\n10. Checking service file configuration..."
cat /etc/systemd/system/gbot.service

echo -e "\n=== Debug Complete ==="
