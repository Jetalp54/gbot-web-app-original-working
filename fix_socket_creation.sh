#!/bin/bash

echo "=== Fixing Socket Creation Issue ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "1. Stopping gbot service..."
systemctl stop gbot.service

echo -e "\n2. Removing any existing socket file..."
rm -f /opt/gbot-web-app/gbot.sock

echo -e "\n3. Checking app.py for syntax errors..."
cd /opt/gbot-web-app
source venv/bin/activate

python -m py_compile app.py
if [ $? -ne 0 ]; then
    echo "❌ app.py has syntax errors. Please fix them first."
    exit 1
fi
echo "✅ app.py syntax is correct"

echo -e "\n4. Testing app import..."
python -c "
try:
    import app
    print('✅ App imports successfully')
    print('App object type:', type(app.app))
except Exception as e:
    print('❌ App import failed:', str(e))
    import traceback
    traceback.print_exc()
    exit(1)
"

echo -e "\n5. Testing gunicorn manually with timeout..."
echo "Starting gunicorn manually..."
timeout 10 gunicorn --bind unix:/opt/gbot-web-app/gbot.sock --workers 1 --timeout 60 app:app &
GUNICORN_PID=$!

echo "Waiting for socket creation..."
sleep 5

if [ -S /opt/gbot-web-app/gbot.sock ]; then
    echo "✅ Socket file created successfully"
    ls -la /opt/gbot-web-app/gbot.sock
    
    echo "Stopping manual gunicorn..."
    kill $GUNICORN_PID 2>/dev/null
    sleep 2
    
    echo -e "\n6. Fixing socket permissions..."
    chown root:www-data /opt/gbot-web-app/gbot.sock
    chmod 660 /opt/gbot-web-app/gbot.sock
    
    echo -e "\n7. Starting gbot service..."
    systemctl start gbot.service
    sleep 3
    
    echo -e "\n8. Checking service status..."
    systemctl status gbot.service --no-pager
    
    if [ -S /opt/gbot-web-app/gbot.sock ]; then
        echo "✅ Socket file exists after service start"
        ls -la /opt/gbot-web-app/gbot.sock
        
        echo -e "\n9. Starting nginx..."
        systemctl start nginx
        
        echo -e "\n10. Final status check..."
        systemctl status gbot.service --no-pager
        systemctl status nginx --no-pager
        
        echo -e "\n=== Fix Complete ==="
        echo "✅ Services should now be running properly"
        
    else
        echo "❌ Socket file disappeared after service start"
        echo "Checking service logs..."
        journalctl -u gbot.service --no-pager -n 10
    fi
    
else
    echo "❌ Socket file was not created by manual gunicorn"
    echo "This indicates a deeper issue with the application"
    echo "Checking for errors..."
    
    # Kill the process if it's still running
    kill $GUNICORN_PID 2>/dev/null
    
    echo "Checking gunicorn error logs..."
    if [ -f "/opt/gbot-web-app/gunicorn-error.log" ]; then
        tail -n 20 /opt/gbot-web-app/gunicorn-error.log
    fi
    
    echo "Trying to run gunicorn with more verbose output..."
    cd /opt/gbot-web-app
    source venv/bin/activate
    gunicorn --bind unix:/opt/gbot-web-app/gbot.sock --workers 1 --timeout 60 --log-level debug app:app &
    sleep 3
    kill %1 2>/dev/null
fi
