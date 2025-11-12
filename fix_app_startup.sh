#!/bin/bash

echo "=== Fixing App Startup Issues ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "1. Stopping all services..."
systemctl stop gbot.service 2>/dev/null
pkill -f gunicorn 2>/dev/null

echo -e "\n2. Removing old socket and log files..."
rm -f /opt/gbot-web-app/gbot.sock
rm -f /opt/gbot-web-app/gunicorn.log
rm -f /opt/gbot-web-app/gunicorn-access.log
rm -f /opt/gbot-web-app/gunicorn-error.log

echo -e "\n3. Fixing directory permissions..."
chown -R root:root /opt/gbot-web-app
chmod -R 755 /opt/gbot-web-app

echo -e "\n4. Activating virtual environment and testing..."
cd /opt/gbot-web-app
source venv/bin/activate

echo "Testing Python and Flask..."
python -c "
import sys
print('Python version:', sys.version)
print('Python path:', sys.path[:3])

try:
    import flask
    print('✅ Flask version:', flask.__version__)
except Exception as e:
    print('❌ Flask import failed:', e)
    sys.exit(1)
"

echo -e "\n5. Testing app import with detailed error handling..."
python -c "
import sys
import traceback

try:
    print('Importing app...')
    import app
    print('✅ app.py imported successfully')
    
    print('Testing app object...')
    print('App type:', type(app.app))
    print('App name:', app.app.name)
    
    print('Testing app context...')
    with app.app.app_context():
        print('✅ App context works')
        
    print('Testing database connection...')
    try:
        result = app.db.session.execute(app.db.text('SELECT 1')).fetchone()
        print('✅ Database connection works')
    except Exception as e:
        print('❌ Database connection failed:', e)
        traceback.print_exc()
        
except Exception as e:
    print('❌ App import/startup failed:', e)
    traceback.print_exc()
    sys.exit(1)
"

if [ $? -ne 0 ]; then
    echo "❌ App startup test failed. Please check the errors above."
    exit 1
fi

echo -e "\n6. Testing gunicorn with minimal configuration..."
echo "Starting gunicorn with single worker and no preload..."
timeout 15 gunicorn --bind unix:/opt/gbot-web-app/gbot.sock --workers 1 --timeout 60 --log-level info app:app &
GUNICORN_PID=$!

echo "Waiting for startup..."
sleep 5

if [ -S /opt/gbot-web-app/gbot.sock ]; then
    echo "✅ Socket file created successfully"
    ls -la /opt/gbot-web-app/gbot.sock
    
    echo "Fixing socket permissions..."
    chown root:www-data /opt/gbot-web-app/gbot.sock
    chmod 660 /opt/gbot-web-app/gbot.sock
    
    echo "Stopping test gunicorn..."
    kill $GUNICORN_PID 2>/dev/null
    sleep 2
    
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
    echo "❌ Socket file was not created"
    echo "Checking gunicorn logs..."
    if [ -f "/opt/gbot-web-app/gunicorn.log" ]; then
        cat /opt/gbot-web-app/gunicorn.log
    fi
    
    echo "Killing test gunicorn..."
    kill $GUNICORN_PID 2>/dev/null
    
    echo "This indicates a fundamental issue with the application."
    echo "Please check the errors above and fix any import or configuration issues."
fi
