#!/bin/bash

echo "=== Diagnosing App Startup Issue ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "1. Checking gunicorn log..."
if [ -f "/opt/gbot-web-app/gunicorn.log" ]; then
    echo "Gunicorn log contents:"
    cat /opt/gbot-web-app/gunicorn.log
else
    echo "No gunicorn.log found"
fi

echo -e "\n2. Checking gunicorn error log..."
if [ -f "/opt/gbot-web-app/gunicorn-error.log" ]; then
    echo "Gunicorn error log contents:"
    tail -n 30 /opt/gbot-web-app/gunicorn-error.log
else
    echo "No gunicorn-error.log found"
fi

echo -e "\n3. Testing Python import..."
cd /opt/gbot-web-app
source venv/bin/activate

echo "Testing basic Python import..."
python -c "print('Python is working')"

echo -e "\n4. Testing Flask import..."
python -c "
try:
    import flask
    print('✅ Flask imported successfully')
    print('Flask version:', flask.__version__)
except Exception as e:
    print('❌ Flask import failed:', e)
"

echo -e "\n5. Testing app.py import..."
python -c "
try:
    import app
    print('✅ app.py imported successfully')
    print('App object:', app.app)
    print('App type:', type(app.app))
except Exception as e:
    print('❌ app.py import failed:', e)
    import traceback
    traceback.print_exc()
"

echo -e "\n6. Testing app startup with Flask test client..."
python -c "
try:
    import app
    print('Testing Flask app startup...')
    with app.app.app_context():
        print('✅ App context created successfully')
    
    # Test a simple route
    with app.app.test_client() as client:
        try:
            response = client.get('/')
            print('✅ Root route accessible, status:', response.status_code)
        except Exception as e:
            print('❌ Root route failed:', e)
            
except Exception as e:
    print('❌ App startup failed:', e)
    import traceback
    traceback.print_exc()
"

echo -e "\n7. Testing database connection..."
python -c "
try:
    import app
    with app.app.app_context():
        try:
            result = app.db.session.execute(app.db.text('SELECT 1')).fetchone()
            print('✅ Database connection successful')
        except Exception as e:
            print('❌ Database connection failed:', e)
            import traceback
            traceback.print_exc()
except Exception as e:
    print('❌ Database test failed:', e)
"

echo -e "\n8. Testing gunicorn with single worker and debug..."
echo "Starting gunicorn with debug logging..."
timeout 10 gunicorn --bind unix:/opt/gbot-web-app/gbot.sock --workers 1 --timeout 60 --log-level debug --preload app:app 2>&1 | head -n 20 &
GUNICORN_PID=$!

sleep 3

echo "Checking if socket was created..."
if [ -S /opt/gbot-web-app/gbot.sock ]; then
    echo "✅ Socket file created"
    ls -la /opt/gbot-web-app/gbot.sock
else
    echo "❌ Socket file not created"
fi

echo "Killing test gunicorn..."
kill $GUNICORN_PID 2>/dev/null

echo -e "\n9. Checking for any syntax errors in app.py..."
python -m py_compile app.py
if [ $? -eq 0 ]; then
    echo "✅ app.py compiles without syntax errors"
else
    echo "❌ app.py has syntax errors"
fi

echo -e "\n10. Checking environment variables..."
echo "FLASK_ENV: $FLASK_ENV"
echo "PATH: $PATH"
echo "Working directory: $(pwd)"

echo -e "\n=== Diagnosis Complete ==="
