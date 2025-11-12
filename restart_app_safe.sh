#!/bin/bash

echo "🔄 Safe Restart of GBot Web App..."
echo "==================================="
echo ""

# Step 1: Check current status
echo "1️⃣ Checking current service status..."
sudo systemctl status gbot --no-pager | head -5
echo ""

# Step 2: Stop the service gracefully
echo "2️⃣ Stopping Gunicorn service..."
sudo systemctl stop gbot
sleep 3

# Step 3: Kill any remaining Gunicorn processes
echo "3️⃣ Killing any remaining Gunicorn processes..."
sudo pkill -9 gunicorn || echo "No Gunicorn processes found"
sleep 2

# Step 4: Check config file
echo "4️⃣ Verifying configuration..."
if [ ! -f /opt/gbot-web-app/gunicorn.conf.py ]; then
    echo "❌ ERROR: gunicorn.conf.py not found!"
    exit 1
fi

# Step 5: Check if workers count is too high
WORKERS=$(grep "^workers" /opt/gbot-web-app/gunicorn.conf.py | grep -oP '\d+')
echo "Workers configured: $WORKERS"

if [ "$WORKERS" -gt 50 ]; then
    echo "⚠️ WARNING: Very high worker count ($WORKERS). Consider reducing if server has limited resources."
fi

# Step 6: Verify database connection
echo "5️⃣ Testing database connection..."
cd /opt/gbot-web-app
source venv/bin/activate
python3 -c "from app import app, db; app.app_context().push(); db.engine.connect(); print('✅ DB OK')" 2>&1 || {
    echo "❌ Database connection failed!"
    exit 1
}
deactivate

# Step 7: Restart the service
echo "6️⃣ Starting Gunicorn service..."
sudo systemctl start gbot
sleep 5

# Step 8: Check if it started successfully
echo "7️⃣ Verifying service started..."
if sudo systemctl is-active --quiet gbot; then
    echo "✅ Service is running!"
else
    echo "❌ Service failed to start!"
    echo "Checking logs..."
    sudo journalctl -u gbot -n 30 --no-pager
    exit 1
fi

# Step 9: Check if port is listening
echo "8️⃣ Checking if port 5000 is listening..."
sleep 3
if netstat -tlnp 2>/dev/null | grep -q :5000 || ss -tlnp 2>/dev/null | grep -q :5000; then
    echo "✅ Port 5000 is listening!"
else
    echo "❌ Port 5000 is not listening!"
    echo "Checking recent logs..."
    sudo journalctl -u gbot -n 50 --no-pager | tail -20
    exit 1
fi

# Step 10: Test health endpoint
echo "9️⃣ Testing health endpoint..."
if curl -s http://127.0.0.1:5000/health > /dev/null; then
    echo "✅ Health endpoint responding!"
else
    echo "❌ Health endpoint not responding!"
    exit 1
fi

# Step 11: Reload Nginx
echo "🔟 Reloading Nginx..."
sudo systemctl reload nginx || sudo systemctl restart nginx

echo ""
echo "✅ Restart complete! App should be accessible now."
echo "Check status with: sudo systemctl status gbot"

