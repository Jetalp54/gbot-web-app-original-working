#!/bin/bash

echo "🔍 Checking GBot Web App Status..."
echo "===================================="
echo ""

echo "1️⃣ Checking Gunicorn Process:"
ps aux | grep gunicorn | grep -v grep || echo "❌ Gunicorn not running!"
echo ""

echo "2️⃣ Checking if port 5000 is listening:"
netstat -tlnp | grep :5000 || echo "❌ Port 5000 not listening!"
ss -tlnp | grep :5000 || echo "❌ Port 5000 not listening (using ss)!"
echo ""

echo "3️⃣ Checking Gunicorn Service Status:"
sudo systemctl status gbot --no-pager -l | head -20
echo ""

echo "4️⃣ Checking Nginx Status:"
sudo systemctl status nginx --no-pager | head -10
echo ""

echo "5️⃣ Checking Recent Gunicorn Errors:"
sudo journalctl -u gbot -n 50 --no-pager | grep -i error || echo "No recent errors found"
echo ""

echo "6️⃣ Checking System Resources:"
echo "Memory:"
free -h
echo ""
echo "CPU Load:"
uptime
echo ""

echo "7️⃣ Testing Local Connection:"
curl -s http://127.0.0.1:5000/health || echo "❌ Cannot connect to Gunicorn on port 5000!"
echo ""

echo "8️⃣ Checking Gunicorn Config:"
if [ -f /opt/gbot-web-app/gunicorn.conf.py ]; then
    echo "✅ Config file exists"
    grep -E "workers|backlog|bind" /opt/gbot-web-app/gunicorn.conf.py
else
    echo "❌ Config file not found!"
fi
echo ""

echo "9️⃣ Checking Open Files Limit:"
ulimit -n
echo ""

echo "🔟 Checking Database Connection:"
cd /opt/gbot-web-app
source venv/bin/activate
python3 -c "from app import app, db; app.app_context().push(); db.engine.execute('SELECT 1'); print('✅ Database connection OK')" 2>&1 || echo "❌ Database connection failed!"
deactivate
echo ""

echo "✅ Diagnostic complete!"

