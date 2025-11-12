#!/bin/bash

echo "🔍 Testing Domain Configuration for ecochains.online"
echo "===================================================="
echo ""

echo "1️⃣ Testing domain DNS resolution:"
nslookup ecochains.online || dig ecochains.online || echo "❌ DNS resolution failed"
echo ""

echo "2️⃣ Testing domain IP:"
DOMAIN_IP=$(dig +short ecochains.online | tail -1)
echo "Domain resolves to: $DOMAIN_IP"

SERVER_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || curl -s ipinfo.io/ip)
echo "Server IP: $SERVER_IP"

if [ "$DOMAIN_IP" = "$SERVER_IP" ]; then
    echo "✅ DNS is pointing to this server"
else
    echo "❌ DNS is NOT pointing to this server!"
    echo "   Domain IP: $DOMAIN_IP"
    echo "   Server IP: $SERVER_IP"
fi
echo ""

echo "3️⃣ Testing Nginx on port 80:"
curl -I http://ecochains.online 2>&1 | head -10 || echo "❌ Cannot connect on port 80"
echo ""

echo "4️⃣ Testing direct IP on port 80:"
curl -I http://$SERVER_IP 2>&1 | head -10 || echo "❌ Cannot connect to IP on port 80"
echo ""

echo "5️⃣ Testing localhost port 5000:"
curl -s http://127.0.0.1:5000/health || echo "❌ Cannot connect to localhost:5000"
echo ""

echo "6️⃣ Checking Nginx configuration:"
if [ -f /etc/nginx/sites-available/gbot ]; then
    echo "✅ Nginx config found"
    echo "Server name in config:"
    grep -i server_name /etc/nginx/sites-available/gbot || echo "No server_name found!"
else
    echo "❌ Nginx config not found!"
fi
echo ""

echo "7️⃣ Checking if Nginx is listening on port 80:"
sudo netstat -tlnp | grep :80 || echo "❌ Nginx not listening on port 80"
echo ""

echo "8️⃣ Checking Nginx error logs:"
sudo tail -20 /var/log/nginx/error.log | grep -i ecochains || echo "No recent errors for ecochains"
echo ""

echo "✅ Diagnostic complete!"

