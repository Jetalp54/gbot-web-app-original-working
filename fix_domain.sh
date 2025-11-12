#!/bin/bash

echo "🔧 Fixing Domain Configuration for ecochains.online"
echo "===================================================="
echo ""

# Step 1: Check if Nginx config exists and is enabled
echo "1️⃣ Checking Nginx configuration..."
if [ ! -f /etc/nginx/sites-available/gbot ]; then
    echo "❌ Nginx config not found at /etc/nginx/sites-available/gbot"
    echo "   Creating symlink..."
    cd /opt/gbot-web-app
    sudo cp nginx_gbot_fixed.conf /etc/nginx/sites-available/gbot
    sudo ln -sf /etc/nginx/sites-available/gbot /etc/nginx/sites-enabled/gbot
    echo "✅ Config created and enabled"
else
    echo "✅ Config file exists"
fi

# Step 2: Check if it's enabled
if [ -L /etc/nginx/sites-enabled/gbot ]; then
    echo "✅ Config is enabled (symlink exists)"
else
    echo "⚠️ Config not enabled, creating symlink..."
    sudo ln -sf /etc/nginx/sites-available/gbot /etc/nginx/sites-enabled/gbot
    echo "✅ Symlink created"
fi

# Step 3: Check for default Nginx config that might be blocking
echo ""
echo "2️⃣ Checking for default Nginx config..."
if [ -f /etc/nginx/sites-enabled/default ]; then
    echo "⚠️ WARNING: Default Nginx config is enabled!"
    echo "   This might be blocking your domain. Checking..."
    
    # Check if default config is listening on port 80
    if grep -q "listen 80" /etc/nginx/sites-enabled/default 2>/dev/null; then
        echo "❌ Default config is listening on port 80 - this will block your domain!"
        echo "   Options:"
        echo "   a) Disable default config: sudo rm /etc/nginx/sites-enabled/default"
        echo "   b) Or modify default config to not listen on port 80"
        read -p "   Disable default config now? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo rm /etc/nginx/sites-enabled/default
            echo "✅ Default config disabled"
        fi
    else
        echo "✅ Default config exists but not listening on port 80"
    fi
else
    echo "✅ No default config enabled"
fi

# Step 4: Test Nginx configuration
echo ""
echo "3️⃣ Testing Nginx configuration..."
if sudo nginx -t; then
    echo "✅ Nginx configuration is valid"
else
    echo "❌ Nginx configuration has errors!"
    echo "   Please fix the errors above before continuing"
    exit 1
fi

# Step 5: Check DNS
echo ""
echo "4️⃣ Checking DNS configuration..."
DOMAIN_IP=$(dig +short ecochains.online | tail -1)
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')

echo "   Domain ecochains.online resolves to: $DOMAIN_IP"
echo "   Server IP: $SERVER_IP"

if [ -z "$DOMAIN_IP" ]; then
    echo "⚠️ WARNING: Domain does not resolve!"
    echo "   You need to configure DNS to point ecochains.online to this server's IP"
elif [ "$DOMAIN_IP" != "$SERVER_IP" ]; then
    echo "⚠️ WARNING: Domain does not point to this server!"
    echo "   DNS shows: $DOMAIN_IP"
    echo "   Server IP: $SERVER_IP"
    echo "   Update your DNS records to point ecochains.online to $SERVER_IP"
fi

# Step 6: Check if Nginx is listening on port 80
echo ""
echo "5️⃣ Checking if Nginx is listening on port 80..."
if sudo netstat -tlnp | grep :80 | grep nginx; then
    echo "✅ Nginx is listening on port 80"
else
    echo "❌ Nginx is NOT listening on port 80!"
    echo "   Starting Nginx..."
    sudo systemctl start nginx
    sleep 2
    if sudo netstat -tlnp | grep :80 | grep nginx; then
        echo "✅ Nginx is now listening on port 80"
    else
        echo "❌ Nginx failed to start!"
        sudo systemctl status nginx --no-pager -l | head -20
        exit 1
    fi
fi

# Step 7: Restart Nginx
echo ""
echo "6️⃣ Reloading Nginx..."
sudo systemctl reload nginx || sudo systemctl restart nginx
sleep 2

# Step 8: Test domain access
echo ""
echo "7️⃣ Testing domain access..."
echo "   Testing http://ecochains.online/health..."
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://ecochains.online/health 2>&1)
if [ "$RESPONSE" = "200" ]; then
    echo "✅ Domain is working! HTTP $RESPONSE"
else
    echo "❌ Domain test failed! HTTP $RESPONSE"
    echo "   Testing localhost instead..."
    LOCAL_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/health 2>&1)
    if [ "$LOCAL_RESPONSE" = "200" ]; then
        echo "✅ Localhost:5000 is working (HTTP $LOCAL_RESPONSE)"
        echo "   Issue is likely DNS or Nginx configuration"
    else
        echo "❌ Localhost:5000 also failed (HTTP $LOCAL_RESPONSE)"
    fi
fi

# Step 9: Check firewall
echo ""
echo "8️⃣ Checking firewall..."
if command -v ufw &> /dev/null; then
    if sudo ufw status | grep -q "80/tcp.*ALLOW"; then
        echo "✅ Port 80 is allowed in firewall"
    else
        echo "⚠️ Port 80 might be blocked in firewall"
        echo "   Run: sudo ufw allow 80/tcp"
    fi
elif command -v firewall-cmd &> /dev/null; then
    if sudo firewall-cmd --list-ports | grep -q "80/tcp"; then
        echo "✅ Port 80 is allowed in firewall"
    else
        echo "⚠️ Port 80 might be blocked in firewall"
        echo "   Run: sudo firewall-cmd --permanent --add-service=http && sudo firewall-cmd --reload"
    fi
else
    echo "ℹ️ Firewall command not found (might not be using ufw or firewalld)"
fi

echo ""
echo "✅ Domain fix script complete!"
echo ""
echo "📋 Summary:"
echo "   - Test domain: curl http://ecochains.online/health"
echo "   - Check Nginx logs: sudo tail -f /var/log/nginx/error.log"
echo "   - Check Nginx access: sudo tail -f /var/log/nginx/access.log"
echo ""
echo "If domain still doesn't work, check:"
echo "   1. DNS is pointing to this server ($SERVER_IP)"
echo "   2. Port 80 is open in firewall"
echo "   3. No other services are using port 80"

