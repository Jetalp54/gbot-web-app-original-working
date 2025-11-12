#!/bin/bash

echo "=== Complete GBot Fix Script ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "1. Stopping services..."
systemctl stop gbot.service
systemctl stop nginx

echo -e "\n2. Removing old socket file..."
rm -f /opt/gbot-web-app/gbot.sock

echo -e "\n3. Fixing directory permissions..."
chown -R root:root /opt/gbot-web-app
chmod -R 755 /opt/gbot-web-app

echo -e "\n4. Creating proper nginx configuration..."
cat > /etc/nginx/sites-available/gbot << 'EOF'
server {
    listen 80;
    server_name _;

    location / {
        include proxy_params;
        proxy_pass http://unix:/opt/gbot-web-app/gbot.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Increase timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Increase client body size
        client_max_body_size 100M;
    }
}
EOF

echo -e "\n5. Enabling gbot site and removing default..."
ln -sf /etc/nginx/sites-available/gbot /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

echo -e "\n6. Testing nginx configuration..."
nginx -t

if [ $? -ne 0 ]; then
    echo "❌ Nginx configuration error. Please check the config."
    exit 1
fi

echo -e "\n7. Starting gbot service..."
systemctl start gbot.service
sleep 3

echo -e "\n8. Checking gbot status..."
systemctl status gbot.service --no-pager

echo -e "\n9. Waiting for socket creation..."
sleep 2

if [ -S /opt/gbot-web-app/gbot.sock ]; then
    echo "✅ Socket file created"
    ls -la /opt/gbot-web-app/gbot.sock
    
    echo -e "\n10. Fixing socket permissions..."
    chown root:www-data /opt/gbot-web-app/gbot.sock
    chmod 660 /opt/gbot-web-app/gbot.sock
    
    echo -e "\n11. Starting nginx..."
    systemctl start nginx
    
    echo -e "\n12. Final status check..."
    systemctl status gbot.service --no-pager
    systemctl status nginx --no-pager
    
    echo -e "\n13. Testing connection..."
    curl -I http://localhost/ 2>/dev/null | head -1 || echo "Connection test failed"
    
    echo -e "\n=== Fix Complete ==="
    echo "✅ Services should now be running properly"
    echo "🌐 Try accessing your application now"
    
else
    echo "❌ Socket file not created. Checking logs..."
    journalctl -u gbot.service --no-pager -n 10
    echo "Please check the gbot service logs for errors."
fi
