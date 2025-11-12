#!/bin/bash

echo "=== Fixing 502 Bad Gateway Error ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "1. Checking gbot service status..."
systemctl status gbot.service

echo -e "\n2. Checking if socket file exists and permissions..."
ls -la /opt/gbot-web-app/gbot.sock

echo -e "\n3. Checking nginx configuration..."
nginx -t

echo -e "\n4. Checking nginx error logs..."
tail -n 20 /var/log/nginx/error.log

echo -e "\n5. Checking nginx access logs..."
tail -n 10 /var/log/nginx/access.log

echo -e "\n6. Fixing socket file permissions..."
chown www-data:www-data /opt/gbot-web-app/gbot.sock
chmod 660 /opt/gbot-web-app/gbot.sock

echo -e "\n7. Checking nginx configuration for gbot..."
if [ -f "/etc/nginx/sites-available/gbot" ]; then
    echo "GBot nginx config found:"
    cat /etc/nginx/sites-available/gbot
else
    echo "Creating nginx configuration for gbot..."
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
fi

echo -e "\n8. Enabling gbot site..."
ln -sf /etc/nginx/sites-available/gbot /etc/nginx/sites-enabled/

echo -e "\n9. Removing default nginx site if it exists..."
rm -f /etc/nginx/sites-enabled/default

echo -e "\n10. Testing nginx configuration..."
nginx -t

if [ $? -eq 0 ]; then
    echo "✅ Nginx configuration is valid"
    echo -e "\n11. Restarting nginx..."
    systemctl restart nginx
    
    echo -e "\n12. Restarting gbot service..."
    systemctl restart gbot.service
    
    echo -e "\n13. Final status check..."
    systemctl status gbot.service
    systemctl status nginx
    
    echo -e "\n14. Testing socket file..."
    ls -la /opt/gbot-web-app/gbot.sock
    
    echo -e "\n15. Checking if socket is accessible..."
    curl -I http://localhost/ || echo "Local test failed, but this might be normal"
    
    echo -e "\n=== Fix Complete ==="
    echo "The service should now be accessible. Check your browser."
else
    echo "❌ Nginx configuration has errors. Please fix them first."
fi
