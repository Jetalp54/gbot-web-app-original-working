#!/bin/bash

echo "=== Fixing Socket Permissions ==="

# Stop the service first
systemctl stop gbot.service

# Remove old socket file if it exists
rm -f /opt/gbot-web-app/gbot.sock

# Fix directory permissions
chown -R root:root /opt/gbot-web-app
chmod -R 755 /opt/gbot-web-app

# Make sure nginx can access the socket
chown root:www-data /opt/gbot-web-app
chmod 755 /opt/gbot-web-app

# Start the service
systemctl start gbot.service

# Wait a moment for the socket to be created
sleep 2

# Fix socket permissions
if [ -S /opt/gbot-web-app/gbot.sock ]; then
    chown root:www-data /opt/gbot-web-app/gbot.sock
    chmod 660 /opt/gbot-web-app/gbot.sock
    echo "✅ Socket permissions fixed"
    ls -la /opt/gbot-web-app/gbot.sock
else
    echo "❌ Socket file not created"
    systemctl status gbot.service
fi

# Restart nginx
systemctl restart nginx

echo "=== Complete ==="
