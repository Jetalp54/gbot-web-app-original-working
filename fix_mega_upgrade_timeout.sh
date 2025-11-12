#!/bin/bash

# Fix timeout issues for Mega Upgrade workflow
# This script increases server timeouts to prevent 504 errors during Mega Upgrade operations

echo "🔧 Fixing Mega Upgrade timeout configuration..."

# Get the current script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Fix Nginx timeout configuration
echo "📡 Updating Nginx timeout configuration..."

# Backup current configuration
sudo cp /etc/nginx/sites-available/gbot /etc/nginx/sites-available/gbot.backup.$(date +%Y%m%d_%H%M%S)

# Create new nginx configuration with increased timeouts (10 minutes)
cat > /tmp/gbot_nginx_mega_fix << EOF
server {
    listen 80;
    server_name _;
    
    location / {
        include proxy_params;
        proxy_pass http://unix:$SCRIPT_DIR/gbot.sock;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Increased timeouts for Mega Upgrade operations (10 minutes)
        proxy_connect_timeout 600s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;
        
        # Additional timeout settings
        proxy_buffering off;
        proxy_request_buffering off;
    }
    
    location /static {
        alias $SCRIPT_DIR/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF

# Apply the new configuration
sudo cp /tmp/gbot_nginx_mega_fix /etc/nginx/sites-available/gbot
rm /tmp/gbot_nginx_mega_fix

# 2. Update systemd service with increased Gunicorn timeout
echo "⚙️ Updating systemd service with increased Gunicorn timeout..."

# Create new systemd service file with 10-minute timeout
sudo tee /etc/systemd/system/gbot.service > /dev/null << EOF
[Unit]
Description=GBot Web Application
After=network.target

[Service]
Type=notify
User=root
Group=root
WorkingDirectory=$SCRIPT_DIR
Environment="PATH=$SCRIPT_DIR/venv/bin"
Environment="FLASK_ENV=production"
ExecStart=$SCRIPT_DIR/venv/bin/gunicorn --workers 2 --bind unix:$SCRIPT_DIR/gbot.sock --access-logfile $SCRIPT_DIR/gunicorn-access.log --error-logfile $SCRIPT_DIR/gunicorn-error.log --timeout 600 app:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Test nginx configuration
echo "🧪 Testing nginx configuration..."
if sudo nginx -t; then
    echo "✅ Nginx configuration test passed"
    
    # Reload nginx
    echo "🔄 Reloading nginx..."
    sudo systemctl reload nginx
    
    # Reload systemd and restart service
    echo "🔄 Reloading systemd and restarting service..."
    sudo systemctl daemon-reload
    sudo systemctl restart gbot
    
    echo "🎉 Mega Upgrade timeout configuration fixed!"
    echo ""
    echo "📊 New timeout settings:"
    echo "  - Nginx proxy timeouts: 600s (10 minutes)"
    echo "  - Gunicorn timeout: 600s (10 minutes)"
    echo ""
    echo "This should eliminate the 504 Gateway Time-out errors during Mega Upgrade operations."
    echo "The Mega Upgrade workflow can now handle longer processing times."
    
else
    echo "❌ Nginx configuration test failed!"
    echo "Restoring backup..."
    sudo cp /etc/nginx/sites-available/gbot.backup.$(date +%Y%m%d_%H%M%S) /etc/nginx/sites-available/gbot
    exit 1
fi

echo ""
echo "✅ Mega Upgrade timeout fix completed!"
echo "🔄 Please restart your application if needed."
