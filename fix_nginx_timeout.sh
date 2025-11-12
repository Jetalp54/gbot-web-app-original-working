#!/bin/bash

# Fix nginx timeout configuration for GBot
# This script increases nginx proxy timeouts to prevent 504 errors during long operations

echo "🔧 Fixing nginx timeout configuration..."

# Backup current configuration
sudo cp /etc/nginx/sites-available/gbot /etc/nginx/sites-available/gbot.backup.$(date +%Y%m%d_%H%M%S)

# Get the current script directory (where gbot is installed)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create new nginx configuration with increased timeouts
cat > /tmp/gbot_nginx_fixed << EOF
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
        
        # Increased timeouts to prevent 504 errors during bulk operations (10 minutes)
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
sudo cp /tmp/gbot_nginx_fixed /etc/nginx/sites-available/gbot
rm /tmp/gbot_nginx_fixed

# Test nginx configuration
echo "🧪 Testing nginx configuration..."
if sudo nginx -t; then
    echo "✅ Nginx configuration test passed"
    
    # Reload nginx
    echo "🔄 Reloading nginx..."
    sudo systemctl reload nginx
    
    echo "🎉 Nginx timeout configuration fixed!"
    echo ""
    echo "📊 New timeout settings:"
    echo "  - proxy_connect_timeout: 120s (was 30s)"
    echo "  - proxy_send_timeout: 120s (was 30s)" 
    echo "  - proxy_read_timeout: 120s (was 30s)"
    echo ""
    echo "This should eliminate the 504 'Server returned HTML instead of JSON' errors"
    echo "during bulk domain changes and password updates."
    
else
    echo "❌ Nginx configuration test failed!"
    echo "Restoring backup..."
    sudo cp /etc/nginx/sites-available/gbot.backup.$(date +%Y%m%d_%H%M%S) /etc/nginx/sites-available/gbot
    exit 1
fi
