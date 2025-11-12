#!/bin/bash

# Fix Nginx HTTP 413 "Request Entity Too Large" Error
# This script increases nginx client_max_body_size to allow larger file uploads

echo "🔧 Fixing Nginx HTTP 413 Upload Size Error..."

# Backup current nginx configuration
echo "📋 Backing up current nginx configuration..."
sudo cp /etc/nginx/sites-available/gbot /etc/nginx/sites-available/gbot.backup.$(date +%Y%m%d_%H%M%S)

# Check if gbot configuration exists
if [ ! -f "/etc/nginx/sites-available/gbot" ]; then
    echo "❌ Error: /etc/nginx/sites-available/gbot not found!"
    echo "Please make sure nginx is properly configured for GBot."
    exit 1
fi

# Create new configuration with increased upload size
echo "📝 Creating new nginx configuration with increased upload limits..."

sudo tee /etc/nginx/sites-available/gbot > /dev/null << 'EOF'
server {
    listen 80;
    server_name _;
    
    # Increase client max body size to allow large file uploads
    client_max_body_size 1G;
    
    location / {
        include proxy_params;
        proxy_pass http://unix:/home/gbot/gbot/gbot.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Increased timeouts to prevent 504 errors
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
        
        # Additional settings for large uploads
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_max_temp_file_size 0;
    }
    
    location /static {
        alias /home/gbot/gbot/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF

# Test nginx configuration
echo "🧪 Testing nginx configuration..."
if sudo nginx -t; then
    echo "✅ Nginx configuration test passed!"
    
    # Reload nginx
    echo "🔄 Reloading nginx..."
    sudo systemctl reload nginx
    
    if [ $? -eq 0 ]; then
        echo "✅ Nginx reloaded successfully!"
        echo ""
        echo "🎉 Fix applied successfully!"
        echo ""
        echo "📋 What was changed:"
        echo "   - client_max_body_size increased to 1G"
        echo "   - proxy timeouts increased to 120s"
        echo "   - proxy buffering disabled for large uploads"
        echo ""
        echo "🚀 You can now upload backup files up to 1GB!"
        echo "   Try uploading your backup file again."
    else
        echo "❌ Failed to reload nginx!"
        echo "Restoring backup configuration..."
        sudo cp /etc/nginx/sites-available/gbot.backup.* /etc/nginx/sites-available/gbot
        exit 1
    fi
else
    echo "❌ Nginx configuration test failed!"
    echo "Restoring backup configuration..."
    sudo cp /etc/nginx/sites-available/gbot.backup.* /etc/nginx/sites-available/gbot
    exit 1
fi
