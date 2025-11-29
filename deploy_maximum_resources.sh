#!/bin/bash

# Deploy GBot Web App with MAXIMUM resource utilization
# 4 vCPU, 16GB RAM server - PUSH TO THE LIMIT

set -e

echo "🚀 Deploying GBot Web App with MAXIMUM resource utilization..."
echo "Server specs: 4 vCPU, 16GB RAM"
echo "================================================"

# Navigate to the application directory (current directory)
cd "$(dirname "$0")"

# 1. Pull the latest code
echo "📥 Pulling latest code from Git..."
git pull

# 2. Install Python dependencies
echo "📦 Installing/updating Python dependencies..."
source venv/bin/activate
pip install -r requirements.txt
deactivate

# 3. Update to maximum Gunicorn configuration
echo "⚡ Updating to MAXIMUM Gunicorn configuration..."
sudo cp gunicorn_maximum.conf.py "$(pwd)/gunicorn.conf.py"

# 4. Update Nginx configuration for maximum load
echo "🌐 Updating Nginx for maximum load..."
sudo cp nginx_gbot_fixed.conf /etc/nginx/sites-available/gbot
sudo ln -sf /etc/nginx/sites-available/gbot /etc/nginx/sites-enabled/gbot

# 5. Update Nginx main config for maximum connections
echo "🔧 Updating Nginx main configuration..."
sudo tee -a /etc/nginx/nginx.conf > /dev/null << 'EOF'

# Maximum performance settings
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 8192;
    use epoll;
    multi_accept on;
}

http {
    # Maximum buffer sizes
    client_body_buffer_size 256k;
    client_header_buffer_size 4k;
    large_client_header_buffers 8 8k;
    
    # Maximum timeouts
    client_body_timeout 120s;
    client_header_timeout 120s;
    keepalive_timeout 120s;
    keepalive_requests 10000;
    
    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=api:10m rate=1000r/s;
    limit_req_zone $binary_remote_addr zone=upload:10m rate=100r/s;
    limit_req_zone $binary_remote_addr zone=mega:10m rate=1r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
}
EOF

# 6. Test Nginx configuration
echo "🧪 Testing Nginx configuration..."
sudo nginx -t

# 7. Update to maximum Systemd service
echo "⚙️ Updating to MAXIMUM Systemd service..."
sudo cp gbot_maximum.service /etc/systemd/system/gbot.service

# 8. Reload systemd daemon
echo "🔄 Reloading Systemd daemon..."
sudo systemctl daemon-reload

# 9. Stop current services
echo "⏹️ Stopping current services..."
sudo systemctl stop gbot || true
sudo systemctl stop gbot-memory-monitor || true

# 10. Start with maximum configuration
echo "🚀 Starting with MAXIMUM configuration..."
sudo systemctl start gbot

# 11. Enable and start memory monitor
echo "📊 Starting memory monitor..."
sudo systemctl enable gbot-memory-monitor
sudo systemctl start gbot-memory-monitor

# 12. Reload Nginx
echo "🔄 Reloading Nginx..."
sudo systemctl reload nginx

# 13. Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# 14. Check service status
echo "📊 Checking service status..."
echo "GBot service:"
sudo systemctl status gbot --no-pager -l
echo ""
echo "Memory monitor:"
sudo systemctl status gbot-memory-monitor --no-pager -l
echo ""
echo "Nginx:"
sudo systemctl status nginx --no-pager -l

# 15. Run resource check
echo "🔍 Running resource usage check..."
python3 check_resource_usage.py

echo ""
echo "✅ MAXIMUM resource deployment complete!"
echo ""
echo "📈 Current configuration:"
echo "  - Gunicorn workers: 16 (4x CPU cores)"
echo "  - Worker connections: 5000 each"
echo "  - Database pool: 100 + 200 overflow"
echo "  - Nginx worker connections: 8192"
echo "  - System limits: 262k files, 16k processes"
echo ""
echo "🔍 Monitor with:"
echo "  - sudo journalctl -u gbot -f"
echo "  - python3 check_resource_usage.py"
echo "  - htop"
echo "  - sudo netstat -tulpn | grep :5000"
