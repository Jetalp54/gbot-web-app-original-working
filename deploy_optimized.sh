#!/bin/bash
# Deploy optimized configuration for 4 vCPU, 16GB RAM server

echo "🚀 Deploying optimized GBot configuration for high-end server..."

# Stop services
echo "⏹️ Stopping services..."
sudo systemctl stop gbot
sudo systemctl stop gbot-memory-monitor 2>/dev/null || true

# Update code
echo "📥 Pulling latest code..."
cd "$(dirname "$0")"
git pull

# Install dependencies
echo "📦 Installing dependencies..."
source venv/bin/activate
pip install psutil

# Create logs directory
echo "📁 Creating logs directory..."
mkdir -p logs

# Deploy optimized configurations
echo "⚙️ Deploying optimized configurations..."

# Update Gunicorn service
sudo cp gbot_optimized.service /etc/systemd/system/gbot.service

# Update Nginx configuration
sudo cp nginx_gbot_optimized.conf /etc/nginx/sites-available/gbot
sudo nginx -t
if [ $? -eq 0 ]; then
    sudo systemctl reload nginx
    echo "✅ Nginx configuration updated"
else
    echo "❌ Nginx configuration error"
    exit 1
fi

# Install memory monitor service
sudo cp gbot-memory-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable gbot-memory-monitor

# Start services
echo "🔄 Starting services..."
sudo systemctl start gbot
sudo systemctl start gbot-memory-monitor

# Check status
echo "📊 Checking service status..."
sudo systemctl status gbot --no-pager
sudo systemctl status gbot-memory-monitor --no-pager

echo "✅ Deployment complete!"
echo ""
echo "📈 Optimizations applied:"
echo "  • 8 Gunicorn workers (2x CPU cores)"
echo "  • 2000 connections per worker"
echo "  • 50 database connections + 100 overflow"
echo "  • 5x higher rate limits"
echo "  • Memory monitoring with auto-restart"
echo "  • Optimized timeouts and limits"
echo ""
echo "🔍 Monitor with:"
echo "  sudo journalctl -u gbot -f"
echo "  sudo journalctl -u gbot-memory-monitor -f"
echo "  python monitor_performance.py"
