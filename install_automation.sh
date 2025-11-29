#!/bin/bash
# Gbot Automation Installation Script
# Installs and configures the Gbot Web App on a fresh Ubuntu server

# Exit on error
set -e

echo "🚀 Starting Gbot Automation Installation..."

# 1. System Updates & Dependencies
echo "📦 Updating system and installing dependencies..."
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y python3-pip python3-venv nginx git libpq-dev build-essential curl

# 2. Directory Setup
APP_DIR="/opt/gbot-web-app"
echo "📂 Setting up application directory at $APP_DIR..."

# If directory doesn't exist, we assume we are running this script FROM the repo
# or we need to clone it. For now, let's assume the script is inside the repo
# and we are running it from there.
if [ "$PWD" != "$APP_DIR" ]; then
    echo "⚠️  Note: Script is running from $PWD, but target dir is $APP_DIR"
    echo "   Moving files to $APP_DIR..."
    sudo mkdir -p $APP_DIR
    sudo cp -r . $APP_DIR/
    sudo chown -R $USER:$USER $APP_DIR
    cd $APP_DIR
fi

# 3. Virtual Environment
echo "🐍 Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn psutil

# 4. Create Logs Directory
mkdir -p logs

# 5. Nginx Configuration (Optimized)
echo "🌐 Configuring Nginx..."
# Remove default if exists
if [ -f /etc/nginx/sites-enabled/default ]; then
    sudo rm /etc/nginx/sites-enabled/default
fi

# Copy optimized config
sudo cp nginx_gbot_optimized.conf /etc/nginx/sites-available/gbot
# Link it
sudo ln -sf /etc/nginx/sites-available/gbot /etc/nginx/sites-enabled/
# Test config
sudo nginx -t
sudo systemctl reload nginx

# 6. Systemd Service Configuration (Optimized)
echo "⚙️ Configuring Systemd Services..."
sudo cp gbot_optimized.service /etc/systemd/system/gbot.service
sudo cp gbot-memory-monitor.service /etc/systemd/system/gbot-memory-monitor.service

sudo systemctl daemon-reload
sudo systemctl enable gbot
sudo systemctl enable gbot-memory-monitor

# 7. Start Services
echo "🔄 Starting Services..."
sudo systemctl restart gbot
sudo systemctl restart gbot-memory-monitor

# 8. Firewall Setup
echo "🛡️ Configuring Firewall..."
sudo ufw allow 'Nginx Full'
# sudo ufw allow ssh # Ensure SSH is allowed if UFW is enabled

# 9. Final Check
echo "📊 Checking Service Status..."
sudo systemctl status gbot --no-pager
echo ""
echo "✅ Installation Complete!"
echo "   App should be accessible at http://$(curl -s ifconfig.me)"
echo "   Monitor logs: sudo journalctl -u gbot -f"
