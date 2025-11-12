#!/bin/bash

# Fix Gunicorn Installation Script
# This script fixes the 502 error by ensuring gunicorn is properly installed

set -e

APP_DIR="/opt/gbot-web-app-original-working"
VENV_DIR="$APP_DIR/venv"

echo "🔧 Fixing Gunicorn Installation"
echo "================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Step 1: Stop the service
echo "1️⃣ Stopping gbot service..."
systemctl stop gbot.service || true
sleep 2

# Step 2: Check if venv exists
echo ""
echo "2️⃣ Checking virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    echo "❌ Virtual environment not found at $VENV_DIR"
    echo "Creating virtual environment..."
    cd "$APP_DIR"
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment exists"
fi

# Step 3: Activate venv and install/upgrade dependencies
echo ""
echo "3️⃣ Installing/upgrading dependencies..."
cd "$APP_DIR"
source venv/bin/activate

# Upgrade pip first
pip install --upgrade pip setuptools wheel

# Install all requirements including gunicorn
echo "Installing requirements from requirements.txt..."
pip install -r requirements.txt

# Verify gunicorn installation
if [ -f "$VENV_DIR/bin/gunicorn" ]; then
    echo "✅ Gunicorn installed successfully"
    gunicorn --version
else
    echo "❌ Gunicorn installation failed"
    exit 1
fi

deactivate

# Step 4: Check and update systemd service file
echo ""
echo "4️⃣ Checking systemd service file..."
SERVICE_FILE="/etc/systemd/system/gbot.service"

if [ -f "$SERVICE_FILE" ]; then
    echo "Service file exists, checking path..."
    
    # Check if the path in service file matches actual path
    if grep -q "$APP_DIR" "$SERVICE_FILE"; then
        echo "✅ Service file path is correct"
    else
        echo "⚠️  Service file path may need updating"
        echo "Current service file content:"
        cat "$SERVICE_FILE"
    fi
else
    echo "⚠️  Service file not found, creating it..."
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=GBot Web Application
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$APP_DIR
Environment="PATH=$VENV_DIR/bin"
Environment="FLASK_ENV=production"
ExecStart=$VENV_DIR/bin/gunicorn --workers 2 --bind unix:$APP_DIR/gbot.sock --access-logfile $APP_DIR/gunicorn-access.log --error-logfile $APP_DIR/gunicorn-error.log --timeout 600 app:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    echo "✅ Service file created"
fi

# Step 5: Reload systemd and restart service
echo ""
echo "5️⃣ Reloading systemd daemon..."
systemctl daemon-reload

echo ""
echo "6️⃣ Starting gbot service..."
systemctl start gbot.service

sleep 3

# Step 7: Check service status
echo ""
echo "7️⃣ Checking service status..."
if systemctl is-active --quiet gbot.service; then
    echo "✅ Service is running"
    systemctl status gbot.service --no-pager -l
else
    echo "❌ Service failed to start"
    echo "Recent logs:"
    journalctl -u gbot.service -n 20 --no-pager
    exit 1
fi

# Step 8: Check if socket file exists
echo ""
echo "8️⃣ Checking socket file..."
sleep 2
if [ -S "$APP_DIR/gbot.sock" ]; then
    echo "✅ Socket file created: $APP_DIR/gbot.sock"
    ls -lh "$APP_DIR/gbot.sock"
else
    echo "⚠️  Socket file not found yet (may take a few seconds)"
    echo "Waiting 5 more seconds..."
    sleep 5
    if [ -S "$APP_DIR/gbot.sock" ]; then
        echo "✅ Socket file created"
    else
        echo "❌ Socket file still not found"
        echo "Check logs: journalctl -u gbot.service -f"
    fi
fi

echo ""
echo "✅ Fix completed!"
echo ""
echo "📋 Next steps:"
echo "  1. Check service: systemctl status gbot.service"
echo "  2. Check logs: journalctl -u gbot.service -f"
echo "  3. Test in browser: http://your-server-ip/dashboard"
echo ""

