#!/bin/bash

# Complete Virtual Environment Recreation Script
# This will recreate the venv and install all dependencies

set -e

APP_DIR="/opt/gbot-web-app-original-working"
VENV_DIR="$APP_DIR/venv"

echo "🔧 Recreating Virtual Environment"
echo "=================================="
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

# Step 2: Remove old venv if it exists
echo ""
echo "2️⃣ Removing old virtual environment..."
if [ -d "$VENV_DIR" ]; then
    echo "Removing existing venv..."
    rm -rf "$VENV_DIR"
    echo "✅ Old venv removed"
else
    echo "No existing venv found"
fi

# Step 3: Create new virtual environment
echo ""
echo "3️⃣ Creating new virtual environment..."
cd "$APP_DIR"
python3 -m venv venv

if [ ! -d "$VENV_DIR" ]; then
    echo "❌ Failed to create virtual environment"
    exit 1
fi

echo "✅ Virtual environment created"

# Step 4: Activate and upgrade pip
echo ""
echo "4️⃣ Upgrading pip, setuptools, and wheel..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip setuptools wheel
echo "✅ Pip upgraded"

# Step 5: Install all requirements
echo ""
echo "5️⃣ Installing requirements..."
pip install -r requirements.txt
echo "✅ Requirements installed"

# Step 6: Verify critical packages
echo ""
echo "6️⃣ Verifying critical packages..."
if [ -f "$VENV_DIR/bin/gunicorn" ]; then
    echo "✅ Gunicorn installed"
    "$VENV_DIR/bin/gunicorn" --version
else
    echo "❌ Gunicorn not found!"
    exit 1
fi

if python -c "import flask" 2>/dev/null; then
    echo "✅ Flask installed"
else
    echo "❌ Flask not found!"
    exit 1
fi

if python -c "import publicsuffix2" 2>/dev/null; then
    echo "✅ publicsuffix2 installed"
    python -c "import publicsuffix2; print(f'Version: {publicsuffix2.__version__}')"
else
    echo "❌ publicsuffix2 not found!"
    exit 1
fi

deactivate

# Step 7: Check systemd service file
echo ""
echo "7️⃣ Checking systemd service file..."
SERVICE_FILE="/etc/systemd/system/gbot.service"

if [ ! -f "$SERVICE_FILE" ]; then
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
else
    echo "✅ Service file exists"
fi

# Step 8: Set proper permissions
echo ""
echo "8️⃣ Setting permissions..."
chown -R root:root "$VENV_DIR"
chmod -R 755 "$VENV_DIR"
echo "✅ Permissions set"

# Step 9: Reload systemd and start service
echo ""
echo "9️⃣ Reloading systemd and starting service..."
systemctl daemon-reload
systemctl start gbot.service

sleep 3

# Step 10: Check service status
echo ""
echo "🔟 Checking service status..."
if systemctl is-active --quiet gbot.service; then
    echo "✅ Service is running!"
    systemctl status gbot.service --no-pager -l | head -15
else
    echo "❌ Service failed to start"
    echo "Recent logs:"
    journalctl -u gbot.service -n 30 --no-pager
    exit 1
fi

# Step 11: Check socket file
echo ""
echo "1️⃣1️⃣ Checking socket file..."
sleep 3
if [ -S "$APP_DIR/gbot.sock" ]; then
    echo "✅ Socket file created: $APP_DIR/gbot.sock"
    ls -lh "$APP_DIR/gbot.sock"
else
    echo "⚠️  Socket file not found yet (may take a few more seconds)"
    sleep 5
    if [ -S "$APP_DIR/gbot.sock" ]; then
        echo "✅ Socket file created"
    else
        echo "❌ Socket file still not found - check logs"
        journalctl -u gbot.service -n 20 --no-pager
    fi
fi

echo ""
echo "✅ Setup completed!"
echo ""
echo "📋 Verification commands:"
echo "  systemctl status gbot.service"
echo "  journalctl -u gbot.service -f"
echo "  ls -la $APP_DIR/gbot.sock"
echo ""

