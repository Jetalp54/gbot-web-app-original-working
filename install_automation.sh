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
# Added postgresql, postgresql-contrib, ufw, unzip, jq, awscli
sudo apt-get install -y python3-pip python3-venv nginx git libpq-dev build-essential curl postgresql postgresql-contrib ufw unzip jq awscli

# 2. Generate Secrets & Configuration
echo "🔐 Generating secrets and configuration..."
if [ -f .env ]; then
    echo "ℹ️  .env file already exists. Updating DATABASE_URL to force IPv4..."
    # Force update localhost to 127.0.0.1 to avoid IPv6 errors
    sed -i 's/@localhost/@127.0.0.1/g' .env
    # Try to extract DB password from existing .env for DB setup (optional, but good practice)
    # For now, we assume if .env exists, DB is likely set up.
else
    # Generate random secrets using Python
    SECRETS=$(python3 -c "import secrets; print(f'{secrets.token_hex(32)} {secrets.token_hex(16)} {secrets.token_hex(12)}')")
    read -r GEN_SECRET_KEY GEN_WHITELIST_TOKEN GEN_DB_PASSWORD <<< "$SECRETS"

    echo "✅ Generated fresh secrets."

    # Create .env file
    cat > .env <<EOF
# GBot Web Application Environment Configuration
# Generated automatically during installation

SECRET_KEY=$GEN_SECRET_KEY
WHITELIST_TOKEN=$GEN_WHITELIST_TOKEN
DATABASE_URL=postgresql://gbot_user:$GEN_DB_PASSWORD@127.0.0.1/gbot_db

# IP Whitelist Configuration - ENABLED FOR SECURITY
ENABLE_IP_WHITELIST=True
ALLOW_ALL_IPS_IN_DEV=False

# Google API Configuration
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Application Settings
DEBUG=False
FLASK_ENV=production
LOG_LEVEL=INFO

# Production Settings - FIXED FOR HTTP ACCESS
SESSION_COOKIE_SECURE=False
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=3600
EOF
    echo "✅ .env file created."
fi

# 3. Database Setup (PostgreSQL)
echo "🐘 Configuring PostgreSQL..."
# Ensure PostgreSQL is running
sudo systemctl enable postgresql
sudo systemctl start postgresql

# If we generated a password, use it. If not (env exists), we might skip password reset or use a default/extracted one.
# Here we only update the password if we just generated one, to ensure sync.
if [ ! -z "$GEN_DB_PASSWORD" ]; then
    DB_PASS="$GEN_DB_PASSWORD"
else
    # Fallback or skip if we didn't generate one (meaning env existed)
    # We won't force a password change if .env exists to avoid breaking it.
    echo "ℹ️  Using existing database configuration."
fi

# Check if database exists, if not create it
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'gbot_db'" | grep -q 1 || sudo -u postgres psql -c "CREATE DATABASE gbot_db;"

# Check if user exists
if sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname = 'gbot_user'" | grep -q 1; then
    # User exists. If we have a NEW password, update it.
    if [ ! -z "$GEN_DB_PASSWORD" ]; then
        echo "🔄 Updating 'gbot_user' password..."
        sudo -u postgres psql -c "ALTER USER gbot_user WITH PASSWORD '$GEN_DB_PASSWORD';"
    fi
else
    # User doesn't exist. Create with password.
    # If we didn't generate one (env existed but user didn't?), use a default or fail?
    # Let's assume if env exists, we don't touch this unless necessary.
    # But for safety, if we have no password, generate one now just for the DB user (won't match env though).
    # Better: If GEN_DB_PASSWORD is empty, default to 'gbot_password' (legacy) or warn.
    TARGET_PASS="${GEN_DB_PASSWORD:-gbot_password}"
    sudo -u postgres psql -c "CREATE USER gbot_user WITH PASSWORD '$TARGET_PASS';"
fi

# Grant privileges
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE gbot_db TO gbot_user;"
echo "✅ Database 'gbot_db' and user 'gbot_user' configured."

# 4. Directory Setup
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

# 4. Virtual Environment
echo "🐍 Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn psutil psycopg2-binary

# 5. Create Logs Directory
mkdir -p logs

# 6. Nginx Configuration (Optimized)
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

# 7. Systemd Service Configuration (Optimized)
echo "⚙️ Configuring Systemd Services..."
sudo cp gbot_optimized.service /etc/systemd/system/gbot.service
sudo cp gbot-memory-monitor.service /etc/systemd/system/gbot-memory-monitor.service

sudo systemctl daemon-reload
sudo systemctl enable gbot
sudo systemctl enable gbot-memory-monitor

# 8. Start Services
echo "🔄 Starting Services..."
sudo systemctl restart gbot
sudo systemctl restart gbot-memory-monitor

# 9. Run Database Migration
echo "🔄 Running Database Migration..."
python3 migrate_db.py

# 10. Firewall Setup (Whitelist IP / Security)
echo "🛡️ Configuring Firewall (UFW)..."
# Enable UFW if not enabled
sudo ufw --force enable
# Allow SSH (Port 22) - CRITICAL to avoid lockout
sudo ufw allow 22/tcp
# Allow Nginx Full (Port 80/443)
sudo ufw allow 'Nginx Full'
# Example: Whitelist specific IP for admin access (Uncomment and replace IP to use)
# sudo ufw allow from 1.2.3.4 to any port 22
echo "✅ Firewall configured. SSH (22) and HTTP/HTTPS (80/443) allowed."

# 10. Final Check
echo "📊 Checking Service Status..."
sudo systemctl status gbot --no-pager
echo ""
echo "✅ Installation Complete!"
echo "   App should be accessible at http://$(curl -s ifconfig.me)"
echo "   Monitor logs: sudo journalctl -u gbot -f"

if [ ! -z "$GEN_WHITELIST_TOKEN" ]; then
    echo ""
    echo "🔑 GENERATED SECRETS (SAVE THESE!):"
    echo "   SECRET_KEY: $GEN_SECRET_KEY"
    echo "   WHITELIST_TOKEN: $GEN_WHITELIST_TOKEN"
    echo "   Emergency URL: http://$(curl -s ifconfig.me)/emergency_access?key=$GEN_WHITELIST_TOKEN"
fi
