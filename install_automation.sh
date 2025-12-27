#!/bin/bash
################################################################################
# GBot Complete Automated Installation Script for Ubuntu 22.04 LTS
# 
# This script performs a COMPLETE installation from a fresh Ubuntu 22 server:
#   - System updates and essential packages
#   - Python 3.10+, pip, and virtual environment
#   - PostgreSQL database installation and configuration
#   - Nginx web server installation and configuration
#   - Chrome/Chromium + ChromeDriver for Selenium automation
#   - AWS CLI installation
#   - Application setup with all dependencies
#   - Systemd service configuration
#   - Firewall (UFW) configuration
#   - Log rotation and backup system
#
# Usage: 
#   chmod +x install_automation.sh
#   sudo ./install_automation.sh
#
# Author: GBot Automation
# Last Updated: 2024
################################################################################

set -e  # Exit on error

# ============================================================================
# Configuration Variables
# ============================================================================
APP_NAME="gbot"
APP_USER="${SUDO_USER:-$USER}"
APP_DIR="/opt/gbot-web-app"
DB_NAME="gbot_db"
DB_USER="gbot_user"
NGINX_SITE="gbot"
SERVICE_NAME="gbot"
LOG_DIR="/var/log/gbot"
PYTHON_MIN_VERSION="3.10"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================================
# Helper Functions
# ============================================================================
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

print_section() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}🔹 $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_banner() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           🚀 GBot Complete Installation Script 🚀             ║${NC}"
    echo -e "${CYAN}║                    Ubuntu 22.04 LTS                            ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "Please run as root or with sudo"
        echo "Usage: sudo ./install_automation.sh"
        exit 1
    fi
}

# Remove stale apt lock files
remove_stale_locks() {
    print_info "Checking for stale lock files..."
    
    for lock_file in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock; do
        if [ -f "$lock_file" ]; then
            if ! lsof "$lock_file" > /dev/null 2>&1; then
                print_warning "Removing stale lock: $lock_file"
                rm -f "$lock_file"
            fi
        fi
    done
    
    # Reconfigure dpkg if needed
    dpkg --configure -a 2>/dev/null || true
}

# Wait for apt lock
wait_for_apt() {
    local max_wait=60
    local wait_time=0
    
    remove_stale_locks
    
    while pgrep -x "apt-get|apt|dpkg|unattended-upgrades" > /dev/null && [ $wait_time -lt $max_wait ]; do
        print_warning "Package manager is busy, waiting... ($wait_time/$max_wait sec)"
        sleep 5
        wait_time=$((wait_time + 5))
    done
    
    if [ $wait_time -ge $max_wait ]; then
        print_error "Timeout waiting for package manager. Please try again later."
        exit 1
    fi
    
    remove_stale_locks
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================

print_banner
check_root

print_info "Installation started at: $(date)"
print_info "Target directory: $APP_DIR"
print_info "Application user: $APP_USER"
echo ""

# ============================================================================
# STEP 1: System Updates and Essential Packages
# ============================================================================
print_section "STEP 1/12: System Updates and Essential Packages"

wait_for_apt

print_info "Updating package lists..."
apt-get update -qq

print_info "Upgrading system packages..."
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq

print_info "Installing essential system packages..."
wait_for_apt
apt-get install -y \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    curl \
    wget \
    git \
    unzip \
    zip \
    jq \
    htop \
    nano \
    vim \
    ufw \
    fail2ban \
    logrotate \
    cron \
    build-essential \
    libssl-dev \
    libffi-dev \
    libpq-dev \
    python3-dev \
    python3-pip \
    python3-venv \
    python3-setuptools \
    python3-wheel \
    lsof

print_success "System packages installed"

# ============================================================================
# STEP 2: Python 3.10+ Setup
# ============================================================================
print_section "STEP 2/12: Python Setup"

PYTHON_VERSION=$(python3 --version 2>/dev/null | cut -d' ' -f2 | cut -d'.' -f1,2 || echo "0")
print_info "Current Python version: $(python3 --version 2>/dev/null || echo 'Not installed')"

if [ "$(printf '%s\n' "$PYTHON_MIN_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$PYTHON_MIN_VERSION" ]; then
    print_warning "Python 3.10+ required. Installing from deadsnakes PPA..."
    wait_for_apt
    add-apt-repository -y ppa:deadsnakes/ppa
    wait_for_apt
    apt-get update -qq
    wait_for_apt
    apt-get install -y python3.10 python3.10-venv python3.10-dev python3.10-distutils
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1
    print_success "Python 3.10 installed"
else
    print_success "Python version is sufficient"
fi

# Upgrade pip
print_info "Upgrading pip..."
python3 -m pip install --upgrade pip setuptools wheel

print_success "Python setup complete"

# ============================================================================
# STEP 3: PostgreSQL Database Installation
# ============================================================================
print_section "STEP 3/12: PostgreSQL Database Installation"

print_info "Installing PostgreSQL..."
wait_for_apt
apt-get install -y postgresql postgresql-contrib

print_info "Starting PostgreSQL service..."
systemctl enable postgresql
systemctl start postgresql

# Generate secure database password
DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")

print_info "Configuring database and user..."

# Create database if not exists
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;"

# Create/update user
if sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname = '$DB_USER'" | grep -q 1; then
    print_info "Updating existing user password..."
    sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"
else
    print_info "Creating database user..."
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"
fi

# Grant privileges
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
sudo -u postgres psql -c "ALTER DATABASE $DB_NAME OWNER TO $DB_USER;"

# Grant schema permissions (PostgreSQL 15+ requirement)
sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL ON SCHEMA public TO $DB_USER;" 2>/dev/null || true

# Grant comprehensive permissions on all existing and future tables/sequences
print_info "Setting up comprehensive database permissions..."
sudo -u postgres psql -d "$DB_NAME" -c "GRANT USAGE, CREATE ON SCHEMA public TO $DB_USER;"
sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_USER;"
sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $DB_USER;"
sudo -u postgres psql -d "$DB_NAME" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $DB_USER;"
sudo -u postgres psql -d "$DB_NAME" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $DB_USER;"

# Transfer ownership of all existing tables to gbot_user (for restored backups)
sudo -u postgres psql -d "$DB_NAME" -c "
DO \$\$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
        EXECUTE 'ALTER TABLE public.' || quote_ident(r.tablename) || ' OWNER TO $DB_USER';
    END LOOP;
END
\$\$;
" 2>/dev/null || true

# Transfer ownership of all sequences
sudo -u postgres psql -d "$DB_NAME" -c "
DO \$\$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'public') LOOP
        EXECUTE 'ALTER SEQUENCE public.' || quote_ident(r.sequence_name) || ' OWNER TO $DB_USER';
    END LOOP;
END
\$\$;
" 2>/dev/null || true

print_success "PostgreSQL configured successfully with comprehensive permissions"

# ============================================================================
# STEP 4: Chrome/Chromium and ChromeDriver Installation
# ============================================================================
print_section "STEP 4/12: Chrome and ChromeDriver Installation"

print_info "Installing Chromium browser and ChromeDriver..."
wait_for_apt
apt-get install -y chromium-browser chromium-chromedriver

# Verify installation
if command -v chromium-browser &> /dev/null; then
    CHROME_VERSION=$(chromium-browser --version 2>/dev/null || echo "Unknown")
    print_success "Chromium installed: $CHROME_VERSION"
else
    print_warning "Chromium not found, trying Google Chrome..."
    wget -q -O /tmp/google-chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
    apt-get install -y /tmp/google-chrome.deb || true
    rm -f /tmp/google-chrome.deb
fi

# ChromeDriver path for selenium
CHROMEDRIVER_PATH=$(which chromedriver 2>/dev/null || echo "/usr/bin/chromedriver")
print_info "ChromeDriver path: $CHROMEDRIVER_PATH"

print_success "Chrome/ChromeDriver setup complete"

# ============================================================================
# STEP 5: AWS CLI Installation
# ============================================================================
print_section "STEP 5/12: AWS CLI Installation"

if command -v aws &> /dev/null; then
    print_info "AWS CLI already installed: $(aws --version)"
else
    print_info "Installing AWS CLI v2..."
    cd /tmp
    curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q -o awscliv2.zip
    ./aws/install --update
    rm -rf awscliv2.zip aws
fi

print_success "AWS CLI installed: $(aws --version 2>/dev/null || echo 'Ready')"

# ============================================================================
# STEP 6: Nginx Web Server Installation
# ============================================================================
print_section "STEP 6/12: Nginx Web Server Installation"

print_info "Installing Nginx..."
wait_for_apt
apt-get install -y nginx

# Remove default site
rm -f /etc/nginx/sites-enabled/default

# Create Nginx configuration
print_info "Creating Nginx configuration..."
cat > /etc/nginx/sites-available/$NGINX_SITE <<'NGINX_EOF'
# Rate limiting zones
limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=upload:10m rate=1r/s;

upstream gbot_app {
    server 127.0.0.1:5000 fail_timeout=0;
    keepalive 32;
}

server {
    listen 80;
    server_name _;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Client settings
    client_max_body_size 500M;
    client_body_buffer_size 128k;
    client_body_timeout 300s;
    client_header_timeout 60s;
    keepalive_timeout 65s;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml;

    # Connection limiting
    limit_conn conn_limit_per_ip 100;

    # Main location
    location / {
        limit_req zone=api burst=100 nodelay;
        
        proxy_pass http://gbot_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }

    # Upload endpoint
    location /api/upload-app-passwords {
        limit_req zone=upload burst=5 nodelay;
        
        proxy_pass http://gbot_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;
        
        proxy_request_buffering off;
        proxy_buffering off;
    }

    # Health check
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    # Block sensitive files
    location ~ /\. { deny all; access_log off; log_not_found off; }
    location ~ \.(env|log|conf)$ { deny all; access_log off; log_not_found off; }
}
NGINX_EOF

# Enable site and test
ln -sf /etc/nginx/sites-available/$NGINX_SITE /etc/nginx/sites-enabled/
nginx -t
systemctl enable nginx
systemctl restart nginx

print_success "Nginx configured and started"

# ============================================================================
# STEP 7: Application Directory Setup
# ============================================================================
print_section "STEP 7/12: Application Directory Setup"

# Create directories
mkdir -p $APP_DIR
mkdir -p $LOG_DIR
mkdir -p $APP_DIR/logs
mkdir -p $APP_DIR/backups
mkdir -p $APP_DIR/instance

# Get the script's directory (where the source files are)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Copy files if not already in APP_DIR
if [ "$SCRIPT_DIR" != "$APP_DIR" ]; then
    print_info "Copying application files from $SCRIPT_DIR to $APP_DIR..."
    cp -r "$SCRIPT_DIR"/* $APP_DIR/ 2>/dev/null || true
    cp "$SCRIPT_DIR"/.env $APP_DIR/ 2>/dev/null || true
    cp "$SCRIPT_DIR"/.gitignore $APP_DIR/ 2>/dev/null || true
fi

# Set ownership
chown -R $APP_USER:$APP_USER $APP_DIR
chown -R $APP_USER:$APP_USER $LOG_DIR

print_success "Application directory setup complete"

# ============================================================================
# STEP 8: Python Virtual Environment and Dependencies
# ============================================================================
print_section "STEP 8/12: Python Virtual Environment and Dependencies"

cd $APP_DIR

# Create virtual environment
print_info "Creating Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate and upgrade pip
print_info "Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip setuptools wheel

# Install requirements
if [ -f requirements.txt ]; then
    pip install -r requirements.txt
else
    print_warning "requirements.txt not found, installing essential packages..."
    pip install \
        Flask==2.3.3 \
        paramiko==3.3.1 \
        google-auth==2.23.3 \
        google-auth-oauthlib==1.1.0 \
        google-api-python-client==2.103.0 \
        faker==19.6.2 \
        psycopg2-binary \
        Flask-SQLAlchemy \
        python-dotenv \
        psutil==5.9.5 \
        gunicorn==21.2.0 \
        requests==2.31.0 \
        pyotp==2.9.0 \
        publicsuffix2==2.20191221 \
        boto3==1.34.0 \
        selenium==4.16.0 \
        webdriver-manager==4.0.1 \
        selenium-stealth==1.0.6 \
        fake-useragent==1.4.0 \
        selenium-wire==5.1.0
fi

# Install additional production packages
pip install gunicorn psutil psycopg2-binary

print_success "Python dependencies installed"

# ============================================================================
# STEP 9: Environment Configuration
# ============================================================================
print_section "STEP 9/12: Environment Configuration"

cd $APP_DIR

# Generate secrets
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
WHITELIST_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(16))")
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}' || echo "127.0.0.1")

ENV_FILE="$APP_DIR/.env"

if [ -f "$ENV_FILE" ]; then
    print_warning ".env file exists. Backing up and updating DATABASE_URL..."
    cp "$ENV_FILE" "$APP_DIR/.env.backup.$(date +%Y%m%d_%H%M%S)"
    sed -i "s|DATABASE_URL=.*|DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@127.0.0.1/$DB_NAME|g" "$ENV_FILE"
else
    print_info "Creating .env file..."
    cat > "$ENV_FILE" <<EOF
# GBot Web Application Environment Configuration
# Generated: $(date)

# Security
SECRET_KEY=$SECRET_KEY
WHITELIST_TOKEN=$WHITELIST_TOKEN

# Database
DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@127.0.0.1/$DB_NAME

# IP Whitelist Configuration
ENABLE_IP_WHITELIST=True
ALLOW_ALL_IPS_IN_DEV=False

# Google API Configuration (fill in your credentials)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Application Settings
DEBUG=False
FLASK_ENV=production
LOG_LEVEL=INFO

# Session Settings
SESSION_COOKIE_SECURE=False
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=3600

# Server Information
SERVER_IP=$SERVER_IP

# Chrome Settings for Selenium
CHROME_BINARY=/usr/bin/chromium-browser
CHROMEDRIVER_PATH=/usr/bin/chromedriver
EOF
fi

chmod 600 "$ENV_FILE"
chown $APP_USER:$APP_USER "$ENV_FILE"

print_success "Environment configuration complete"

# ============================================================================
# STEP 10: Database Initialization
# ============================================================================
print_section "STEP 10/12: Database Initialization"

cd $APP_DIR
source venv/bin/activate

if [ -f migrate_db.py ]; then
    print_info "Running database migration..."
    python3 migrate_db.py || print_warning "Migration may have already been applied"
else
    print_info "Initializing database tables..."
    python3 -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('Database tables created successfully')
" 2>/dev/null || print_warning "Database initialization may need manual attention"
fi

print_success "Database initialization complete"

# ============================================================================
# STEP 11: Systemd Service Configuration
# ============================================================================
print_section "STEP 11/12: Systemd Service Configuration"

# Create gunicorn config if not exists
if [ ! -f "$APP_DIR/gunicorn.conf.py" ]; then
    print_info "Creating gunicorn configuration..."
    cat > "$APP_DIR/gunicorn.conf.py" <<'GUNICORN_EOF'
import multiprocessing
import os

# Server socket
bind = "127.0.0.1:5000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'sync'
worker_connections = 1000
timeout = 300
keepalive = 5
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = '/var/log/gbot/access.log'
errorlog = '/var/log/gbot/error.log'
loglevel = 'info'
capture_output = True

# Process naming
proc_name = 'gbot'

# Server mechanics
daemon = False
pidfile = '/tmp/gbot.pid'
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL (disabled by default)
keyfile = None
certfile = None
GUNICORN_EOF
    chown $APP_USER:$APP_USER "$APP_DIR/gunicorn.conf.py"
fi

# Create systemd service
print_info "Creating systemd service..."
cat > /etc/systemd/system/$SERVICE_NAME.service <<SERVICE_EOF
[Unit]
Description=GBot Web Application
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=notify
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=PATH=$APP_DIR/venv/bin
Environment=FLASK_ENV=production
Environment=PYTHONPATH=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/venv/bin/gunicorn --config gunicorn.conf.py app:app
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=300
PrivateTmp=true
Restart=always
RestartSec=10

LimitNOFILE=524288
LimitNPROC=32768

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$APP_DIR
ReadWritePaths=$LOG_DIR
ReadWritePaths=/tmp

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# Reload and enable
systemctl daemon-reload
systemctl enable $SERVICE_NAME

print_success "Systemd service configured"

# ============================================================================
# STEP 12: Firewall, Log Rotation, and Final Setup
# ============================================================================
print_section "STEP 12/12: Firewall, Log Rotation, and Backup Setup"

# Firewall
print_info "Configuring firewall..."
ufw --force enable
ufw allow 22/tcp comment 'SSH'
ufw allow 'Nginx Full' comment 'HTTP/HTTPS'
ufw allow from 127.0.0.1

# Log rotation
print_info "Configuring log rotation..."
cat > /etc/logrotate.d/$SERVICE_NAME <<LOGROTATE_EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 $APP_USER $APP_USER
    sharedscripts
    postrotate
        systemctl reload $SERVICE_NAME > /dev/null 2>&1 || true
    endscript
}

$APP_DIR/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 $APP_USER $APP_USER
}
LOGROTATE_EOF

# Backup script
print_info "Creating backup script..."
cat > $APP_DIR/backup.sh <<'BACKUP_EOF'
#!/bin/bash
BACKUP_DIR="/opt/gbot-web-app/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup database
sudo -u postgres pg_dump gbot_db | gzip > $BACKUP_DIR/db_$TIMESTAMP.sql.gz

# Backup application
tar -czf $BACKUP_DIR/app_$TIMESTAMP.tar.gz \
    --exclude='venv' \
    --exclude='*.pyc' \
    --exclude='__pycache__' \
    --exclude='logs/*' \
    --exclude='backups/*' \
    /opt/gbot-web-app

# Keep only last 7 days
find $BACKUP_DIR -name "*.gz" -mtime +7 -delete

echo "Backup completed: $BACKUP_DIR/db_$TIMESTAMP.sql.gz"
BACKUP_EOF

chmod +x $APP_DIR/backup.sh
chown $APP_USER:$APP_USER $APP_DIR/backup.sh

# Add backup to crontab (daily at 2 AM)
(crontab -u $APP_USER -l 2>/dev/null | grep -v "backup.sh"; echo "0 2 * * * $APP_DIR/backup.sh >> $LOG_DIR/backup.log 2>&1") | crontab -u $APP_USER -

# Fix permissions script (for use after restoring backups)
print_info "Creating database permission fix script..."
cat > $APP_DIR/fix_permissions.sh <<'FIXPERM_EOF'
#!/bin/bash
#
# Fix database permissions after restoring a backup
# Usage: sudo ./fix_permissions.sh
#
echo "🔧 Fixing database permissions for gbot_user..."

DB_NAME="gbot_db"
DB_USER="gbot_user"

# Grant schema permissions
sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL ON SCHEMA public TO $DB_USER;"
sudo -u postgres psql -d "$DB_NAME" -c "GRANT USAGE, CREATE ON SCHEMA public TO $DB_USER;"
sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_USER;"
sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $DB_USER;"
sudo -u postgres psql -d "$DB_NAME" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $DB_USER;"
sudo -u postgres psql -d "$DB_NAME" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $DB_USER;"

# Transfer ownership of all tables
echo "📋 Transferring table ownership..."
sudo -u postgres psql -d "$DB_NAME" -c "
DO \$\$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
        EXECUTE 'ALTER TABLE public.' || quote_ident(r.tablename) || ' OWNER TO $DB_USER';
        RAISE NOTICE 'Changed owner of table % to $DB_USER', r.tablename;
    END LOOP;
END
\$\$;
"

# Transfer ownership of all sequences
echo "📋 Transferring sequence ownership..."
sudo -u postgres psql -d "$DB_NAME" -c "
DO \$\$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'public') LOOP
        EXECUTE 'ALTER SEQUENCE public.' || quote_ident(r.sequence_name) || ' OWNER TO $DB_USER';
        RAISE NOTICE 'Changed owner of sequence % to $DB_USER', r.sequence_name;
    END LOOP;
END
\$\$;
"

# Verify
echo ""
echo "📊 Current table ownership:"
sudo -u postgres psql -d "$DB_NAME" -c "SELECT tablename, tableowner FROM pg_tables WHERE schemaname = 'public';"

echo ""
echo "✅ Database permissions fixed!"
echo "🔄 Now restart the service: sudo systemctl restart gbot"
FIXPERM_EOF

chmod +x $APP_DIR/fix_permissions.sh
chown $APP_USER:$APP_USER $APP_DIR/fix_permissions.sh

print_success "Firewall, log rotation, backup, and permission fix scripts configured"

# ============================================================================
# Start Services
# ============================================================================
print_section "Starting Services"

print_info "Starting GBot service..."
systemctl start $SERVICE_NAME

# Wait and verify
sleep 3

if systemctl is-active --quiet $SERVICE_NAME; then
    print_success "GBot service started successfully"
else
    print_warning "Service may not have started properly. Checking logs..."
    journalctl -u $SERVICE_NAME -n 20 --no-pager
fi

# ============================================================================
# Installation Complete
# ============================================================================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║             ✅ INSTALLATION COMPLETE! ✅                       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 Installation Summary:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Application Directory: $APP_DIR"
echo "  Environment File:      $APP_DIR/.env"
echo "  Log Directory:         $LOG_DIR"
echo "  Database:              $DB_NAME"
echo "  Database User:         $DB_USER"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🌐 Access Information:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Server IP:     $SERVER_IP"
echo "  HTTP URL:      http://$SERVER_IP"
echo "  Health Check:  http://$SERVER_IP/health"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔑 Generated Secrets (SAVE THESE!):"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  SECRET_KEY:      $SECRET_KEY"
echo "  WHITELIST_TOKEN: $WHITELIST_TOKEN"
echo "  DB_PASSWORD:     $DB_PASSWORD"
echo ""
echo "  Emergency Access: http://$SERVER_IP/emergency_access?key=$WHITELIST_TOKEN"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📝 Useful Commands:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Service Status:    sudo systemctl status $SERVICE_NAME"
echo "  View Logs:         sudo journalctl -u $SERVICE_NAME -f"
echo "  Restart Service:   sudo systemctl restart $SERVICE_NAME"
echo "  Nginx Logs:        sudo tail -f /var/log/nginx/error.log"
echo "  Edit Config:       sudo nano $APP_DIR/.env"
echo "  Run Backup:        sudo $APP_DIR/backup.sh"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔧 Next Steps:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  1. Configure Google OAuth in $APP_DIR/.env"
echo "  2. Configure AWS credentials: aws configure"
echo "  3. Access the application at http://$SERVER_IP"
echo "  4. Optional: Set up SSL with Let's Encrypt:"
echo "     sudo apt install certbot python3-certbot-nginx"
echo "     sudo certbot --nginx -d yourdomain.com"
echo ""

print_success "Installation completed at: $(date)"
echo ""
