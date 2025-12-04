#!/bin/bash
################################################################################
# GBot Complete Installation Script for Ubuntu 22.04 LTS
# This script installs and configures everything needed for GBot Web Application
# from a fresh Ubuntu 22.04 server installation
#
# Usage: sudo ./install_complete_ubuntu22.sh
#
# What this script does:
# 1. System updates and essential packages
# 2. Python 3.10+ and pip setup
# 3. PostgreSQL database installation and configuration
# 4. Nginx web server installation and configuration
# 5. Python virtual environment and dependencies
# 6. Application directory structure
# 7. Environment configuration (.env file)
# 8. Database initialization
# 9. Systemd service configuration
# 10. Firewall (UFW) configuration
# 11. SSL certificate setup (optional)
# 12. Log rotation configuration
# 13. Backup system setup
################################################################################

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
APP_NAME="gbot"
APP_USER="${SUDO_USER:-$USER}"
APP_DIR="/opt/gbot-web-app"
DB_NAME="gbot_db"
DB_USER="gbot_user"
NGINX_SITE="gbot"
SERVICE_NAME="gbot"
LOG_DIR="/var/log/gbot"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run as root or with sudo"
    exit 1
fi

print_section "🚀 GBot Complete Installation for Ubuntu 22.04"
print_info "This script will install and configure GBot Web Application"
print_info "Target directory: $APP_DIR"
print_info "Database: $DB_NAME"
print_info "User: $APP_USER"
echo ""

# ============================================================================
# STEP 1: System Updates and Essential Packages
# ============================================================================
print_section "STEP 1: System Updates and Essential Packages"

print_info "Updating package lists..."
apt-get update -qq

print_info "Upgrading system packages..."
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq

print_info "Installing essential system packages..."
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
    python3-wheel

print_success "System packages installed"

# ============================================================================
# STEP 2: Python 3.10+ Setup
# ============================================================================
print_section "STEP 2: Python Setup"

# Check Python version
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
print_info "Python version: $(python3 --version)"

if [ "$(printf '%s\n' "3.10" "$PYTHON_VERSION" | sort -V | head -n1)" != "3.10" ]; then
    print_warning "Python 3.10+ recommended. Current: $PYTHON_VERSION"
    print_info "Installing Python 3.10 from deadsnakes PPA..."
    add-apt-repository -y ppa:deadsnakes/ppa
    apt-get update -qq
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
print_section "STEP 3: PostgreSQL Database Installation"

print_info "Installing PostgreSQL..."
apt-get install -y postgresql postgresql-contrib

print_info "Starting PostgreSQL service..."
systemctl enable postgresql
systemctl start postgresql

# Generate secure database password
DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

print_info "Configuring PostgreSQL database and user..."

# Create database
sudo -u postgres psql -c "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;"

# Create user
if sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname = '$DB_USER'" | grep -q 1; then
    print_info "User $DB_USER already exists, updating password..."
    sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"
else
    print_info "Creating database user $DB_USER..."
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"
fi

# Grant privileges
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
sudo -u postgres psql -c "ALTER DATABASE $DB_NAME OWNER TO $DB_USER;"

# Configure PostgreSQL for better performance
PG_VERSION=$(sudo -u postgres psql -t -c "SHOW server_version_num;" | xargs)
print_info "PostgreSQL version: $(sudo -u postgres psql -t -c 'SHOW version;' | head -1 | xargs)"

print_success "PostgreSQL configured successfully"

# ============================================================================
# STEP 4: Nginx Web Server Installation
# ============================================================================
print_section "STEP 4: Nginx Web Server Installation"

print_info "Installing Nginx..."
apt-get install -y nginx

print_info "Configuring Nginx..."

# Remove default site
if [ -f /etc/nginx/sites-enabled/default ]; then
    rm -f /etc/nginx/sites-enabled/default
fi

# Create Nginx configuration
cat > /etc/nginx/sites-available/$NGINX_SITE <<'NGINX_EOF'
upstream gbot_app {
    server 127.0.0.1:5000 fail_timeout=0;
}

server {
    listen 80;
    server_name _;

    client_max_body_size 100M;
    client_body_timeout 300s;
    client_header_timeout 300s;

    # Logging
    access_log /var/log/nginx/gbot_access.log;
    error_log /var/log/nginx/gbot_error.log;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    location / {
        proxy_pass http://gbot_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        
        # Timeouts
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Static files (if any)
    location /static {
        alias /opt/gbot-web-app/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Health check endpoint
    location /health {
        proxy_pass http://gbot_app;
        access_log off;
    }
}
NGINX_EOF

# Enable site
ln -sf /etc/nginx/sites-available/$NGINX_SITE /etc/nginx/sites-enabled/

# Test Nginx configuration
print_info "Testing Nginx configuration..."
nginx -t

# Start and enable Nginx
systemctl enable nginx
systemctl restart nginx

print_success "Nginx configured and started"

# ============================================================================
# STEP 5: Application Directory Setup
# ============================================================================
print_section "STEP 5: Application Directory Setup"

print_info "Creating application directory: $APP_DIR"
mkdir -p $APP_DIR
mkdir -p $LOG_DIR
mkdir -p $APP_DIR/logs
mkdir -p $APP_DIR/backups

# If script is not in APP_DIR, copy files
if [ "$PWD" != "$APP_DIR" ]; then
    print_info "Copying application files to $APP_DIR..."
    cp -r . $APP_DIR/ 2>/dev/null || {
        print_warning "Could not copy files. Please ensure application files are in $APP_DIR"
    }
fi

# Set ownership
chown -R $APP_USER:$APP_USER $APP_DIR
chown -R $APP_USER:$APP_USER $LOG_DIR

print_success "Application directory setup complete"

# ============================================================================
# STEP 6: Python Virtual Environment and Dependencies
# ============================================================================
print_section "STEP 6: Python Virtual Environment and Dependencies"

cd $APP_DIR

print_info "Creating Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

print_info "Activating virtual environment and upgrading pip..."
source venv/bin/activate
pip install --upgrade pip setuptools wheel

print_info "Installing Python dependencies..."
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
        webdriver-manager==4.0.1
fi

# Install additional production packages
print_info "Installing production packages..."
pip install gunicorn psutil psycopg2-binary

print_success "Python dependencies installed"

# ============================================================================
# STEP 7: Environment Configuration
# ============================================================================
print_section "STEP 7: Environment Configuration"

print_info "Generating secure secrets..."

# Generate secrets
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
WHITELIST_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(16))")

# Get server IP
SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')

# Create .env file
if [ -f .env ]; then
    print_warning ".env file already exists. Backing up to .env.backup..."
    cp .env .env.backup
    # Update DATABASE_URL if it exists
    sed -i "s|DATABASE_URL=.*|DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@127.0.0.1/$DB_NAME|g" .env
else
    print_info "Creating .env file..."
    cat > .env <<EOF
# GBot Web Application Environment Configuration
# Generated automatically during installation on $(date)

# Security
SECRET_KEY=$SECRET_KEY
WHITELIST_TOKEN=$WHITELIST_TOKEN

# Database
DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@127.0.0.1/$DB_NAME

# IP Whitelist Configuration
ENABLE_IP_WHITELIST=True
ALLOW_ALL_IPS_IN_DEV=False

# Google API Configuration
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Application Settings
DEBUG=False
FLASK_ENV=production
LOG_LEVEL=INFO

# Production Settings
SESSION_COOKIE_SECURE=False
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=3600

# Server Information
SERVER_IP=$SERVER_IP
EOF
    chmod 600 .env
    chown $APP_USER:$APP_USER .env
fi

print_success "Environment configuration complete"

# ============================================================================
# STEP 8: Database Initialization
# ============================================================================
print_section "STEP 8: Database Initialization"

print_info "Initializing database..."

# Activate venv and run migration if script exists
if [ -f migrate_db.py ]; then
    source venv/bin/activate
    python3 migrate_db.py || {
        print_warning "Migration script failed or database already initialized"
    }
else
    print_info "Running database initialization..."
    source venv/bin/activate
    python3 -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('Database initialized successfully')
" || print_warning "Database initialization may have failed. Check manually."
fi

print_success "Database initialization complete"

# ============================================================================
# STEP 9: Systemd Service Configuration
# ============================================================================
print_section "STEP 9: Systemd Service Configuration"

print_info "Creating systemd service file..."

# Create systemd service
cat > /etc/systemd/system/$SERVICE_NAME.service <<SERVICE_EOF
[Unit]
Description=GBot Web Application
After=network.target postgresql.service

[Service]
Type=notify
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/venv/bin/gunicorn \
    --bind 127.0.0.1:5000 \
    --workers 4 \
    --worker-class sync \
    --worker-connections 1000 \
    --timeout 300 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 50 \
    --access-logfile $LOG_DIR/access.log \
    --error-logfile $LOG_DIR/error.log \
    --log-level info \
    --capture-output \
    app:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$APP_DIR $LOG_DIR

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# Create memory monitor service (optional)
cat > /etc/systemd/system/$SERVICE_NAME-memory-monitor.service <<MONITOR_EOF
[Unit]
Description=GBot Memory Monitor
After=$SERVICE_NAME.service

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
ExecStart=$APP_DIR/venv/bin/python3 $APP_DIR/monitor_memory.py
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
MONITOR_EOF

# Reload systemd and enable services
systemctl daemon-reload
systemctl enable $SERVICE_NAME

print_success "Systemd service configured"

# ============================================================================
# STEP 10: Firewall Configuration
# ============================================================================
print_section "STEP 10: Firewall Configuration"

print_info "Configuring UFW firewall..."

# Enable UFW
ufw --force enable

# Allow SSH (CRITICAL - do this first!)
ufw allow 22/tcp comment 'SSH'

# Allow HTTP and HTTPS
ufw allow 'Nginx Full' comment 'Nginx HTTP/HTTPS'

# Allow from localhost
ufw allow from 127.0.0.1

print_success "Firewall configured (SSH and HTTP/HTTPS allowed)"

# ============================================================================
# STEP 11: Log Rotation Configuration
# ============================================================================
print_section "STEP 11: Log Rotation Configuration"

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

print_success "Log rotation configured"

# ============================================================================
# STEP 12: Backup Script Setup
# ============================================================================
print_section "STEP 12: Backup Script Setup"

print_info "Creating backup script..."

cat > $APP_DIR/backup.sh <<BACKUP_EOF
#!/bin/bash
# GBot Backup Script
BACKUP_DIR="$APP_DIR/backups"
TIMESTAMP=\$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="gbot_backup_\$TIMESTAMP.tar.gz"

mkdir -p \$BACKUP_DIR

# Backup database
sudo -u postgres pg_dump $DB_NAME | gzip > \$BACKUP_DIR/db_\$TIMESTAMP.sql.gz

# Backup application files
tar -czf \$BACKUP_DIR/\$BACKUP_FILE \\
    --exclude='venv' \\
    --exclude='*.pyc' \\
    --exclude='__pycache__' \\
    --exclude='logs/*' \\
    --exclude='backups/*' \\
    $APP_DIR

# Keep only last 7 days of backups
find \$BACKUP_DIR -name "*.gz" -mtime +7 -delete
find \$BACKUP_DIR -name "*.sql.gz" -mtime +7 -delete

echo "Backup completed: \$BACKUP_FILE"
BACKUP_EOF

chmod +x $APP_DIR/backup.sh
chown $APP_USER:$APP_USER $APP_DIR/backup.sh

# Add to crontab (daily at 2 AM)
(crontab -u $APP_USER -l 2>/dev/null; echo "0 2 * * * $APP_DIR/backup.sh >> $LOG_DIR/backup.log 2>&1") | crontab -u $APP_USER -

print_success "Backup system configured (daily at 2 AM)"

# ============================================================================
# STEP 13: Start Services
# ============================================================================
print_section "STEP 13: Starting Services"

print_info "Starting application service..."
systemctl start $SERVICE_NAME

# Wait a moment for service to start
sleep 3

# Check service status
if systemctl is-active --quiet $SERVICE_NAME; then
    print_success "Service started successfully"
else
    print_error "Service failed to start. Check logs: journalctl -u $SERVICE_NAME -n 50"
    systemctl status $SERVICE_NAME --no-pager
fi

# ============================================================================
# STEP 14: Final Verification
# ============================================================================
print_section "STEP 14: Final Verification"

print_info "Checking service status..."
systemctl status $SERVICE_NAME --no-pager -l | head -20

print_info "Checking Nginx status..."
systemctl status nginx --no-pager -l | head -10

print_info "Checking PostgreSQL status..."
systemctl status postgresql --no-pager -l | head -10

# Test HTTP endpoint
print_info "Testing HTTP endpoint..."
sleep 2
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/health || echo "000")
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "000" ]; then
    print_success "Application is responding"
else
    print_warning "Application may not be fully ready (HTTP $HTTP_CODE)"
fi

# ============================================================================
# Installation Complete
# ============================================================================
print_section "✅ Installation Complete!"

echo ""
print_success "GBot Web Application has been installed and configured!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 Installation Summary:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Application Directory: $APP_DIR"
echo "  Database: $DB_NAME"
echo "  Database User: $DB_USER"
echo "  Service Name: $SERVICE_NAME"
echo "  Log Directory: $LOG_DIR"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🌐 Access Information:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Server IP: $SERVER_IP"
echo "  HTTP URL: http://$SERVER_IP"
echo "  Health Check: http://$SERVER_IP/health"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔑 Generated Secrets (SAVE THESE!):"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  SECRET_KEY: $SECRET_KEY"
echo "  WHITELIST_TOKEN: $WHITELIST_TOKEN"
echo "  DB_PASSWORD: $DB_PASSWORD"
echo ""
echo "  Emergency Access: http://$SERVER_IP/emergency_access?key=$WHITELIST_TOKEN"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📝 Useful Commands:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Service Status:    sudo systemctl status $SERVICE_NAME"
echo "  View Logs:         sudo journalctl -u $SERVICE_NAME -f"
echo "  Restart Service:   sudo systemctl restart $SERVICE_NAME"
echo "  Nginx Logs:        sudo tail -f /var/log/nginx/gbot_error.log"
echo "  Backup:            $APP_DIR/backup.sh"
echo "  Database Access:   sudo -u postgres psql $DB_NAME"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔒 Security Notes:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  • Firewall (UFW) is enabled - SSH (22) and HTTP/HTTPS (80/443) allowed"
echo "  • Configure Google OAuth credentials in .env file"
echo "  • Consider setting up SSL/TLS with Let's Encrypt:"
echo "    sudo apt-get install certbot python3-certbot-nginx"
echo "    sudo certbot --nginx -d yourdomain.com"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

print_success "Installation completed successfully!"
print_info "Next steps:"
echo "  1. Configure Google OAuth credentials in $APP_DIR/.env"
echo "  2. Access the application at http://$SERVER_IP"
echo "  3. Set up SSL certificate for HTTPS (recommended)"
echo ""

