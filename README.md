# GBot Web Application

A comprehensive Google Workspace administration and automation platform designed to streamline the management of Google Workspace domains, users, and administrative tasks through a web-based interface.

## 🚀 Features

- **Google Workspace Domain Management**: Add, remove, and manage domain aliases
- **User Account Management**: Create and manage GSuite user accounts
- **Bulk Operations**: Handle large-scale domain and user changes
- **OAuth 2.0 Integration**: Secure Google API authentication
- **Multi-Account Support**: Manage multiple Google Workspace accounts
- **Role-Based Access Control**: Admin and support user roles
- **IP Whitelisting**: Enhanced security with IP-based access control

## 📋 System Requirements

- **Operating System**: Ubuntu 18.04 LTS or later
- **Python**: Python 3.8 or higher
- **Memory**: Minimum 512MB RAM (1GB recommended)
- **Disk Space**: Minimum 1GB free space
- **Internet**: Required for package installation and Google API access

## 🛠️ Installation

### Option 1: Complete Automated Installation (Recommended)

#### Quick Start
```bash
# Clone the repository
git clone <repository-url>
cd gbot-web-app

# Make script executable
chmod +x setup_complete.sh

# Run complete installation
./setup_complete.sh --install
```

#### Installation Modes

**Complete Installation (Production Ready)**
```bash
./setup_complete.sh --install
```

**Force Reinstall Everything**
```bash
./setup_complete.sh --reinstall
```

**Validate Existing Installation**
```bash
./setup_complete.sh --validate
```

**Check System Requirements**
```bash
./setup_complete.sh --check
```

**Setup SSL Certificate**
```bash
./setup_complete.sh --ssl
```

**Create Backup**
```bash
./setup_complete.sh --backup
```

**Clean Installation**
```bash
./setup_complete.sh --clean
```

### Option 2: Python Installer Only (Alternative)

```bash
# Check prerequisites
python3 install.py --check

# Install application
python3 install.py

# Validate installation
python3 install.py --validate

# Force reinstall
python3 install.py --reinstall
```

### Option 3: Manual Installation

#### 1. Install System Dependencies
```bash
sudo apt-get update
sudo apt-get install -y python3-pip python3-dev python3-venv build-essential libssl-dev libffi-dev
```

#### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 3. Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### 4. Setup Environment
```bash
# Generate secure keys
SECRET_KEY=$(openssl rand -hex 32)
WHITELIST_TOKEN=$(openssl rand -hex 16)

# Create .env file
cat > .env << EOF
SECRET_KEY=$SECRET_KEY
WHITELIST_TOKEN=$WHITELIST_TOKEN
DATABASE_URL=sqlite:///$(pwd)/gbot.db
DEBUG=True
FLASK_ENV=development
EOF
```

#### 5. Initialize Database
```bash
python3 -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('Database initialized successfully')
"
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Security
SECRET_KEY=your_secret_key_here
WHITELIST_TOKEN=your_whitelist_token_here

# Database
DATABASE_URL=sqlite:///path/to/gbot.db

# Google API (optional)
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret

# Application Settings
DEBUG=True
FLASK_ENV=development
```

### Google API Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google Admin SDK API
4. Create OAuth 2.0 credentials
5. Add your domain to authorized redirect URIs
6. Copy Client ID and Client Secret to your `.env` file

## 🚀 Running the Application

### Development Mode
```bash
# Activate virtual environment
source venv/bin/activate

# Run Flask development server
python3 app.py
```

### Production Mode
```bash
# Start systemd service
sudo systemctl start gbot
sudo systemctl enable gbot

# Check status
sudo systemctl status gbot

# View logs
sudo journalctl -u gbot -f
```

## 🌐 Accessing the Application

- **URL**: http://localhost:5000 (development) or http://your-domain (production)
- **Default Admin Credentials**:
  - Username: `admin`
  - Password: `A9B3nX#Q8k$mZ6vw`

## 📊 Usage

### 1. Account Management
- Add Google Workspace accounts with OAuth credentials
- Manage multiple accounts from single interface
- Authenticate accounts using OAuth 2.0 flow

### 2. User Operations
- Create new GSuite user accounts
- Bulk user management operations
- User lifecycle management

### 3. Domain Management
- Add/remove domain aliases
- Bulk domain operations
- Domain information retrieval

### 4. Security Features
- IP address whitelisting
- Role-based access control
- Secure session management

## 🔍 Troubleshooting

### Common Issues

**1. Virtual Environment Issues**
```bash
# Remove corrupted venv
rm -rf venv

# Recreate virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**2. Database Issues**
```bash
# Remove existing database
rm -f gbot.db

# Reinitialize database
python3 -c "
from app import app, db
with app.app_context():
    db.create_all()
"
```

**3. Permission Issues**
```bash
# Fix file permissions
sudo chown -R $USER:$USER .
chmod +x *.sh *.py
```

**4. Service Issues**
```bash
# Check service status
sudo systemctl status gbot

# Restart service
sudo systemctl restart gbot

# View service logs
sudo journalctl -u gbot -f
```

### Log Files

- **Installation Log**: `install.log`
- **Application Log**: Check Flask logs or systemd journal
- **Setup Log**: `setup.log` (if using enhanced setup script)

### Validation Commands

```bash
# Check installation health
python3 install.py --validate

# Check system prerequisites
python3 install.py --check

# Validate with enhanced script
./setup_enhanced.sh --validate
```

## 🏗️ Architecture

### Components
- **Flask Web Application**: Main web framework
- **SQLAlchemy ORM**: Database abstraction layer
- **Google Admin SDK**: Google Workspace management
- **OAuth 2.0**: Secure authentication
- **SQLite/PostgreSQL**: Database storage

### File Structure
```
gbot-web-app/
├── app.py                 # Main Flask application
├── core_logic.py          # Google API integration
├── database.py            # Database models
├── config.py              # Configuration settings
├── install.py             # Python installer
├── setup_enhanced.sh      # Enhanced setup script
├── requirements.txt       # Python dependencies
├── .env                   # Environment variables
├── static/                # Static assets
├── templates/             # HTML templates
└── venv/                  # Python virtual environment
```

## 🔒 Security Considerations

- **IP Whitelisting**: Restrict access to specific IP addresses
- **Role-Based Access**: Different permission levels for users
- **Secure Keys**: Automatically generated secure keys
- **OAuth 2.0**: Industry-standard authentication
- **Session Management**: Secure user sessions

## 📚 API Endpoints

### Authentication
- `POST /api/authenticate` - Authenticate Google account
- `POST /api/complete-oauth` - Complete OAuth flow

### User Management
- `POST /api/add-user` - Add system user
- `GET /api/list-users` - List system users
- `POST /api/edit-user` - Edit user
- `POST /api/delete-user` - Delete user

### Google Workspace
- `POST /api/create-gsuite-user` - Create GSuite user
- `GET /api/get-domain-info` - Get domain information
- `POST /api/add-domain-alias` - Add domain alias
- `POST /api/delete-domain` - Delete domain

### IP Whitelist
- `POST /api/add-whitelist-ip` - Add IP to whitelist
- `GET /api/list-whitelist-ips` - List whitelisted IPs
- `POST /api/delete-whitelist-ip` - Remove IP from whitelist

## 🚀 Deployment

### Development
```bash
# Simple development server
python3 app.py
```

### Production Deployment

#### Quick Production Setup
```bash
# Complete production deployment with PostgreSQL, Nginx, SSL, and monitoring
./setup_complete.sh --install

# Force reinstall everything (clean slate)
./setup_complete.sh --reinstall
```

#### Step-by-Step Production Setup
```bash
# 1. Install system dependencies (optional - script handles this automatically)
sudo apt-get update
sudo apt-get install -y python3-pip python3-dev python3-venv build-essential libssl-dev libffi-dev postgresql postgresql-contrib nginx ufw certbot python3-certbot-nginx

# 2. Run complete production installation (handles everything automatically)
./setup_complete.sh --install

# 3. Or force reinstall everything (clean slate)
./setup_complete.sh --reinstall

# 4. Create backup anytime
./setup_complete.sh --backup

# 5. Services start automatically, but you can check status:
sudo systemctl status gbot nginx postgresql
```

#### Production Configuration
- **Database**: PostgreSQL with optimized settings
- **Web Server**: Nginx with reverse proxy
- **Application Server**: Gunicorn with 4 workers
- **Process Management**: Systemd service
- **Security**: Firewall (UFW), SSL/TLS, Security headers
- **Monitoring**: Log rotation, health checks
- **Backup**: Automated backup system

#### SSL Certificate Setup
```bash
# Setup SSL with Let's Encrypt
./setup_complete.sh --ssl

# Manual SSL setup
sudo certbot --nginx -d yourdomain.com
```

#### Production Commands
```bash
# Check service status
sudo systemctl status gbot nginx postgresql

# View logs
sudo journalctl -u gbot -f
sudo tail -f /var/log/nginx/error.log

# Restart services
sudo systemctl restart gbot nginx

# Backup and restore
./setup_complete.sh --backup

# Validate installation
./setup_complete.sh --validate

# Clean installation (removes everything)
./setup_complete.sh --clean
```

### Docker (Future Enhancement)
```bash
# Build and run with Docker
docker build -t gbot-web .
docker run -p 5000:5000 gbot-web
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

### Getting Help
- Check the troubleshooting section above
- Review log files for error details
- Validate installation with provided tools
- Check system requirements

### Reporting Issues
- Include system information (Ubuntu version, Python version)
- Provide error messages and log files
- Describe steps to reproduce the issue

## 🔄 Updates

### Updating the Application
```bash
# Pull latest changes
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt

# Restart services
sudo systemctl restart gbot
```

### Updating System Dependencies
```bash
sudo apt-get update
sudo apt-get upgrade
```

---

**Note**: This application is designed specifically for Ubuntu/Linux systems. Windows support is not provided.
