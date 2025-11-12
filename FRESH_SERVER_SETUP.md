# 🚀 Fresh Server Setup Guide

This guide will help you deploy the GBot Web Application on a completely fresh Ubuntu server.

## 📋 Prerequisites

- **Fresh Ubuntu Server** (20.04 LTS or 22.04 LTS recommended)
- **Root access** or sudo privileges
- **Internet connection** for package downloads
- **Domain name** (optional, for SSL)

## 🔧 Step-by-Step Installation

### 1. **Connect to Your Server**

```bash
ssh root@your-server-ip
```

### 2. **Update System Packages**

```bash
apt update && apt upgrade -y
```

### 3. **Download the Application**

```bash
# Create application directory
mkdir -p /opt/gbot-web-app
cd /opt/gbot-web-app

# Download application files
# (You'll need to upload your application files to the server)
```

### 4. **Make Installation Script Executable**

```bash
chmod +x setup_complete.sh
```

### 5. **Run the Complete Installation**

```bash
./setup_complete.sh --install
```

## 🎯 What the Installation Script Does

The installation script will automatically:

### ✅ **System Dependencies**
- Install Python 3.8+ and pip3
- Install PostgreSQL database
- Install Nginx web server
- Install firewall (UFW)
- Install SSL tools (Certbot)
- Install development tools

### ✅ **Python Environment**
- Create virtual environment
- Install all Python dependencies from `requirements.txt`
- Upgrade pip and setuptools

### ✅ **Database Setup**
- Configure PostgreSQL for production
- Create database and user
- Set up optimized database settings
- Create application tables

### ✅ **Web Server Configuration**
- Configure Nginx as reverse proxy
- Set up Unix socket communication
- Configure static file serving
- Set up health check endpoint

### ✅ **Application Service**
- Create systemd service for automatic startup
- Configure Gunicorn with 4 workers
- Set up logging and monitoring
- Enable automatic restarts

### ✅ **Security & Monitoring**
- Configure firewall rules
- Set up SSL certificate (if domain provided)
- Create monitoring scripts
- Set up automated backups

## 🔍 **Troubleshooting Common Issues**

### **Issue: pip3 not available**
```bash
# The script will automatically install pip3, but if it fails:
apt install python3-pip -y
```

### **Issue: Python version too old**
```bash
# Check Python version
python3 --version

# If below 3.8, update Python:
add-apt-repository ppa:deadsnakes/ppa
apt update
apt install python3.10 python3.10-venv python3.10-dev
```

### **Issue: PostgreSQL not starting**
```bash
# Check PostgreSQL status
systemctl status postgresql

# Start PostgreSQL manually
systemctl start postgresql
systemctl enable postgresql
```

### **Issue: Nginx configuration errors**
```bash
# Test Nginx configuration
nginx -t

# Check Nginx error logs
tail -f /var/log/nginx/error.log
```

### **Issue: Application not accessible**
```bash
# Check application status
systemctl status gbot

# Check application logs
journalctl -u gbot -f

# Test socket connection
curl --unix-socket /opt/gbot-web-app/gbot.sock http://localhost/health
```

## 🚀 **Post-Installation Steps**

### 1. **Access the Application**
```bash
# Get your server IP
hostname -I

# Access the application
http://your-server-ip
```

### 2. **Default Admin Credentials**
- **Username:** `admin`
- **Password:** `A9B3nX#Q8k$mZ6vw`

### 3. **Configure SSL (Optional)**
```bash
# If you have a domain name
./setup_complete.sh --ssl
```

### 4. **Set Up IP Whitelist**
```bash
# Add your IP to whitelist
./setup_complete.sh --add-ip

# Or disable whitelist for development
./setup_complete.sh --disable-whitelist
```

## 📊 **Monitoring & Management**

### **Check Service Status**
```bash
systemctl status gbot nginx postgresql
```

### **View Application Logs**
```bash
# Real-time logs
journalctl -u gbot -f

# Recent logs
journalctl -u gbot --since "1 hour ago"
```

### **Monitor System Health**
```bash
# Run monitoring script
./monitor_gbot.sh

# View monitoring logs
tail -f monitoring.log
```

### **Create Backup**
```bash
./setup_complete.sh --backup
```

### **Restart Services**
```bash
systemctl restart gbot nginx
```

## 🔧 **Advanced Configuration**

### **Environment Variables**
Edit `.env` file to customize:
- Database settings
- Security keys
- Debug mode
- IP whitelist settings

### **Nginx Configuration**
Edit `/etc/nginx/sites-available/gbot` to customize:
- Server blocks
- SSL settings
- Proxy settings
- Static file serving

### **Gunicorn Configuration**
Edit systemd service file `/etc/systemd/system/gbot.service` to customize:
- Number of workers
- Timeout settings
- Logging configuration

## 🆘 **Getting Help**

### **Run Diagnostics**
```bash
# Comprehensive troubleshooting
./setup_complete.sh --troubleshoot

# Fix common issues automatically
./setup_complete.sh --fix-all
```

### **Check Installation Health**
```bash
./setup_complete.sh --validate
```

### **View Installation Logs**
```bash
tail -f setup.log
```

## 🎉 **Success Indicators**

Your installation is successful when:

✅ **Services are running:**
```bash
systemctl is-active gbot nginx postgresql
# Should return: active active active
```

✅ **Application is accessible:**
```bash
curl http://localhost/health
# Should return: healthy
```

✅ **Socket file exists:**
```bash
ls -la /opt/gbot-web-app/gbot.sock
# Should show socket file with proper permissions
```

✅ **Database is connected:**
```bash
# Check database connection in application logs
journalctl -u gbot | grep "Database"
```

## 📚 **Additional Resources**

- **README.md** - Complete application documentation
- **setup.log** - Detailed installation logs
- **monitoring.log** - System health monitoring
- **backups/** - Automated backup files

---

**Need help?** Check the troubleshooting section or run `./setup_complete.sh --help` for all available options.
