# GBot Installation Troubleshooting Guide

## Common Issues and Solutions

### 1. dpkg Lock Error

**Error Message:**
```
E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 39507 (apt-get)
E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?
```

**Solution:**

The installation script now automatically handles this by waiting for the lock to be released. However, if you encounter this issue:

#### Option 1: Wait for the script (Recommended)
The script will automatically wait up to 5 minutes for the lock to be released. Just let it run.

#### Option 2: Check what's running
```bash
# Check for running apt processes
ps aux | grep -E 'apt|dpkg'

# Check lock files
ls -la /var/lib/dpkg/lock*
ls -la /var/cache/apt/archives/lock
```

#### Option 3: Kill the blocking process (if safe)
```bash
# Find the process ID
ps aux | grep apt

# Kill it (replace PID with actual process ID)
sudo kill <PID>

# If it doesn't respond, force kill
sudo kill -9 <PID>
```

#### Option 4: Remove lock files (USE WITH CAUTION)
**Only do this if you're absolutely sure no apt process is running!**

```bash
# Check for running processes first
ps aux | grep -E 'apt|dpkg'

# If nothing is running, remove locks
sudo rm /var/lib/dpkg/lock-frontend
sudo rm /var/lib/dpkg/lock
sudo rm /var/cache/apt/archives/lock

# Reconfigure dpkg
sudo dpkg --configure -a
```

### 2. Unattended Upgrades Running

Ubuntu often runs automatic updates in the background. The script will wait for these to complete, but you can also:

```bash
# Check if unattended-upgrades is running
sudo systemctl status unattended-upgrades

# Temporarily disable (will re-enable after installation)
sudo systemctl stop unattended-upgrades
```

### 3. Manual Lock Release (Last Resort)

If the script times out waiting for the lock:

```bash
# 1. Check what's holding the lock
sudo lsof /var/lib/dpkg/lock-frontend
sudo lsof /var/lib/dpkg/lock

# 2. Kill the process if safe
sudo kill <PID>

# 3. Clean up
sudo apt-get clean
sudo apt-get update

# 4. Re-run the installation script
sudo ./install_complete_ubuntu22.sh
```

### 4. Installation Interrupted

If the installation was interrupted:

```bash
# Check what was installed
sudo systemctl status gbot
sudo systemctl status nginx
sudo systemctl status postgresql

# Check if services exist
ls -la /etc/systemd/system/gbot.service
ls -la /etc/nginx/sites-available/gbot

# Re-run the script (it's idempotent - safe to run multiple times)
sudo ./install_complete_ubuntu22.sh
```

### 5. Database Connection Issues

If you get database connection errors:

```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check if database exists
sudo -u postgres psql -l | grep gbot_db

# Check if user exists
sudo -u postgres psql -c "\du" | grep gbot_user

# Reset database (if needed)
sudo -u postgres psql -c "DROP DATABASE IF EXISTS gbot_db;"
sudo -u postgres psql -c "DROP USER IF EXISTS gbot_user;"
# Then re-run the installation script
```

### 6. Nginx Configuration Errors

```bash
# Test Nginx configuration
sudo nginx -t

# Check Nginx error logs
sudo tail -f /var/log/nginx/error.log

# Reload Nginx
sudo systemctl reload nginx
```

### 7. Python Virtual Environment Issues

```bash
# Recreate virtual environment
cd /opt/gbot-web-app
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 8. Permission Issues

```bash
# Fix ownership
sudo chown -R $USER:$USER /opt/gbot-web-app
sudo chown -R $USER:$USER /var/log/gbot

# Fix permissions
chmod 600 /opt/gbot-web-app/.env
chmod +x /opt/gbot-web-app/backup.sh
```

## Pre-Installation Checklist

Before running the installation script:

- [ ] Ensure you have sudo/root access
- [ ] Check disk space: `df -h` (need at least 2GB free)
- [ ] Check memory: `free -h` (need at least 1GB RAM)
- [ ] Ensure no other package installations are running
- [ ] Backup any existing configuration if upgrading
- [ ] Have your domain name ready (for SSL setup)

## Post-Installation Verification

After installation, verify everything is working:

```bash
# Check all services
sudo systemctl status gbot
sudo systemctl status nginx
sudo systemctl status postgresql

# Check application logs
sudo journalctl -u gbot -n 50

# Test HTTP endpoint
curl http://localhost/health

# Check firewall
sudo ufw status

# Verify database connection
sudo -u postgres psql -d gbot_db -c "SELECT version();"
```

## Getting Help

If you continue to have issues:

1. Check the logs: `sudo journalctl -u gbot -n 100`
2. Check Nginx logs: `sudo tail -f /var/log/nginx/gbot_error.log`
3. Verify all services are running: `sudo systemctl status gbot nginx postgresql`
4. Review the installation script output for any error messages

## Quick Fixes

### Restart Everything
```bash
sudo systemctl restart gbot
sudo systemctl restart nginx
sudo systemctl restart postgresql
```

### View Real-time Logs
```bash
sudo journalctl -u gbot -f
```

### Re-run Installation (Safe)
The installation script is idempotent - you can safely run it multiple times:
```bash
sudo ./install_complete_ubuntu22.sh
```

