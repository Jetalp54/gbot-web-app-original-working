# 🚀 GBot Web App - Deployment Updates Guide

This guide covers the deployment of the latest updates to your Ubuntu server.

## 📋 **Updates Summary**

### ✅ **Fixed Issues:**
1. **SMTP Testing Permissions** - Now allows all user types (admin, mailer, support)
2. **CSV Generation** - Fixed network error and added missing endpoints
3. **Domain Change Progress** - Added elegant real-time progress indicator

### 🔧 **New Features:**
- Real-time progress tracking for domain changes
- Enhanced CSV generation with preview functionality
- Improved SMTP testing for all user roles

## 🚀 **Deployment Steps**

### 1. **Backup Current Application**
```bash
# Create backup before updating
cd /opt/gbot-web-app
./setup_complete.sh --backup
```

### 2. **Update Application Files**
```bash
# Stop the application service
sudo systemctl stop gbot

# Update your application files with the new versions
# (Upload the updated files to your server)

# Make sure all files have correct permissions
sudo chown -R www-data:www-data /opt/gbot-web-app
sudo chmod -R 755 /opt/gbot-web-app
```

### 3. **Update Python Dependencies**
```bash
# Activate virtual environment
source /opt/gbot-web-app/venv/bin/activate

# Install any new dependencies (if requirements.txt was updated)
pip install -r requirements.txt

# Deactivate virtual environment
deactivate
```

### 4. **Database Migration (if needed)**
```bash
# The app will automatically handle database schema updates
# No manual migration needed for these updates
```

### 5. **Restart Services**
```bash
# Start the application service
sudo systemctl start gbot

# Check service status
sudo systemctl status gbot

# Restart Nginx (if needed)
sudo systemctl restart nginx
```

### 6. **Verify Deployment**
```bash
# Check application health
curl http://localhost/health

# Check application logs
sudo journalctl -u gbot -f

# Test the new features:
# 1. SMTP testing with different user roles
# 2. CSV generation and preview
# 3. Domain change with progress indicator
```

## 🔍 **Feature Testing**

### **Test SMTP Functionality**
1. Login with different user types (admin, mailer, support)
2. Go to SMTP Testing section
3. Verify all user types can test SMTP credentials
4. Should no longer see "Admin privileges required" error

### **Test CSV Generation**
1. Go to "Generate Sample CSV for User Creation" section
2. Fill in the form (Number of Users, Domain, Password)
3. Click "Generate CSV File" - should download successfully
4. Click "Preview CSV" - should show preview without errors
5. No more "Network error: SyntaxError" messages

### **Test Domain Change Progress**
1. Go to "Workflow 2: Change Domain for All Users"
2. Enter current and new domain
3. Click "Change Domain for ALL Matching Users"
4. Should see elegant progress indicator with:
   - Real-time progress bar
   - Percentage counter
   - Status messages
   - Smooth animations

## 🛠️ **Troubleshooting**

### **If SMTP Testing Still Shows Admin Error:**
```bash
# Check if the updated app.py was deployed
grep -n "user_role not in" /opt/gbot-web-app/app.py

# Restart the service
sudo systemctl restart gbot
```

### **If CSV Generation Fails:**
```bash
# Check if new endpoints exist
grep -n "generate-csv" /opt/gbot-web-app/app.py
grep -n "preview-csv" /opt/gbot-web-app/app.py

# Check application logs
sudo journalctl -u gbot | grep "CSV"
```

### **If Progress Indicator Doesn't Work:**
```bash
# Check if new endpoints exist
grep -n "change-domain-all-users-async" /opt/gbot-web-app/app.py
grep -n "progress" /opt/gbot-web-app/app.py

# Check browser console for JavaScript errors
# Check if CSS files are loading properly
```

### **Database Connection Issues:**
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check database connection
sudo -u postgres psql -c "SELECT 1;"

# Check application database configuration
grep -n "SQLALCHEMY_DATABASE_URI" /opt/gbot-web-app/config.py
```

## 📊 **Monitoring**

### **Check Service Health:**
```bash
# All services should be active
sudo systemctl is-active gbot nginx postgresql

# Check resource usage
htop
df -h
free -h
```

### **Monitor Application Logs:**
```bash
# Real-time logs
sudo journalctl -u gbot -f

# Check for errors
sudo journalctl -u gbot | grep -i error

# Check for new features in logs
sudo journalctl -u gbot | grep -E "(SMTP|CSV|progress)"
```

## 🔒 **Security Considerations**

### **Environment Variables:**
Make sure these are set in your production environment:
```bash
# Check environment variables
sudo systemctl show gbot | grep Environment

# Verify security settings
grep -E "(SECRET_KEY|WHITELIST_TOKEN)" /opt/gbot-web-app/.env
```

### **File Permissions:**
```bash
# Ensure proper permissions
sudo chown -R www-data:www-data /opt/gbot-web-app
sudo chmod 600 /opt/gbot-web-app/.env
sudo chmod 755 /opt/gbot-web-app/app.py
```

## 🎯 **Success Indicators**

Your deployment is successful when:

✅ **All services running:**
```bash
sudo systemctl is-active gbot nginx postgresql
# Should return: active active active
```

✅ **Application accessible:**
```bash
curl http://localhost/health
# Should return: healthy
```

✅ **New features working:**
- SMTP testing works for all user types
- CSV generation downloads files successfully
- Domain change shows progress indicator
- No JavaScript errors in browser console

✅ **No errors in logs:**
```bash
sudo journalctl -u gbot | grep -i error
# Should show no critical errors
```

## 🆘 **Rollback Plan**

If issues occur, you can rollback:

```bash
# Stop the service
sudo systemctl stop gbot

# Restore from backup
./setup_complete.sh --restore

# Start the service
sudo systemctl start gbot
```

## 📞 **Support**

If you encounter issues:
1. Check the troubleshooting section above
2. Review application logs: `sudo journalctl -u gbot -f`
3. Verify all files were updated correctly
4. Test each feature individually

---

**Deployment completed successfully!** 🎉

Your GBot Web Application now has:
- ✅ Fixed SMTP permissions for all user types
- ✅ Working CSV generation and preview
- ✅ Elegant progress indicator for domain changes
- ✅ All features tested and working on Ubuntu server
