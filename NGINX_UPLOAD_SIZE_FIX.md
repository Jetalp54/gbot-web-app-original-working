# Fix HTTP 413 "Request Entity Too Large" Error

## Problem
The app is showing "❌ Network error during upload/restore: HTTP 413: Request Entity Too Large" even for small files (like 2.7MB). This error is coming from nginx, not from the Flask application.

## Root Cause
Nginx has a default `client_max_body_size` limit (usually 1MB) that prevents file uploads larger than this limit. Even though we removed Flask's file size limits, nginx is still blocking the uploads.

## Solution
Increase nginx's `client_max_body_size` to allow larger file uploads.

## Quick Fix

### Option 1: Run the Fix Script (Recommended)
```bash
# Upload the fix_nginx_upload_size.sh script to your server and run:
chmod +x fix_nginx_upload_size.sh
sudo ./fix_nginx_upload_size.sh
```

### Option 2: Manual Fix
```bash
# 1. Backup current nginx configuration
sudo cp /etc/nginx/sites-available/gbot /etc/nginx/sites-available/gbot.backup

# 2. Edit the nginx configuration
sudo nano /etc/nginx/sites-available/gbot

# 3. Add this line at the top of the server block:
#    client_max_body_size 1G;

# 4. Test nginx configuration
sudo nginx -t

# 5. If test passes, reload nginx
sudo systemctl reload nginx
```

### Option 3: Complete Configuration Replacement
Replace the entire `/etc/nginx/sites-available/gbot` file with:

```nginx
server {
    listen 80;
    server_name _;
    
    # Increase client max body size to allow large file uploads
    client_max_body_size 1G;
    
    location / {
        include proxy_params;
        proxy_pass http://unix:/home/gbot/gbot/gbot.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Increased timeouts to prevent 504 errors
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
        
        # Additional settings for large uploads
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_max_temp_file_size 0;
    }
    
    location /static {
        alias /home/gbot/gbot/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
```

**Note:** Replace `/home/gbot/gbot/` with your actual GBot installation path.

## Verification
After applying the fix:

1. Test nginx configuration: `sudo nginx -t`
2. Reload nginx: `sudo systemctl reload nginx`
3. Try uploading your backup file again
4. The HTTP 413 error should be gone

## What This Fixes
- **Before**: nginx client_max_body_size = 1MB, file = 2.7MB → HTTP 413 error
- **After**: nginx client_max_body_size = 1GB, file = 2.7MB → Success

## Additional Notes
- The Flask application has no file size limits (we removed them)
- The HTTP 413 error was coming from nginx, not Flask
- This fix allows uploads up to 1GB
- If you need larger uploads, increase the `client_max_body_size` value

## Troubleshooting
If you still get HTTP 413 errors after applying this fix:

1. Check nginx error logs: `sudo tail -f /var/log/nginx/error.log`
2. Verify the configuration was applied: `sudo nginx -T | grep client_max_body_size`
3. Make sure nginx was reloaded: `sudo systemctl status nginx`
4. Check if there are other nginx configuration files that might override this setting
