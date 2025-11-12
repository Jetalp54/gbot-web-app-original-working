# Fix Nginx 504 Timeout Error

## Problem
The app is getting "Network error: Server returned HTML instead of JSON. Status: 504" because nginx is configured with 30-second timeouts, but bulk operations take longer than that.

## Solution
Increase nginx proxy timeouts to 300 seconds (5 minutes) to handle very large user bases (10k+ users).

## Steps to Fix on Ubuntu Server

### Option 1: Run the Fix Script
```bash
# Upload the fix_nginx_timeout.sh script to your server and run:
chmod +x fix_nginx_timeout.sh
sudo ./fix_nginx_timeout.sh
```

### Option 2: Manual Fix
```bash
# 1. Backup current nginx configuration
sudo cp /etc/nginx/sites-available/gbot /etc/nginx/sites-available/gbot.backup

# 2. Edit the nginx configuration
sudo nano /etc/nginx/sites-available/gbot

# 3. Find these lines:
#    proxy_connect_timeout 30s;
#    proxy_send_timeout 30s;
#    proxy_read_timeout 30s;

# 4. Change them to:
#    proxy_connect_timeout 300s;
#    proxy_send_timeout 300s;
#    proxy_read_timeout 300s;

# 5. Also add these lines after the proxy_set_header lines:
#    proxy_buffering off;
#    proxy_request_buffering off;

# 6. Test nginx configuration
sudo nginx -t

# 7. If test passes, reload nginx
sudo systemctl reload nginx
```

### Option 3: Complete Replacement
Replace the entire `/etc/nginx/sites-available/gbot` file with:

```nginx
server {
    listen 80;
    server_name _;
    
    location / {
        include proxy_params;
        proxy_pass http://unix:/path/to/your/gbot/gbot.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Increased timeouts to prevent 504 errors
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        # Additional settings
        proxy_buffering off;
        proxy_request_buffering off;
    }
    
    location /static {
        alias /path/to/your/gbot/static;
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

**Note:** Replace `/path/to/your/gbot/` with your actual GBot installation path.

## Verification
After applying the fix:

1. Test nginx configuration: `sudo nginx -t`
2. Reload nginx: `sudo systemctl reload nginx`
3. Try the bulk domain change operation again
4. The 504 error popup should no longer appear

## What This Fixes
- **Before**: nginx timeout = 30s, operation takes 45s → 504 HTML error page
- **After**: nginx timeout = 120s, operation takes 45s → Success JSON response

The domain changes will continue to work perfectly, but you won't get the annoying 504 error popup anymore!
