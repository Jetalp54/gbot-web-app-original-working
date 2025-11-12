# IP Whitelist Management for GBot Web App

This document explains how to use the IP Whitelist feature to control access to your GBot Web Application.

## Overview

The IP Whitelist feature allows you to restrict access to your application to only specific IP addresses. This is useful for:
- Securing your application from unauthorized access
- Limiting access to specific networks or locations
- Emergency access control

## How It Works

1. **IP Whitelist Check**: When enabled, the application checks if the client's IP address is in the whitelist
2. **Emergency Access**: If your IP is not whitelisted, you can use emergency access to add it
3. **Static Key Access**: Use a predefined key to bypass IP restrictions for initial setup

## Configuration

### Environment Variables

Set these in your `.env` file:

```bash
# Enable IP whitelist (set to True to enable)
ENABLE_IP_WHITELIST=True

# Emergency access key for bypassing IP restrictions
WHITELIST_TOKEN=your_secret_key_here

# Allow all IPs in development mode
ALLOW_ALL_IPS_IN_DEV=False

# Debug mode (disables IP whitelist)
DEBUG=False
```

### Database

The whitelisted IPs are stored in the `WhitelistedIP` table in your PostgreSQL database.

## Usage Methods

### Method 1: Web Interface (After Login)

1. **Login to the application** (if your IP is already whitelisted)
2. **Navigate to IP Whitelist page** (`/whitelist`)
3. **Add new IPs** using the form
4. **View and manage** existing whitelisted IPs

### Method 2: Emergency Access (When Locked Out)

1. **Access emergency page**: `/emergency_access`
2. **Enter your emergency access key** (WHITELIST_TOKEN from .env)
3. **Your IP will be automatically detected** or you can enter it manually
4. **Click "Grant Emergency Access"** to add your IP to the whitelist

### Method 3: Command Line Tool

Use the `manage_whitelist.py` script for command-line management:

```bash
# Detect your current IP
python3 manage_whitelist.py --detect --key YOUR_EMERGENCY_KEY

# Add your IP to whitelist
python3 manage_whitelist.py --add YOUR_IP --key YOUR_EMERGENCY_KEY

# List all whitelisted IPs
python3 manage_whitelist.py --list --key YOUR_EMERGENCY_KEY

# Use custom application URL
python3 manage_whitelist.py --add YOUR_IP --key YOUR_EMERGENCY_KEY --url https://yourdomain.com
```

### Method 4: Direct API Call

Make a direct HTTP request to the emergency API:

```bash
curl -X POST http://yourdomain.com/api/emergency-add-ip \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "YOUR_IP", "emergency_key": "YOUR_EMERGENCY_KEY"}'
```

## Step-by-Step Setup

### Initial Setup (First Time)

1. **Set your emergency access key** in `.env`:
   ```bash
   WHITELIST_TOKEN=your_very_secure_random_key_here
   ```

2. **Enable IP whitelist** in `.env`:
   ```bash
   ENABLE_IP_WHITELIST=True
   DEBUG=False
   ```

3. **Restart your application**:
   ```bash
   systemctl restart gbot
   ```

4. **Access emergency page** from your current IP:
   ```
   https://yourdomain.com/emergency_access
   ```

5. **Enter your emergency key** and grant access

6. **Your IP is now whitelisted** - you can access the main application

### Adding More IPs

1. **Login to the application** (using your whitelisted IP)
2. **Go to IP Whitelist page**
3. **Add new IP addresses** as needed
4. **Remove IPs** that are no longer needed

## Troubleshooting

### "Access denied. IP not whitelisted" Error

**Cause**: Your current IP address is not in the whitelist.

**Solutions**:
1. **Use emergency access**: Go to `/emergency_access`
2. **Check your IP**: Use `python3 manage_whitelist.py --detect`
3. **Verify configuration**: Check `.env` file for `WHITELIST_TOKEN`
4. **Check database**: Ensure the whitelist table exists and is accessible

### Emergency Access Not Working

**Possible causes**:
1. **Wrong emergency key**: Verify `WHITELIST_TOKEN` in `.env`
2. **Application not running**: Check `systemctl status gbot`
3. **Database issues**: Check PostgreSQL connection
4. **Network issues**: Verify the application is accessible

**Debug steps**:
1. Check application logs: `tail -f logs/gbot.log`
2. Verify database connection
3. Test emergency API directly with curl
4. Check firewall settings

### Temporarily Disable IP Whitelist

If you need to disable IP whitelist temporarily:

1. **Edit `.env` file**:
   ```bash
   ENABLE_IP_WHITELIST=False
   DEBUG=True
   ```

2. **Restart application**:
   ```bash
   systemctl restart gbot
   ```

3. **Re-enable when ready**:
   ```bash
   ENABLE_IP_WHITELIST=True
   DEBUG=False
   systemctl restart gbot
   ```

## Security Considerations

1. **Keep your emergency key secret** - don't share it or commit it to version control
2. **Use strong, random keys** for `WHITELIST_TOKEN`
3. **Regularly review** whitelisted IPs
4. **Monitor access logs** for suspicious activity
5. **Consider using VPNs** for secure access from multiple locations

## API Endpoints

- `GET /emergency_access` - Emergency access page
- `POST /api/emergency-add-ip` - Add IP via emergency API
- `GET /api/list-whitelist-ips` - List all whitelisted IPs
- `POST /api/add-whitelist-ip` - Add IP (requires authentication)
- `POST /api/delete-whitelist-ip` - Remove IP (requires authentication)

## Examples

### Quick IP Addition

```bash
# Detect and add your current IP
python3 manage_whitelist.py --detect --key my_secret_key
python3 manage_whitelist.py --add $(curl -s ifconfig.me) --key my_secret_key
```

### Bulk IP Management

```bash
# Add multiple IPs
for ip in 192.168.1.100 192.168.1.101 192.168.1.102; do
    python3 manage_whitelist.py --add $ip --key my_secret_key
done
```

### Check Status

```bash
# List all whitelisted IPs
python3 manage_whitelist.py --list --key my_secret_key

# Check if specific IP is whitelisted
python3 manage_whitelist.py --list --key my_secret_key | grep "192.168.1.100"
```

## Support

If you encounter issues:

1. Check the application logs in `logs/gbot.log`
2. Verify your `.env` configuration
3. Test database connectivity
4. Check network and firewall settings
5. Review this documentation for common solutions
