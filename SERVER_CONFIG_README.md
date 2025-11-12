# 🖥️ Server Configuration for JSON Import

This feature allows administrators to configure a remote server connection for importing Google Workspace account credentials from JSON files.

## 📋 Overview

The server configuration feature enables:
- **Secure SSH connection** to a remote server containing JSON credential files
- **Automatic account import** from JSON files stored on the server
- **Flexible file patterns** to match different naming conventions
- **Authentication methods** including password and SSH key authentication

## ⚙️ Configuration

### Accessing Settings
1. Log in as an administrator
2. Navigate to **⚙️ Settings** in the top navigation
3. Configure the server connection details

### Required Information

#### Server Connection
- **Host/IP**: Server address (e.g., `192.168.1.100` or `server.domain.com`)
- **Port**: SSH port (default: 22)
- **Username**: SSH username (e.g., `ubuntu`, `root`)

#### Authentication
Choose one of two methods:

**Password Authentication:**
- Enter the server password

**SSH Key Authentication:**
- Paste the private key content (OpenSSH format)

#### File Configuration
- **JSON Path**: Directory path where JSON files are stored (e.g., `/opt/gbot-web-app/credentials/`)
- **File Pattern**: Pattern to match JSON files (e.g., `*.json`, `admin@*.json`)

## 🔧 Usage

### 1. Configure Server Settings
1. Go to **⚙️ Settings**
2. Fill in server connection details
3. Click **🔍 Test Connection** to verify connectivity
4. Click **💾 Save Configuration**

### 2. Import Accounts from Server
1. Go to **📊 Dashboard**
2. Click **📁 Add from Server JSON**
3. Enter email addresses (one per line)
4. Click **🔍 Search & Add Accounts**

### 3. File Requirements
JSON files must:
- Be named exactly as the email address (e.g., `admin@domain.com.json`)
- Contain valid Google OAuth credentials
- Have either `installed` or `web` section with `client_id` and `client_secret`

## 📁 JSON File Format

Example JSON file structure:
```json
{
  "installed": {
    "client_id": "123456789-abcdef.apps.googleusercontent.com",
    "client_secret": "GOCSPX-your_client_secret",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}
```

## 🔒 Security Features

- **Encrypted storage** of passwords and private keys
- **Admin-only access** to server configuration
- **Secure SSH connections** with timeout protection
- **Temporary key files** for SSH key authentication

## 🚨 Troubleshooting

### Connection Issues
- Verify server hostname/IP is correct
- Check SSH port is accessible
- Ensure username and password/key are correct
- Test connection using **🔍 Test Connection** button

### File Access Issues
- Verify JSON path exists on server
- Check file permissions on server
- Ensure file pattern matches actual files
- Validate JSON file format

### Import Issues
- Check JSON files contain valid credentials
- Verify email addresses match file names
- Ensure accounts don't already exist in system

## 📝 API Endpoints

### Server Configuration
- `GET /api/get-server-config` - Retrieve current configuration
- `POST /api/save-server-config` - Save server configuration
- `POST /api/test-server-connection` - Test server connectivity
- `POST /api/clear-server-config` - Clear server configuration

### Account Import
- `POST /api/add-from-server-json` - Import accounts from server JSON files

## 🔄 Database Schema

The `ServerConfig` table stores:
- Server connection details (host, port, username)
- Authentication credentials (encrypted)
- File path and pattern configuration
- Configuration status and timestamps

## 🛡️ Best Practices

1. **Use SSH keys** instead of passwords when possible
2. **Restrict file permissions** on the server
3. **Regularly update** server credentials
4. **Monitor connection logs** for security
5. **Backup configurations** before major changes

## 🆘 Support

If you encounter issues:
1. Check the application logs
2. Verify server connectivity manually
3. Test with a simple JSON file first
4. Contact system administrator for assistance
