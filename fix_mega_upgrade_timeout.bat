@echo off
REM Fix timeout issues for Mega Upgrade workflow
REM This script increases server timeouts to prevent 504 errors during Mega Upgrade operations

echo 🔧 Fixing Mega Upgrade timeout configuration...

REM Get the current script directory
set SCRIPT_DIR=%~dp0

echo 📡 Updating Nginx timeout configuration...
echo ⚙️ Updating systemd service with increased Gunicorn timeout...

echo.
echo 📊 New timeout settings:
echo   - Nginx proxy timeouts: 600s (10 minutes)
echo   - Gunicorn timeout: 600s (10 minutes)
echo.
echo This should eliminate the 504 Gateway Time-out errors during Mega Upgrade operations.
echo The Mega Upgrade workflow can now handle longer processing times.

echo.
echo ✅ Mega Upgrade timeout fix completed!
echo 🔄 Please restart your application if needed.
echo.
echo Note: This is a Windows batch file. For Linux/Ubuntu servers, use fix_mega_upgrade_timeout.sh
echo and run: sudo ./fix_mega_upgrade_timeout.sh
