@echo off
REM deploy_gevent_fix.bat - Deploy fix for 1000+ concurrent users (Windows)

echo ==========================================
echo 🚀 Deploying Gevent Fix for 1000+ Users
echo ==========================================
echo.

if "%1"=="" (
    echo Usage: deploy_gevent_fix.bat ^<server_ip^>
    echo Example: deploy_gevent_fix.bat 46.101.235.229
    exit /b 1
)

set SERVER=%1

echo 📤 Uploading configuration files...
scp gunicorn.conf.py root@%SERVER%:/opt/gbot-web-app/
scp gunicorn_maximum.conf.py root@%SERVER%:/opt/gbot-web-app/
scp requirements.txt root@%SERVER%:/opt/gbot-web-app/
scp routes\aws_manager.py root@%SERVER%:/opt/gbot-web-app/routes/
scp templates\aws_management.html root@%SERVER%:/opt/gbot-web-app/templates/

echo.
echo 📦 Installing gevent on server...
ssh root@%SERVER% "cd /opt/gbot-web-app && source venv/bin/activate && pip install gevent==23.9.1"

echo.
echo 🔄 Restarting service...
ssh root@%SERVER% "sudo systemctl restart gbot && sleep 3 && sudo systemctl status gbot --no-pager"

echo.
echo ==========================================
echo ✅ DEPLOYMENT COMPLETE!
echo ==========================================
echo.
echo Test steps:
echo 1. Paste 10 users → Invoke → Check CloudWatch (should see 10 streams)
echo 2. Paste 50 users → Invoke → Check CloudWatch (should see 50 streams!)
echo 3. Paste 1000 users → Invoke → Check CloudWatch (should see 1000 streams!)
echo.
echo Monitor logs: ssh root@%SERVER% "sudo journalctl -u gbot -f | grep '[BULK]'"
echo.

