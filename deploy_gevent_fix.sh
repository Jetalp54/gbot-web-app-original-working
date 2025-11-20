#!/bin/bash
# deploy_gevent_fix.sh - Deploy fix for 1000+ concurrent users

set -e

echo "=========================================="
echo "🚀 Deploying Gevent Fix for 1000+ Users"
echo "=========================================="
echo ""

# Check if server IP provided
if [ -z "$1" ]; then
    echo "Usage: ./deploy_gevent_fix.sh <server_ip>"
    echo "Example: ./deploy_gevent_fix.sh 46.101.235.229"
    exit 1
fi

SERVER=$1

echo "📤 Uploading configuration files..."
scp gunicorn.conf.py root@$SERVER:/opt/gbot-web-app/
scp gunicorn_maximum.conf.py root@$SERVER:/opt/gbot-web-app/
scp requirements.txt root@$SERVER:/opt/gbot-web-app/
scp routes/aws_manager.py root@$SERVER:/opt/gbot-web-app/routes/
scp templates/aws_management.html root@$SERVER:/opt/gbot-web-app/templates/

echo ""
echo "📦 Installing gevent on server..."
ssh root@$SERVER << 'EOF'
cd /opt/gbot-web-app
source venv/bin/activate
pip install gevent==23.9.1
echo "✅ Gevent installed successfully"
EOF

echo ""
echo "🔄 Restarting service..."
ssh root@$SERVER << 'EOF'
sudo systemctl restart gbot
sleep 3
sudo systemctl status gbot --no-pager
EOF

echo ""
echo "=========================================="
echo "✅ DEPLOYMENT COMPLETE!"
echo "=========================================="
echo ""
echo "Test steps:"
echo "1. Paste 10 users → Invoke → Check CloudWatch (should see 10 streams)"
echo "2. Paste 50 users → Invoke → Check CloudWatch (should see 50 streams!)"
echo "3. Paste 1000 users → Invoke → Check CloudWatch (should see 1000 streams!)"
echo ""
echo "Monitor logs: ssh root@$SERVER 'sudo journalctl -u gbot -f | grep \"[BULK]\"'"
echo ""

