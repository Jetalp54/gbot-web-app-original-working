#!/bin/bash
# fix_server.sh - Fix directory mismatch and update Gbot

echo "🔧 Starting Gbot Fix..."

# 1. Identify where we are
CURRENT_DIR=$(pwd)
TARGET_DIR="/opt/gbot-web-app"

echo "📍 Current Directory: $CURRENT_DIR"
echo "🎯 Target Directory:  $TARGET_DIR"

if [ "$CURRENT_DIR" == "$TARGET_DIR" ]; then
    echo "⚠️  You are already in the target directory."
    echo "    If the code isn't working, make sure you uploaded the new files here."
else
    echo "🚀 Copying files to target directory..."
    
    # Copy specific files we fixed
    sudo cp services/google_service_account.py $TARGET_DIR/services/
    sudo cp routes/aws_manager.py $TARGET_DIR/routes/
    sudo cp core_logic.py $TARGET_DIR/
    sudo cp debug_gcp.py $TARGET_DIR/
    
    # Ensure permissions
    sudo chown -R root:root $TARGET_DIR/services/google_service_account.py
    sudo chown -R root:root $TARGET_DIR/routes/aws_manager.py
    sudo chown -R root:root $TARGET_DIR/core_logic.py
    
    echo "✅ Files copied successfully."
fi

# 2. Restart Service
echo "🔄 Restarting Gbot service..."
sudo systemctl restart gbot

# 3. Check Status
echo "📊 Checking status..."
sleep 2
sudo systemctl status gbot --no-pager | head -n 10

echo ""
echo "✅ Fix applied! The new code is now active."
echo "   Please try adding the account in the dashboard now."
