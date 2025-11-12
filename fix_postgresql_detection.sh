#!/bin/bash

echo "=== Fixing PostgreSQL Tools Detection Issue ==="

# Check if app.py exists
if [ ! -f "app.py" ]; then
    echo "ERROR: app.py not found in current directory"
    exit 1
fi

echo "✅ Found app.py"

# Create a backup
cp app.py app_backup_$(date +%Y%m%d_%H%M%S).py
echo "✅ Created backup of app.py"

# Fix the PostgreSQL tools detection by adding apt-get check
echo "🔧 Adding apt-get availability check..."

# Use sed to add the apt-get check before the root user check
sed -i '/# Check if we are running as root (no sudo needed)/i\
                    # First check if apt-get is available\
                    apt_check = subprocess.run([\"which\", \"apt-get\"], capture_output=True, text=True, timeout=5)\
                    if apt_check.returncode != 0:\
                        return jsonify({\"success\": False, \"error\": \"PostgreSQL client tools not found and apt-get not available. Please install PostgreSQL client tools manually: sudo apt-get install postgresql-client\"})\
' app.py

echo "✅ Added apt-get availability check"

# Test the app
echo "🧪 Testing app.py syntax..."
python -c "import app; print('✅ App syntax is valid')" 2>&1
if [ $? -eq 0 ]; then
    echo "✅ App.py syntax is valid - fix applied successfully"
else
    echo "❌ App.py has syntax errors - reverting changes"
    mv app_backup_*.py app.py
    exit 1
fi

echo ""
echo "📋 Next steps:"
echo "1. Commit and push the changes:"
echo "   git add app.py"
echo "   git commit -m \"Fix PostgreSQL tools detection - check apt-get availability\""
echo "   git push origin main"
echo ""
echo "2. Pull changes on Ubuntu server:"
echo "   git pull origin main"
echo "   sudo systemctl restart gbot"
