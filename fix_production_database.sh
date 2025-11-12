#!/bin/bash

# Fix PostgreSQL sequence sync issue for whitelisted_ip table
# This script should be run on the production server

echo "🔧 Fixing PostgreSQL sequence sync issue..."

# Check if we're on the production server
if [ ! -f "/etc/nginx/sites-available/gbot" ]; then
    echo "❌ This script should be run on the production server"
    exit 1
fi

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "❌ .env file not found"
    exit 1
fi

# Source the .env file
source .env

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo "❌ DATABASE_URL not found in .env file"
    exit 1
fi

echo "📊 Database URL: $DATABASE_URL"

# Run the PostgreSQL fix script
echo "🚀 Running PostgreSQL sequence fix..."
python3 fix_postgresql_sequence.py

if [ $? -eq 0 ]; then
    echo "✅ Database sequence fix completed successfully!"
    echo ""
    echo "🎉 You should now be able to:"
    echo "  - Add new IP addresses"
    echo "  - Delete existing IP addresses"
    echo "  - Use emergency access without errors"
else
    echo "❌ Database sequence fix failed!"
    exit 1
fi
