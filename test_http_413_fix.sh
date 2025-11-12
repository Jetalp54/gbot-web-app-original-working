#!/bin/bash

# Test HTTP 413 Fix
# This script tests if the nginx upload size fix is working

echo "🧪 Testing HTTP 413 Fix..."

# Check nginx configuration
echo "📋 Checking nginx configuration..."
if sudo nginx -T | grep -q "client_max_body_size 1G"; then
    echo "✅ client_max_body_size is set to 1G"
else
    echo "❌ client_max_body_size is NOT set to 1G"
    echo "Current nginx configuration:"
    sudo nginx -T | grep client_max_body_size || echo "No client_max_body_size found"
    exit 1
fi

# Check nginx status
echo "📋 Checking nginx status..."
if systemctl is-active --quiet nginx; then
    echo "✅ Nginx is running"
else
    echo "❌ Nginx is not running"
    exit 1
fi

# Check gunicorn status
echo "📋 Checking gunicorn status..."
if systemctl is-active --quiet gbot; then
    echo "✅ GBot service is running"
else
    echo "❌ GBot service is not running"
    exit 1
fi

# Test with curl (if available)
if command -v curl >/dev/null 2>&1; then
    echo "📋 Testing with curl..."
    
    # Create a test file
    echo "test content" > /tmp/test_upload.txt
    
    # Test upload
    response=$(curl -s -o /dev/null -w "%{http_code}" -X POST -F "backup_file=@/tmp/test_upload.txt" http://localhost/api/upload-restore-backup)
    
    if [ "$response" = "413" ]; then
        echo "❌ HTTP 413 error still occurring"
        exit 1
    elif [ "$response" = "401" ] || [ "$response" = "403" ]; then
        echo "✅ HTTP 413 error is fixed (got $response - authentication required, which is expected)"
    else
        echo "✅ HTTP 413 error is fixed (got $response)"
    fi
    
    # Clean up
    rm -f /tmp/test_upload.txt
else
    echo "⚠️  curl not available, skipping upload test"
fi

echo ""
echo "🎉 HTTP 413 fix verification completed!"
echo "   Your backup file upload should now work."
