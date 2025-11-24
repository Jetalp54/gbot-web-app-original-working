#!/bin/bash
# Diagnostic Script for GBot Lambda Batch Processing Issue
# This script checks logs to find where 10 users become 1 user

echo "=========================================="
echo "GBot Lambda Batch Processing Diagnostics"
echo "=========================================="
echo ""

# Get the time to search from (default: 30 minutes ago)
if [ -z "$1" ]; then
    SINCE_TIME="30 minutes ago"
else
    SINCE_TIME="$1"
fi

echo "Searching logs since: $SINCE_TIME"
echo ""

echo "=== 1. Background Process Start ==="
sudo journalctl -u gbot --since "$SINCE_TIME" --no-pager | grep -E "BACKGROUND PROCESS|Job ID:|Total users:" | head -10
echo ""

echo "=== 2. Batch Creation (should show 10 users per batch) ==="
sudo journalctl -u gbot --since "$SINCE_TIME" --no-pager | grep "will process.*user" | head -10
echo ""

echo "=== 3. Lambda Invocation Payload (should show 10 users) ==="
sudo journalctl -u gbot --since "$SINCE_TIME" --no-pager | grep -E "PREPARING TO INVOKE|Batch size:|Users in batch:" | head -20
echo ""

echo "=== 4. Lambda Response (should show 10 results) ==="
sudo journalctl -u gbot --since "$SINCE_TIME" --no-pager | grep "Lambda returned.*results" | head -10
echo ""

echo "=== 5. Any Errors ==="
sudo journalctl -u gbot --since "$SINCE_TIME" --no-pager | grep -i "error\|exception\|failed" | grep BULK | head -20
echo ""

echo "=========================================="
echo "Diagnostic Complete"
echo "=========================================="
echo ""
echo "If you don't see logs above, the background process may have crashed."
echo "Run this to see the full logs:"
echo "  sudo journalctl -u gbot --since \"$SINCE_TIME\" --no-pager | tail -100"

