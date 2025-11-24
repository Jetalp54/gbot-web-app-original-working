#!/bin/bash
# Script to check bulk generation logs specifically

echo "=========================================="
echo "Checking for Bulk Generation Activity"
echo "=========================================="
echo ""

# Check for bulk generation start
echo "=== 1. Bulk Generation Start ==="
sudo journalctl -u gbot --since "1 hour ago" --no-pager | grep -E "bulk-generate|BULK.*BACKGROUND PROCESS|Starting bulk generation" | head -10
echo ""

# Check for batch creation
echo "=== 2. Batch Creation (should show 10 users per batch) ==="
sudo journalctl -u gbot --since "1 hour ago" --no-pager | grep -E "\[BULK\].*will process.*user|\[BULK\].*Creating batches" | head -20
echo ""

# Check for Lambda invocation
echo "=== 3. Lambda Invocation (should show batch size 10) ==="
sudo journalctl -u gbot --since "1 hour ago" --no-pager | grep -E "\[BULK\].*PREPARING TO INVOKE|\[BULK\].*Batch size:" | head -20
echo ""

# Check for any errors
echo "=== 4. Errors ==="
sudo journalctl -u gbot --since "1 hour ago" --no-pager | grep -iE "error|exception|failed" | grep -E "BULK|background" | head -20
echo ""

# Check which endpoint was called
echo "=== 5. API Endpoints Called ==="
sudo journalctl -u gbot --since "1 hour ago" --no-pager | grep -E "POST.*api/aws/(bulk-generate|invoke-lambda)" | head -10
echo ""

echo "=========================================="
echo "If you see no output above, bulk generation"
echo "hasn't been run in the last hour."
echo "=========================================="

