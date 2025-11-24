# 🔍 DIAGNOSTIC GUIDE - Find Why Only 1 User is Processed

## The Mystery
Lambda functions are created correctly across regions, but only process 1 user instead of 10.

## What We Need to Find Out
1. Are batches created with 10 users? (Should see this in logs)
2. Are 10 users sent to Lambda in the payload? (Should see this in logs)
3. Does Lambda receive 10 users? (Check CloudWatch logs)
4. Does Lambda process all 10 users? (Check CloudWatch logs)

---

## 🎯 Step-by-Step Diagnostic Process

### Step 1: Check Flask App Logs (On Ubuntu Server)

Run these commands to see what the Flask app is doing:

```bash
# 1. Check if background process starts
sudo journalctl -u gbot --since "20:24:00" --no-pager | grep "BACKGROUND PROCESS STARTED"

# Expected output:
# [BULK] ========== BACKGROUND PROCESS STARTED ==========
# [BULK] Job ID: 1234567890
# [BULK] Total users: 50
```

```bash
# 2. Check batch creation
sudo journalctl -u gbot --since "20:24:00" --no-pager | grep "Function.*will process.*user"

# Expected output:
# [BULK] Function 1 (us-east-1) will process 10 user(s): ['user1@...', 'user2@...', 'user3@...']...
# [BULK] Function 2 (us-east-2) will process 10 user(s): ['user11@...', 'user12@...', 'user13@...']...
```

```bash
# 3. Check what's being sent to Lambda
sudo journalctl -u gbot --since "20:24:00" --no-pager | grep "PREPARING TO INVOKE" -A 10

# Expected output:
# [BULK] [edu-gw-chromium-useast1-1] PREPARING TO INVOKE LAMBDA
# [BULK] [edu-gw-chromium-useast1-1] Batch size: 10 user(s)
# [BULK] [edu-gw-chromium-useast1-1] Users in batch: ['user1@...', 'user2@...', ..., 'user10@...']
```

```bash
# 4. Check Lambda responses
sudo journalctl -u gbot --since "20:24:00" --no-pager | grep "Lambda returned.*results"

# Expected output:
# [BULK] [edu-gw-chromium-useast1-1] Lambda returned 10 results for 10 users sent
```

---

### Step 2: Check AWS CloudWatch Logs

For each Lambda function, check its CloudWatch logs:

1. Go to AWS Console → CloudWatch → Log groups
2. Find logs like: `/aws/lambda/edu-gw-chromium-useast1-1`
3. Click on the most recent log stream
4. Look for these log lines:

```
Expected in CloudWatch:
[LAMBDA] Handler invoked
[LAMBDA] Event content: {'users': [{'email': '...', 'password': '...'}, ...]}  <-- Should show ALL users
[LAMBDA] Batch processing mode: 10 user(s)  <-- Should say 10, not 1
[LAMBDA] Processing user 1/10: user1@...
[LAMBDA] Processing user 2/10: user2@...
...
[LAMBDA] Processing user 10/10: user10@...
[LAMBDA] Batch processing completed: X success, Y failed
```

---

## 📊 Diagnostic Scenarios

### Scenario A: Flask logs show "Batch size: 1 user(s)"
**Problem:** Batches are being created with only 1 user
**Location:** Flask app batch creation logic (lines 1892-1904)
**Cause:** The user list might not be parsed correctly

### Scenario B: Flask logs show "Batch size: 10 user(s)" but CloudWatch shows "Batch processing mode: 1 user(s)"
**Problem:** 10 users are prepared but only 1 is sent to Lambda
**Location:** Flask app Lambda invocation (lines 1964-1969)
**Cause:** The batch_payload might be constructed incorrectly

### Scenario C: CloudWatch shows "Batch processing mode: 10 user(s)" but only processes 1
**Problem:** Lambda receives 10 users but only processes 1
**Location:** Lambda handler (main.py lines 1665-1683)
**Cause:** The loop might be breaking early

### Scenario D: No logs at all from Flask
**Problem:** Background process is crashing before logging
**Location:** app.app_context() block (lines 1803-2360)
**Cause:** Indentation or context issue

---

## 🚀 Quick Test Commands

Run these all at once to get a complete picture:

```bash
echo "=== 1. Background Process Start ===" && \
sudo journalctl -u gbot --since "20:24:00" --no-pager | grep -E "BACKGROUND PROCESS|Job ID|Total users" | head -10 && \
echo "" && \
echo "=== 2. Batch Creation ===" && \
sudo journalctl -u gbot --since "20:24:00" --no-pager | grep "will process.*user" | head -10 && \
echo "" && \
echo "=== 3. Lambda Invocation ===" && \
sudo journalctl -u gbot --since "20:24:00" --no-pager | grep -E "PREPARING TO INVOKE|Batch size:|Users in batch:" | head -20 && \
echo "" && \
echo "=== 4. Lambda Response ===" && \
sudo journalctl -u gbot --since "20:24:00" --no-pager | grep "Lambda returned.*results" | head -10 && \
echo "" && \
echo "=== 5. Any Errors ===" && \
sudo journalctl -u gbot --since "20:24:00" --no-pager | grep -i "error\|exception\|failed" | grep BULK | head -20
```

---

## 💡 What To Share

After running the commands above, please share:

1. **Output from the "Quick Test Commands"** above
2. **Screenshot of CloudWatch logs** for ONE Lambda function (e.g., `edu-gw-chromium-useast1-1`)
3. **The exact time** you started the bulk generation (e.g., "20:24:17")

This will tell us EXACTLY where the 10 users become 1 user!

---

## 🔧 Common Issues & Fixes

### If you see "Job not found" repeatedly:
- Background process crashed immediately
- Check: `sudo journalctl -u gbot -n 200 | grep -A 10 "IndentationError\|SyntaxError\|Traceback"`

### If logs stop after "BACKGROUND PROCESS STARTED":
- App context issue or unhandled exception
- Check: `sudo journalctl -u gbot --since "20:24:00" --no-pager | tail -100`

### If no logs at all:
- Service not restarted after code changes
- Run: `sudo systemctl restart gbot && sudo journalctl -u gbot -f`

---

## Expected Timeline

For 50 users with 5 functions:
- **00:00** - Bulk generation starts
- **00:01** - Background process starts, creates batches
- **00:02** - First Lambda invoked (10 users)
- **03:00** - First Lambda completes (~3 min for 10 users)
- **03:01** - Second Lambda invoked
- **...** - Continue sequentially per geo
- **~15:00** - All complete

If Lambdas complete in < 1 minute, they're only processing 1 user!

