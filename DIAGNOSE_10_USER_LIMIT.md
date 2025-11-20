# 🔍 Diagnostic Guide: 10 User Limit Issue

## 🎯 Immediate Action Required

Since you're still seeing **exactly 10 log streams**, we need to identify the **exact AWS limit** causing this.

### Step 1: Check AWS Limits (NEW DIAGNOSTIC TOOL)

1. Go to **AWS Management** → **Production Lambda** tab
2. Click **"🔍 Check AWS Limits (Diagnose 10 User Issue)"** button
3. **Review the log output** - it will show:
   - Lambda Reserved Concurrency setting
   - Account-level concurrent execution limits
   - Service quotas
   - Recent max concurrent executions

**This will tell us EXACTLY what's limiting you to 10.**

### Step 2: Review the Diagnostic Output

The diagnostic will show one of these scenarios:

#### Scenario A: Reserved Concurrency = 10
```
⚠️ CRITICAL: Lambda has Reserved Concurrency = 10. This limits concurrent executions to 10!
```
**Fix:** Click "🔧 Fix Concurrency Limit" button

#### Scenario B: Account Limit = 10
```
⚠️ CRITICAL: Account Unreserved Concurrent Executions = 10. This is the hard limit!
```
**Fix:** Request limit increase via AWS Support (this is rare, default is 1000)

#### Scenario C: Service Quota = 10
```
⚠️ Service Quota limits Lambda to 10 concurrent executions
```
**Fix:** Request quota increase via AWS Support Center

#### Scenario D: No Limits Found
```
✅ No obvious limits found
```
**Fix:** The issue might be:
- Backend code not restarted (old code still running)
- Lambda function deployed via SAM/CloudFormation with limits in template
- Network/connection issues on server

---

## 🔧 What We've Fixed (Code Changes)

### 1. Backend (`routes/aws_manager.py`)
- ✅ **Independent boto3 clients per thread** (no connection pool sharing)
- ✅ **1000 worker threads** configured
- ✅ **Aggressive concurrency limit removal** (tries 3 times)

### 2. Lambda Code (`repo_aws_files/main.py`)
- ✅ **Removed S3 race condition function**
- ✅ **Optimized boto3 client caching**

### 3. Lambda Creation
- ✅ **Automatic concurrency limit removal** (on create/update)
- ✅ **Waits for Active state** before modifying settings

---

## 🚨 Most Likely Causes (In Order)

### 1. **Lambda Reserved Concurrency = 10** (90% probability)
- **Symptom:** Exactly 10 log streams, 10/50 success
- **Cause:** Lambda function has `ReservedConcurrentExecutions = 10`
- **Fix:** Use "Check AWS Limits" → "Fix Concurrency Limit" buttons

### 2. **Backend Not Restarted** (5% probability)
- **Symptom:** Code changes not taking effect
- **Fix:** `sudo systemctl restart gbot` on Ubuntu server

### 3. **SAM/CloudFormation Template** (3% probability)
- **Symptom:** Lambda deployed via SAM/CloudFormation with limits in template
- **Fix:** Check `template.yml` for `ReservedConcurrentExecutions` setting

### 4. **Account-Level Limit** (2% probability)
- **Symptom:** Account has custom limit set to 10
- **Fix:** Request increase via AWS Support

---

## 📋 Diagnostic Checklist

Run through this checklist:

- [ ] **Step 1:** Click "Check AWS Limits" button
- [ ] **Step 2:** Review log output for CRITICAL warnings
- [ ] **Step 3:** If Reserved Concurrency found → Click "Fix Concurrency Limit"
- [ ] **Step 4:** Verify server restarted: `sudo systemctl restart gbot`
- [ ] **Step 5:** Rebuild Lambda: EC2 Build Box → Create/Update Lambda
- [ ] **Step 6:** Test with 20 users (should see 20 log streams)

---

## 🔍 Manual AWS Console Check

If the diagnostic tool doesn't work, check manually:

### 1. Lambda Function Settings
```
AWS Console → Lambda → edu-gw-chromium → Configuration → Concurrency
```
**Look for:** "Reserved concurrency" setting
- If it shows **10** → This is your bottleneck!
- If it shows **Unreserved** → Check account limits

### 2. Account Settings
```
AWS Console → Lambda → Account settings
```
**Look for:** "Unreserved account concurrent execution limit"
- Default is **1000**
- If it shows **10** → This is your bottleneck!

### 3. Service Quotas
```
AWS Console → Service Quotas → Lambda → Concurrent executions
```
**Look for:** Quota value
- Default is **1000** per region
- If it shows **10** → Request increase!

---

## 🎯 Next Steps

1. **Run the diagnostic tool** (new button in UI)
2. **Share the log output** - it will show exactly what's limiting you
3. **Apply the fix** based on diagnostic results
4. **Test again** with 20 users

**The diagnostic tool will tell us EXACTLY what's wrong.** 🔍

