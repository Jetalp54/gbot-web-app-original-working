# Duplicate Lambda Invocation Fix

## Problem Identified

The web app was invoking the Lambda **multiple times for the same user**, causing:
- Wasted Lambda executions (costs)
- Race conditions (first invocation sets up 2FA, second fails because 2FA already exists)
- Confusion in the logs

### Evidence from CloudWatch Logs:

Two concurrent invocations for `jasonmontgomerygzaoub@alfred.pxlrbldlnk.pxlrbldlnk.com`:

1. **Request ID: 51b408dd** (started 14:54:00) - **SUCCESS**
   - Set up 2FA from scratch
   - Generated app password: `zqkj****fdde`
   - Duration: 124 seconds

2. **Request ID: f7d3e738** (started 14:54:59) - **FAILED**
   - Tried to set up 2FA but user already had it
   - Failed: "2FA required but secret is unknown"
   - Duration: 18 seconds

## Root Cause

The duplicate invocations were caused by:

1. **Frontend: No double-click protection**
   - Button `onclick="invokeProductionLambda()"` had no flag to prevent multiple clicks
   - If user clicked twice quickly (or page lagged), multiple API calls were sent

2. **Backend: No deduplication**
   - No check to see if an email was already being processed
   - ThreadPoolExecutor processed all requests, even duplicates

## Solutions Implemented

### Frontend Fix (`templates/aws_management.html`)

Added a global flag `isProcessing` to prevent duplicate button clicks:

```javascript
let isProcessing = false;

function invokeProductionLambda() {
    // Prevent duplicate invocations
    if (isProcessing) {
        log('⚠️ WARNING: A bulk job is already running. Please wait for it to complete.');
        alert('A bulk job is already running. Please wait for it to complete.');
        return;
    }
    
    // ... validation code ...
    
    // Set flag before starting job
    isProcessing = true;
    invokeMultipleAccounts(usersRaw);
}

function invokeMultipleAccounts(users) {
    fetch('/api/aws/bulk-generate', { /* ... */ })
        .then(data => {
            if (data.success) {
                pollJobStatus(data.job_id);
            } else {
                isProcessing = false; // Reset on error
            }
        })
        .catch(error => {
            isProcessing = false; // Reset on error
        });
}

function pollJobStatus(jobId) {
    // ... polling code ...
    if (job.status === 'completed') {
        isProcessing = false; // Reset when job completes
    }
}
```

**Benefits:**
- ✅ Prevents accidental double-clicks
- ✅ Shows clear warning if user tries to start another job
- ✅ Resets flag when job completes or errors

### Backend Fix (`routes/aws_manager.py`)

Added a global set `processing_emails` to track which emails are currently being processed:

```python
# Global set to track emails currently being processed (prevent duplicates within a job)
processing_emails = set()
processing_lock = threading.Lock()

def process_single_user(user):
    with app.app_context():
        email = user['email']
        
        # Check if email is already being processed (deduplicate)
        with processing_lock:
            if email in processing_emails:
                logger.warning(f"[BULK] ⚠️ SKIPPED: {email} is already being processed")
                return {'email': email, 'success': False, 'error': 'Duplicate - already processing'}
            processing_emails.add(email)
        
        try:
            # ... Lambda invocation code ...
            return {'email': email, 'success': True, 'app_password': data['app_password']}
        except Exception as e:
            return {'email': email, 'success': False, 'error': str(e)}
        finally:
            # Remove from processing set when done
            with processing_lock:
                processing_emails.discard(email)
```

**Benefits:**
- ✅ Thread-safe deduplication using `threading.Lock()`
- ✅ Skips duplicate emails if somehow multiple requests make it through
- ✅ Automatically cleans up (`finally` block ensures email is removed from set)
- ✅ Works even if you have multiple gunicorn workers (within same process)

## Testing

After deploying these changes:

1. **Single User Test:**
   - Paste 1 user
   - Click "Invoke Production Lambda"
   - Try clicking again immediately → Should show warning

2. **Duplicate User Test:**
   - Paste the same user 4 times:
     ```
     user@domain.com:password
     user@domain.com:password
     user@domain.com:password
     user@domain.com:password
     ```
   - Click "Invoke Production Lambda"
   - Expected: 1 success, 3 skipped ("Duplicate - already processing")

3. **Multiple Users Test:**
   - Paste 10 different users
   - Click "Invoke Production Lambda"
   - Watch CloudWatch logs → Should see exactly 10 unique invocations

## Expected Behavior Now

✅ **Before (Broken):**
- Paste 4 users → Get 8 Lambda invocations (duplicates)
- CloudWatch shows: "jasonmontgomery..." invoked 2x

✅ **After (Fixed):**
- Paste 4 users → Get 4 Lambda invocations (no duplicates)
- CloudWatch shows: Each email invoked exactly once
- If user is pasted twice, second is skipped with clear log message

## Deployment

1. Push updated files:
   - `templates/aws_management.html`
   - `routes/aws_manager.py`

2. On server:
   ```bash
   cd /opt/gbot-web-app-original-working
   sudo systemctl restart gbot
   ```

3. Test with 2-3 users first
4. Then scale to 700+

## Notes

- The fix is **backward compatible** - no database changes needed
- The `processing_emails` set is in-memory and cleared automatically when threads complete
- If server restarts mid-job, the set is cleared (safe)
- Frontend flag resets on page reload (expected behavior)

