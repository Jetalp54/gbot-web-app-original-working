# 🔧 Parallel Processing Resource Exhaustion Fix

## Problem

After implementing parallel processing, all 10 users were failing with Chrome renderer timeout errors:

```
timeout: Timed out receiving message from renderer: 58.842
```

**Root Cause**: Running 10 Chrome instances simultaneously was overwhelming Lambda's resources:
- Each Chrome instance uses ~200-300 MB of memory
- 10 instances = 2-3 GB total memory usage
- Lambda has 2048 MB (2 GB) limit
- Result: Memory exhaustion → Chrome renderer processes hang → Timeout errors

## Solution

### Changes Made

**File**: `repo_aws_files/main.py`

1. **Limited Concurrent Workers**:
   - Changed from `max_workers=len(users_batch)` (10 workers) to `max_workers=3`
   - Only 3 Chrome instances run simultaneously
   - Remaining users queue and start as slots become available

2. **Added Stagger Delay**:
   - Each Chrome instance waits 1 second before starting
   - Spreads out resource usage over time
   - Prevents all instances from initializing at exactly the same moment

### How It Works Now

**Before (Broken)**:
```
All 10 Chrome instances start simultaneously
→ Memory exhaustion (2-3 GB)
→ Renderer timeouts
→ All users fail
```

**After (Fixed)**:
```
3 Chrome instances start (with 1s stagger)
→ Process 3 users
→ As one finishes, next user starts
→ Remaining 7 users queue and process sequentially
→ All users complete successfully
```

## Resource Calculation

- **Lambda Memory**: 2048 MB
- **Chrome Instance**: ~250 MB each
- **Safe Concurrent**: 3 instances = ~750 MB (leaves ~1300 MB for system)
- **10 Users Total**: Processed in batches of 3

## Expected Behavior

### Timeline Example (10 users):

```
T+0s:  User 1, 2, 3 start (staggered by 1s each)
T+12m: User 1, 2, 3 finish
T+12m: User 4, 5, 6 start
T+24m: User 4, 5, 6 finish
T+24m: User 7, 8, 9 start
T+36m: User 7, 8, 9 finish
T+36m: User 10 starts
T+48m: User 10 finishes
```

**Total Time**: ~48 minutes (instead of ~120 minutes sequential, but stable)

## Why This Is Better Than Sequential

- **Sequential**: 10 users × 12 min = 120 minutes total
- **Parallel (3 concurrent)**: ~48 minutes total (2.5x faster)
- **Parallel (10 concurrent)**: Fails due to resource exhaustion

## Important Notes

1. **Memory Safety**: 3 concurrent instances ensures we stay well under Lambda's 2048 MB limit
2. **Stagger Delay**: 1 second delay prevents simultaneous initialization spikes
3. **Automatic Queueing**: ThreadPoolExecutor automatically queues remaining tasks
4. **Still Parallel**: Users 1-3 process simultaneously, then 4-6, etc.

## If You Need More Speed

If you want to process faster (and have Lambda with more memory):

1. **Increase Lambda Memory**:
   - Go to Lambda → Configuration → General
   - Increase memory to 3008 MB or 4096 MB
   - Update `max_concurrent` to 4 or 5

2. **Update Code**:
   ```python
   max_concurrent = min(5, len(users_batch))  # For 4096 MB Lambda
   ```

## Testing

After deploying this fix:

1. **Check Logs**: Should see:
   ```
   [LAMBDA] Using 3 concurrent workers for 10 users
   [LAMBDA] [THREAD] Staggering Chrome start for user 2: waiting 1.0s
   [LAMBDA] [THREAD] Staggering Chrome start for user 3: waiting 2.0s
   ```

2. **Verify Success**: All 10 users should complete without renderer timeout errors

3. **Check Timing**: First 3 users finish together, then next 3, etc.

## Files Modified

- `repo_aws_files/main.py`:
  - Limited `ThreadPoolExecutor` to 3 concurrent workers
  - Added 1-second stagger delay between Chrome initializations
  - Added logging for concurrent worker count and stagger delays

