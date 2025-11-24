# 🔧 DynamoDB Fetch Multi-Region Fix

## Problem

The "Fetch from DynamoDB" button was showing 0 app passwords, even though passwords were being saved successfully.

**Root Cause**: **Region Mismatch**
- Lambda functions run in **multiple regions** (one per geo)
- Each Lambda saves passwords to DynamoDB in **its own region**
- The fetch function was only checking **one region** (the region entered in AWS credentials)
- Result: Passwords saved in `us-east-1`, `eu-west-1`, etc., but fetch only checked `eu-west-1` → Found nothing

## Solution

Modified the `fetch_from_dynamodb()` function to check **all available regions** where Lambda functions run.

### Changes Made

**File**: `routes/aws_manager.py`

1. **Multi-Region Search**:
   - Changed from checking 1 region to checking all 17 regions
   - Uses the same `AVAILABLE_GEO_REGIONS` list as Lambda creation
   - Checks each region sequentially until password is found

2. **Improved Error Handling**:
   - Handles `ResourceNotFoundException` (table doesn't exist in region)
   - Handles `UnrecognizedClientException` (credentials not valid for region)
   - Continues to next region if one fails

3. **Better Logging**:
   - Logs which region each password was found in
   - Provides summary of found/not found counts
   - Tracks duplicates to avoid re-checking

## How It Works Now

### Before (Broken):
```
User enters region: eu-west-1
Fetch checks: eu-west-1 only
Passwords saved in: us-east-1, us-west-2, ap-southeast-1, etc.
Result: 0 passwords found ❌
```

### After (Fixed):
```
User enters region: eu-west-1 (used for credentials only)
Fetch checks: All 17 regions
  - us-east-1 → Not found
  - us-east-2 → Not found
  - us-west-1 → Found! ✓
  - us-west-2 → Found! ✓
  - ... (continues checking all regions)
Result: All passwords found ✅
```

## Region List

The function checks these 17 regions (same as Lambda creation):

1. `us-east-1` - US East (N. Virginia)
2. `us-east-2` - US East (Ohio)
3. `us-west-1` - US West (N. California)
4. `us-west-2` - US West (Oregon)
5. `ap-south-1` - Asia Pacific (Mumbai)
6. `ap-northeast-1` - Asia Pacific (Tokyo)
7. `ap-northeast-2` - Asia Pacific (Seoul)
8. `ap-northeast-3` - Asia Pacific (Osaka)
9. `ap-southeast-1` - Asia Pacific (Singapore)
10. `ap-southeast-2` - Asia Pacific (Sydney)
11. `ca-central-1` - Canada (Central)
12. `eu-central-1` - Europe (Frankfurt)
13. `eu-west-1` - Europe (Ireland)
14. `eu-west-2` - Europe (London)
15. `eu-west-3` - Europe (Paris)
16. `eu-north-1` - Europe (Stockholm)
17. `sa-east-1` - South America (São Paulo)

## Expected Behavior

### When Fetching:

1. **User clicks "Fetch from DynamoDB"**
2. **System extracts emails** from "Multiple Accounts" field
3. **For each email**:
   - Checks region 1 → Not found? Continue
   - Checks region 2 → Not found? Continue
   - Checks region 3 → **Found!** → Stop checking, add to results
   - If not found in any region → Mark as "Not found"
4. **Returns results** with region information

### Response Format:

```json
{
  "success": true,
  "results": [
    {
      "email": "user1@example.com",
      "app_password": "abcd****wxyz",
      "created_at": 1763998600,
      "region": "us-west-1",
      "success": true
    },
    {
      "email": "user2@example.com",
      "error": "Not found in DynamoDB (checked all regions)",
      "success": false
    }
  ],
  "summary": {
    "total": 10,
    "found": 8,
    "not_found": 2
  }
}
```

## Performance

- **Sequential Check**: Checks regions one by one until found
- **Early Exit**: Stops checking once password is found
- **Typical Time**: ~1-2 seconds per email (if found in first few regions)
- **Worst Case**: ~5-10 seconds per email (if found in last region or not found)

## Important Notes

1. **Credentials**: The AWS credentials you enter are used to authenticate with all regions
   - Some regions may not be accessible with your credentials (skipped gracefully)
   - The region field in the UI is only used for initial authentication

2. **Table Creation**: Each region has its own DynamoDB table
   - Table is auto-created by Lambda when first password is saved
   - If table doesn't exist in a region, that region is skipped

3. **Duplicates**: If the same email appears multiple times in the input, it's only fetched once

## Testing

After deploying this fix:

1. **Process some users** (they'll be saved to various regions)
2. **Click "Fetch from DynamoDB"**
3. **Check logs** for:
   ```
   [DYNAMODB] Fetching 10 email(s) from DynamoDB across 17 regions...
   [DYNAMODB] ✓ Found user1@example.com in region us-west-1
   [DYNAMODB] ✓ Found user2@example.com in region eu-west-1
   [DYNAMODB] Fetch complete: 10/10 found
   ```
4. **Verify results** show passwords in the output field

## Troubleshooting

### If still showing 0 passwords:

1. **Check if passwords were actually saved**:
   - Go to AWS Console → DynamoDB → Tables
   - Check `gbot-app-passwords` table in various regions
   - Verify items exist

2. **Check email format**:
   - Ensure emails in "Multiple Accounts" field match exactly
   - Case-sensitive: `User@Example.com` ≠ `user@example.com`

3. **Check credentials**:
   - Ensure AWS credentials have `dynamodb:GetItem` permission
   - Some regions may require separate opt-in

4. **Check logs**:
   - Look for `[DYNAMODB]` messages in server logs
   - Check which regions are being checked
   - Look for error messages

## Files Modified

- `routes/aws_manager.py`:
  - Updated `fetch_from_dynamodb()` to check all 17 regions
  - Added region tracking and logging
  - Improved error handling for missing tables/credentials
  - Added summary statistics in response

