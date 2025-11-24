# 🔧 DynamoDB Table Auto-Creation Fix

## Problem

App passwords were not being saved to DynamoDB. Error logs showed:

```
ResourceNotFoundException: An error occurred (ResourceNotFoundException) when calling the PutItem operation: Requested resource not found
```

**Root Cause**: The DynamoDB table `gbot-app-passwords` didn't exist in the AWS region where the Lambda function was running.

## Solution

Added automatic table creation logic to the Lambda function:

### Changes Made

**File**: `repo_aws_files/main.py`

1. **Added import**:
   ```python
   from botocore.exceptions import ClientError
   ```

2. **Added `ensure_dynamodb_table_exists()` function**:
   - Checks if the DynamoDB table exists
   - Creates the table if it doesn't exist
   - Uses `PAY_PER_REQUEST` billing mode (no upfront costs)
   - Handles race conditions (multiple Lambda invocations trying to create the table)

3. **Enhanced `save_to_dynamodb()` function**:
   - Catches `ResourceNotFoundException` specifically
   - Automatically creates the table if missing
   - Retries the save operation after table creation
   - Provides clear error messages if table creation fails

4. **Added table check at handler start**:
   - Ensures the table exists before processing any users
   - Prevents save failures due to missing table

## How It Works

### Flow:

1. **Handler starts** → Checks if DynamoDB table exists
2. **If table doesn't exist** → Creates it automatically
3. **Users are processed** → Each save operation checks for table existence
4. **If save fails with ResourceNotFoundException**:
   - Creates the table
   - Waits 2 seconds
   - Retries the save operation

### Table Configuration:

- **Table Name**: `gbot-app-passwords` (or from `DYNAMODB_TABLE_NAME` env var)
- **Primary Key**: `email` (String, Hash Key)
- **Billing Mode**: `PAY_PER_REQUEST` (on-demand, pay only for usage)
- **Attributes**:
  - `email` (String) - Primary key
  - `app_password` (String) - Generated app password
  - `secret_key` (String, optional) - TOTP secret (masked)
  - `created_at` (Number) - Unix timestamp
  - `updated_at` (Number) - Unix timestamp

## Expected Behavior

### Before Fix:
```
[ERROR] ResourceNotFoundException: Table not found
→ App passwords not saved
→ User must manually create table in AWS Console
```

### After Fix:
```
[INFO] Table gbot-app-passwords not found. Creating...
[INFO] ✓ Table gbot-app-passwords creation initiated
[INFO] Successfully saved user@example.com to gbot-app-passwords
→ App passwords saved automatically
```

## Important Notes

1. **Table Creation is Asynchronous**:
   - DynamoDB table creation takes 10-30 seconds
   - The Lambda doesn't wait for the table to be fully active
   - First save attempt might fail, but subsequent attempts will succeed
   - The retry logic handles this automatically

2. **Multi-Region Support**:
   - Each AWS region needs its own DynamoDB table
   - The Lambda automatically creates the table in its own region
   - If you have Lambda functions in multiple regions, each will create its own table

3. **Cost**:
   - Table creation: **FREE**
   - Storage: **FREE** (first 25 GB)
   - Writes: ~$1.25 per million
   - Reads: ~$0.25 per million
   - **For 1000 users: ~$0.0015 total**

## Testing

After deploying this fix:

1. **First Lambda Invocation**:
   - Check CloudWatch logs for: `[DYNAMODB] Table gbot-app-passwords not found. Creating...`
   - Table will be created automatically
   - First save might take a few seconds longer (waiting for table)

2. **Subsequent Invocations**:
   - Check CloudWatch logs for: `[DYNAMODB] Table gbot-app-passwords already exists`
   - Saves should work immediately

3. **Verify in AWS Console**:
   - Go to DynamoDB → Tables
   - Should see `gbot-app-passwords` table
   - Check items to verify passwords are being saved

## Deployment

1. **Rebuild Docker Image**:
   ```bash
   # On EC2 build box or local machine
   docker build -t edu-gw-app-password-worker-repo:latest .
   docker tag edu-gw-app-password-worker-repo:latest 470147111686.dkr.ecr.eu-west-1.amazonaws.com/edu-gw-app-password-worker-repo:latest
   aws ecr get-login-password --region eu-west-1 | docker login --username AWS --password-stdin 470147111686.dkr.ecr.eu-west-1.amazonaws.com
   docker push 470147111686.dkr.ecr.eu-west-1.amazonaws.com/edu-gw-app-password-worker-repo:latest
   ```

2. **Push to All Regions** (if needed):
   - Use the "Push ECR Image to All Regions" button in the UI

3. **Test**:
   - Invoke Lambda with a batch of users
   - Check CloudWatch logs for table creation messages
   - Verify passwords are saved to DynamoDB

## Troubleshooting

### If table creation fails:

1. **Check IAM Permissions**:
   - Lambda execution role needs:
     - `dynamodb:CreateTable`
     - `dynamodb:DescribeTable`
     - `dynamodb:PutItem`
     - `dynamodb:GetItem`

2. **Check Region**:
   - Ensure Lambda and DynamoDB are in the same region
   - Table is created in the Lambda's region automatically

3. **Manual Table Creation** (if auto-creation fails):
   - Go to AWS Console → DynamoDB → Create Table
   - Table name: `gbot-app-passwords`
   - Primary key: `email` (String)
   - Billing mode: On-demand

## Files Modified

- `repo_aws_files/main.py`:
  - Added `ensure_dynamodb_table_exists()` function
  - Enhanced `save_to_dynamodb()` with auto-creation and retry logic
  - Added table check at handler start
  - Added `ClientError` import for proper error handling

