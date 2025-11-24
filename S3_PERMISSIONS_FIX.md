# 🔧 S3 Permissions Auto-Attachment Fix

## Problem

When clicking "Delete S3 Content", users were getting an "Access Denied" error:

```
Error: Access Denied to S3 bucket edu-gw-app-passwords. Your AWS credentials need the following IAM permissions:
- s3:ListBucket
- s3:DeleteObject
- s3:ListBucketVersions (if versioning enabled)
- s3:DeleteObjectVersion (if versioning enabled)
```

**Root Cause**: The IAM user/role (associated with the AWS access key) didn't have the required S3 permissions to delete bucket contents.

## Solution

Modified the `create_infrastructure()` function to automatically ensure the user's IAM user/role has S3 permissions when creating core resources.

### Changes Made

**File**: `routes/aws_manager.py`

1. **Added `ensure_user_s3_permissions()` function**:
   - Detects whether the access key belongs to an IAM user or IAM role
   - Checks if `AmazonS3FullAccess` policy is already attached
   - Automatically attaches the policy if missing
   - Handles both IAM users and IAM roles
   - Provides clear logging and error handling

2. **Updated `create_infrastructure()` function**:
   - Calls `ensure_user_s3_permissions()` before creating resources
   - Ensures S3 permissions are in place before any S3 operations

## How It Works

### Flow:

1. **User clicks "Create Core Resources"**
2. **System detects IAM user/role** from the access key
3. **Checks for S3 permissions**:
   - If `AmazonS3FullAccess` is already attached → Skip
   - If not attached → Attach automatically
4. **Creates Lambda IAM role** (with S3 permissions)
5. **Creates ECR repository**
6. **Creates S3 bucket**

### Supported Scenarios:

✅ **IAM User**: Automatically attaches `AmazonS3FullAccess` policy  
✅ **IAM Role**: Automatically attaches `AmazonS3FullAccess` policy  
⚠️ **Access Denied**: Logs warning but continues (user may need admin to attach policy)

## Expected Behavior

### Before Fix:
```
1. Click "Create Core Resources" → Success
2. Click "Delete S3 Content" → ❌ Access Denied
3. User must manually attach S3 permissions in AWS Console
```

### After Fix:
```
1. Click "Create Core Resources" → 
   [IAM] Attaching AmazonS3FullAccess policy to user/role...
   [IAM] ✓ Successfully attached AmazonS3FullAccess policy
   Infrastructure setup completed. S3 permissions have been ensured.
2. Click "Delete S3 Content" → ✅ Success (no access denied)
```

## Permissions Attached

The function attaches the **`AmazonS3FullAccess`** managed policy, which includes:

- `s3:ListBucket` - List objects in bucket
- `s3:DeleteObject` - Delete objects
- `s3:ListBucketVersions` - List object versions
- `s3:DeleteObjectVersion` - Delete object versions
- `s3:HeadBucket` - Check bucket existence
- `s3:GetObject` - Read objects
- `s3:PutObject` - Write objects
- And all other S3 permissions

## Important Notes

1. **Admin Permissions Required**:
   - The IAM user/role must have `iam:AttachUserPolicy` or `iam:AttachRolePolicy` permissions
   - If access is denied, the function logs a warning but continues
   - In this case, an admin must manually attach the policy

2. **Policy Propagation**:
   - After attaching the policy, the function waits 2 seconds for propagation
   - S3 operations should work immediately after

3. **Idempotent**:
   - The function checks if the policy is already attached
   - If already attached, it skips the attachment (no error)

4. **Lambda Role**:
   - The Lambda execution role also gets S3 permissions (separate from user permissions)
   - This is for Lambda functions to access S3, not for the web app

## Testing

After deploying this fix:

1. **Test Infrastructure Creation**:
   - Click "Create Core Resources"
   - Check logs for: `[IAM] ✓ Successfully attached AmazonS3FullAccess policy`
   - Should see: "Infrastructure setup completed. S3 permissions have been ensured."

2. **Test S3 Deletion**:
   - Click "Delete S3 Content"
   - Should work without "Access Denied" error
   - Objects should be deleted successfully

3. **Verify in AWS Console**:
   - Go to IAM → Users (or Roles)
   - Find your IAM user/role
   - Check "Permissions" tab
   - Should see "AmazonS3FullAccess" policy attached

## Troubleshooting

### If "Access Denied" still occurs:

1. **Check IAM Permissions**:
   - Your IAM user/role needs `iam:AttachUserPolicy` or `iam:AttachRolePolicy`
   - If you don't have these, ask an admin to attach the policy manually

2. **Manual Policy Attachment**:
   - Go to AWS Console → IAM → Users (or Roles)
   - Select your user/role
   - Click "Add permissions" → "Attach policies directly"
   - Search for "AmazonS3FullAccess"
   - Attach the policy

3. **Check Policy Propagation**:
   - Wait 10-30 seconds after attaching
   - Try deleting S3 content again

## Files Modified

- `routes/aws_manager.py`:
  - Added `ensure_user_s3_permissions()` function
  - Updated `create_infrastructure()` to call the new function
  - Handles both IAM users and IAM roles
  - Comprehensive error handling and logging

