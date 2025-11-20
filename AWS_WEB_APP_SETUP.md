# Web App Full Independence - Setup Guide

## Prerequisites

Your AWS credentials (Access Key ID + Secret Access Key) MUST have these permissions:

### Required IAM Policies:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:GetRole",
        "iam:AttachRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:CreateInstanceProfile",
        "iam:GetInstanceProfile",
        "iam:AddRoleToInstanceProfile",
        "iam:PassRole",
        "iam:UpdateAssumeRolePolicy"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutBucketVersioning",
        "s3:PutPublicAccessBlock"
      ],
      "Resource": [
        "arn:aws:s3:::edu-gw-app-passwords*",
        "arn:aws:s3:::edu-gw-app-passwords*/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "lambda:*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter"
      ],
      "Resource": "*"
    }
  ]
}
```

## How to Add Permissions in AWS Console

1. Go to AWS Console → IAM → Users
2. Find your user (the one whose Access Key you use in the web app)
3. Click "Add permissions" → "Create inline policy"
4. Paste the JSON above
5. Name it "GBot-WebApp-FullAccess"
6. Click "Create policy"

## Deployment Steps

### 1. Push Updated Files to Server
```bash
# Copy these files to /opt/gbot-web-app-original-working/:
- routes/aws_manager.py
- repo_aws_files/main.py (WITHOUT S3 code)
- repo_aws_files/Dockerfile
- database.py
- update_aws_table.py
```

### 2. On the Server
```bash
cd /opt/gbot-web-app-original-working
source venv/bin/activate

# Create database table
python update_aws_table.py

# Restart service
sudo systemctl restart gbot
```

### 3. In the Web App

**Step 1: Test Connection**
1. Enter your AWS Access Key ID
2. Enter your AWS Secret Access Key
3. Enter Region (eu-west-1)
4. Click "Test Connection"
   - ✅ Should show your Account ID

**Step 2: Create Core Resources** (Tab 1)
1. Click "Create Core Resources (IAM, ECR, S3)"
   - ✅ Should create IAM roles, ECR repo, S3 bucket
   - ❌ If "Access Denied" → Check IAM permissions above

**Step 3: Create EC2 Build Box** (Tab 3)
1. Click "Create / Prepare EC2 Build Box"
   - ✅ Should upload main.py to S3
   - ✅ Should launch EC2 instance
   - ❌ If "Access Denied to S3" → Check S3 permissions
   - ❌ If "Custom main.py not found" → Ensure repo_aws_files/main.py exists on server

2. Wait 5-10 minutes

3. Click "Show EC2 Build Box Status"
   - ⏳ If "BUILD IN PROGRESS" → Wait more
   - ✅ If "BUILD COMPLETED SUCCESSFULLY" → Proceed
   - ❌ If "BUILD FAILED" → Check console output for errors

4. Click "Terminate EC2 Build Box" (to save costs)

**Step 4: Create/Update Lambda** (Tab 2)
1. Fill in SFTP credentials (for secret key storage)
2. Click "Create / Update Production Lambda"
   - ✅ Should create Lambda from ECR image
   - ❌ If "ECR image does not exist" → Re-run Step 3

**Step 5: Test with 1-2 Users**
1. Paste test users in format:
   ```
   user1@domain.com:password1
   user2@domain.com:password2
   ```
2. Click "Invoke Production Lambda"
3. Watch CloudWatch logs (should NOT show S3 errors)
4. Check "Generated App Passwords" field (should populate)

**Step 6: Production Use**
1. Paste 700+ users
2. Click "Invoke Production Lambda"
3. Watch live progress
4. Results appear in "Generated App Passwords" field

## Troubleshooting

### Error: "Access Denied to S3"
**Fix:** Add S3 permissions to your IAM user (see Prerequisites)

### Error: "No module named 'paramiko'"
**Fix:** You're using wrong Lambda type. Delete Lambda and recreate from ECR image (Step 4)

### Error: "Custom main.py not found"
**Fix:** Ensure repo_aws_files/main.py exists on the server at /opt/gbot-web-app-original-working/repo_aws_files/main.py

### Error: "ECR image does not exist"
**Fix:** Run "Create EC2 Build Box" and wait for completion

## Success Indicators

✅ S3 bucket shows: `edu-gw-app-passwords/ec2-build-files/main.py`
✅ ECR repo shows: `edu-gw-app-password-worker-repo:latest` image
✅ Lambda shows: Package type = "Image", Image URI from ECR
✅ CloudWatch logs show: No S3 errors, passwords generated
✅ Web app shows: Live results in "Generated App Passwords"

## Cost Estimate

- S3: ~$0.01/month (minimal storage)
- ECR: ~$0.10/month (image storage)
- Lambda: ~$0.20 per 1000 invocations
- EC2 Build Box: ~$0.02/hour (terminate after build!)

**Total for 700 users/month: ~$0.50/month + $0.14 for processing**

