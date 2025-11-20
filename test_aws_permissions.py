#!/usr/bin/env python3
"""
Quick script to verify AWS credentials have the required permissions for GBot Web App.
Run this before deploying to ensure your credentials work.
"""
import boto3
import sys

def test_permissions(access_key, secret_key, region):
    """Test if credentials have necessary permissions"""
    print("Testing AWS credentials for GBot Web App...")
    print("=" * 60)
    
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )
    
    results = {
        'passed': [],
        'failed': []
    }
    
    # Test 1: STS (Get Account ID)
    try:
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        print(f"✅ STS: Connected to AWS Account {account_id}")
        results['passed'].append('STS - Get Account ID')
    except Exception as e:
        print(f"❌ STS: Failed - {e}")
        results['failed'].append('STS - Get Account ID')
        return results
    
    # Test 2: S3 (Create/List Bucket)
    try:
        s3 = session.client('s3')
        test_bucket = f"edu-gw-app-passwords-test-{account_id}"
        
        # Try to create bucket
        try:
            if region == 'us-east-1':
                s3.create_bucket(Bucket=test_bucket)
            else:
                s3.create_bucket(
                    Bucket=test_bucket,
                    CreateBucketConfiguration={'LocationConstraint': region}
                )
            print(f"✅ S3: Can create buckets")
            
            # Try to upload object
            s3.put_object(Bucket=test_bucket, Key='test.txt', Body=b'test')
            print(f"✅ S3: Can upload objects")
            
            # Cleanup
            s3.delete_object(Bucket=test_bucket, Key='test.txt')
            s3.delete_bucket(Bucket=test_bucket)
            print(f"✅ S3: Test cleanup successful")
            
            results['passed'].append('S3 - Full access')
        except s3.exceptions.BucketAlreadyExists:
            print(f"⚠️  S3: Bucket exists, testing upload...")
            test_bucket = "edu-gw-app-passwords"
            s3.put_object(Bucket=test_bucket, Key='test.txt', Body=b'test')
            print(f"✅ S3: Can upload to existing bucket")
            results['passed'].append('S3 - Upload to existing bucket')
    except Exception as e:
        print(f"❌ S3: Failed - {e}")
        results['failed'].append('S3 - Create/Upload')
    
    # Test 3: IAM (Create Role)
    try:
        iam = session.client('iam')
        test_role = f"edu-gw-test-role-{int(time.time())}"
        
        assume_role_doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }
        
        import json
        iam.create_role(
            RoleName=test_role,
            AssumeRolePolicyDocument=json.dumps(assume_role_doc)
        )
        print(f"✅ IAM: Can create roles")
        
        # Cleanup
        iam.delete_role(RoleName=test_role)
        results['passed'].append('IAM - Create roles')
    except Exception as e:
        print(f"❌ IAM: Failed - {e}")
        results['failed'].append('IAM - Create roles')
    
    # Test 4: ECR (Create Repository)
    try:
        ecr = session.client('ecr')
        test_repo = f"edu-gw-test-repo"
        
        try:
            ecr.create_repository(repositoryName=test_repo)
            print(f"✅ ECR: Can create repositories")
            
            # Cleanup
            ecr.delete_repository(repositoryName=test_repo, force=True)
            results['passed'].append('ECR - Full access')
        except ecr.exceptions.RepositoryAlreadyExistsException:
            print(f"✅ ECR: Repository exists, can access")
            results['passed'].append('ECR - Access existing')
    except Exception as e:
        print(f"❌ ECR: Failed - {e}")
        results['failed'].append('ECR - Create repositories')
    
    # Test 5: Lambda (List Functions)
    try:
        lam = session.client('lambda')
        lam.list_functions(MaxItems=1)
        print(f"✅ Lambda: Can list functions")
        results['passed'].append('Lambda - List functions')
    except Exception as e:
        print(f"❌ Lambda: Failed - {e}")
        results['failed'].append('Lambda - List functions')
    
    # Test 6: EC2 (Describe Instances)
    try:
        ec2 = session.client('ec2')
        ec2.describe_instances(MaxResults=5)
        print(f"✅ EC2: Can describe instances")
        results['passed'].append('EC2 - Describe instances')
    except Exception as e:
        print(f"❌ EC2: Failed - {e}")
        results['failed'].append('EC2 - Describe instances')
    
    return results

if __name__ == "__main__":
    import time
    
    print("\n🔐 AWS Credentials Permission Checker for GBot Web App")
    print("=" * 60)
    print()
    
    # Get credentials from user
    access_key = input("Enter AWS Access Key ID: ").strip()
    secret_key = input("Enter AWS Secret Access Key: ").strip()
    region = input("Enter AWS Region [eu-west-1]: ").strip() or "eu-west-1"
    
    print()
    print("Testing permissions...")
    print()
    
    results = test_permissions(access_key, secret_key, region)
    
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"✅ Passed: {len(results['passed'])}")
    for item in results['passed']:
        print(f"   - {item}")
    
    if results['failed']:
        print(f"\n❌ Failed: {len(results['failed'])}")
        for item in results['failed']:
            print(f"   - {item}")
        print()
        print("⚠️  WARNING: Some permissions are missing!")
        print("Please add the required IAM policies to your AWS user.")
        print("See AWS_WEB_APP_SETUP.md for details.")
        sys.exit(1)
    else:
        print()
        print("✅ ALL TESTS PASSED!")
        print("Your AWS credentials are ready for GBot Web App.")
        sys.exit(0)

