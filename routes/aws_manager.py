"""
AWS Management routes for AWS infrastructure, Lambda, and EC2 management.
"""
import os
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
import json
import io
import zipfile
import time
import traceback
import logging
import threading
import random
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Blueprint, request, jsonify, session, render_template, copy_current_request_context
from functools import wraps
from database import db, UserAppPassword, AwsGeneratedPassword, AwsConfig

# Constants from aws.py
LAMBDA_ROLE_NAME = "edu-gw-app-password-lambda-role"
PRODUCTION_LAMBDA_NAME = "edu-gw-chromium"
S3_BUCKET_NAME = "edu-gw-app-passwords"
ECR_REPO_NAME = "edu-gw-app-password-worker-repo"
ECR_IMAGE_TAG = "latest"
EC2_INSTANCE_NAME = "edu-gw-ec2-build-box"
EC2_ROLE_NAME = "edu-gw-ec2-build-role"
EC2_INSTANCE_PROFILE_NAME = "edu-gw-ec2-build-instance-profile"
EC2_SECURITY_GROUP_NAME = "edu-gw-ec2-build-sg"
EC2_KEY_PAIR_NAME = "edu-gw-ec2-build-key"

logger = logging.getLogger(__name__)

aws_manager = Blueprint('aws_manager', __name__)

# Global executor for background tasks
executor = ThreadPoolExecutor(max_workers=20)
active_jobs = {}
jobs_lock = threading.Lock()  # Lock for job storage

# Global set to track emails currently being processed (prevent duplicates within a job)
processing_emails = set()
processing_lock = threading.Lock()

# Rate limiting semaphore - AWS account limit is typically 10-100 concurrent executions
# Using 10 as safe default (can be increased if account limit is higher)
MAX_CONCURRENT_LAMBDA_INVOCATIONS = 10
lambda_invocation_semaphore = threading.Semaphore(MAX_CONCURRENT_LAMBDA_INVOCATIONS)

# Login required decorator
def login_required(f):
    """Decorator to require login"""
    from flask import redirect, url_for
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def get_boto3_session(access_key, secret_key, region):
    """Create boto3 session from credentials"""
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

def get_account_id(session):
    """Get AWS account ID"""
    sts = session.client("sts")
    ident = sts.get_caller_identity()
    return ident["Account"]

@aws_manager.route('/aws')
@login_required
def aws_management():
    """AWS Management page"""
    # Ensure table exists to prevent 500 errors if migration wasn't run
    try:
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        if 'aws_generated_password' not in tables:
            db.create_all()
        if 'aws_config' not in tables:
            db.create_all()
    except Exception as e:
        logger.error(f"Auto-migration failed: {e}")
    
    return render_template('aws_management.html', user=session.get('user'), role=session.get('role'))

@aws_manager.route('/api/aws/test-connection', methods=['POST'])
@login_required
def test_connection():
    """Test AWS connection"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide Access Key, Secret Key and Region.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        account_id = get_account_id(session)
        ecr_uri = f"{account_id}.dkr.ecr.{region}.amazonaws.com/{ECR_REPO_NAME}:{ECR_IMAGE_TAG}"

        return jsonify({
            'success': True,
            'account_id': account_id,
            'region': region,
            'ecr_uri': ecr_uri
        })
    except Exception as e:
        logger.error(f"Error testing connection: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/save-config', methods=['POST'])
@login_required
def save_aws_config():
    """Save AWS credentials configuration"""
    try:
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
        
        # Ensure table exists
        try:
            inspector = db.inspect(db.engine)
            if 'aws_config' not in inspector.get_table_names():
                db.create_all()
        except Exception as e:
            logger.warning(f"Could not check/create aws_config table: {e}")
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        access_key_id = data.get('access_key_id', '').strip()
        secret_access_key = data.get('secret_access_key', '').strip()
        region = data.get('region', 'us-east-1').strip()
        ecr_uri = data.get('ecr_uri', '').strip()
        s3_bucket = data.get('s3_bucket', 'edu-gw-app-passwords').strip()

        if not access_key_id or not secret_access_key or not region:
            return jsonify({'success': False, 'error': 'Please provide Access Key ID, Secret Access Key and Region.'}), 400

        # Get or create config
        config = AwsConfig.query.first()
        if not config:
            config = AwsConfig()
            db.session.add(config)
            logger.info("[AWS_CONFIG] Creating new AWS config entry")
        else:
            logger.info("[AWS_CONFIG] Updating existing AWS config entry")
        
        # Update config
        config.access_key_id = access_key_id
        config.secret_access_key = secret_access_key
        config.region = region
        config.ecr_uri = ecr_uri if ecr_uri and ecr_uri != '(connect first)' else None
        config.s3_bucket = s3_bucket
        config.is_configured = True
        
        # Commit the changes
        db.session.commit()
        logger.info("[AWS_CONFIG] ✓ AWS configuration saved successfully")
        
        return jsonify({'success': True, 'message': 'AWS configuration saved successfully'})
    except Exception as e:
        logger.error(f"Error saving AWS config: {e}")
        logger.error(traceback.format_exc())
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/get-config', methods=['GET'])
@login_required
def get_aws_config():
    """Get AWS credentials configuration"""
    try:
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
        
        # Ensure table exists
        try:
            inspector = db.inspect(db.engine)
            if 'aws_config' not in inspector.get_table_names():
                db.create_all()
        except Exception as e:
            logger.warning(f"Could not check/create aws_config table: {e}")
        
        config = AwsConfig.query.first()
        if not config or not config.is_configured:
            logger.info("[AWS_CONFIG] No AWS configuration found")
            return jsonify({
                'success': True,
                'config': None,
                'message': 'No AWS configuration found'
            })
        
        logger.info("[AWS_CONFIG] ✓ AWS configuration loaded successfully")
        return jsonify({
            'success': True,
            'config': {
                'access_key_id': config.access_key_id,
                'secret_access_key': config.secret_access_key,  # Note: In production, consider encrypting this
                'region': config.region,
                'ecr_uri': config.ecr_uri or '',
                's3_bucket': config.s3_bucket
            }
        })
    except Exception as e:
        logger.error(f"Error getting AWS config: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/create-dynamodb', methods=['POST'])
@login_required
def create_dynamodb_table():
    """Create DynamoDB table for app password storage"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        dynamodb = session.client('dynamodb')
        table_name = "gbot-app-passwords"
        
        try:
            # Check if table exists
            dynamodb.describe_table(TableName=table_name)
            return jsonify({'success': True, 'message': f'Table {table_name} already exists'})
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                raise
            
            # Create table
            logger.info(f"[DYNAMODB] Creating table {table_name}...")
            dynamodb.create_table(
                TableName=table_name,
                KeySchema=[
                    {'AttributeName': 'email', 'KeyType': 'HASH'}  # Partition key
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'email', 'AttributeType': 'S'}
                ],
                BillingMode='PAY_PER_REQUEST'  # On-demand pricing (no provisioned capacity)
            )
            
            # Wait for table to be created
            waiter = dynamodb.get_waiter('table_exists')
            waiter.wait(TableName=table_name, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})
            
            logger.info(f"[DYNAMODB] ✓ Table {table_name} created successfully")
            return jsonify({'success': True, 'message': f'Table {table_name} created successfully'})
            
    except Exception as e:
        logger.error(f"Error creating DynamoDB table: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/create-infrastructure', methods=['POST'])
@login_required
def create_infrastructure():
    """Create core AWS infrastructure (IAM, ECR, S3)"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide Access Key, Secret Key and Region.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        
        # Create IAM role
        lambda_policies = [
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
            "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        ]
        role_arn = create_iam_role(session, LAMBDA_ROLE_NAME, "lambda.amazonaws.com", lambda_policies)

        # Create ECR repo
        create_ecr_repo(session, region)

        # Create S3 bucket
        create_s3_bucket(session, region)

        return jsonify({
            'success': True,
            'role_arn': role_arn,
            'message': 'Infrastructure setup completed.'
        })
    except Exception as e:
        logger.error(f"Error creating infrastructure: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/create-ecr-manual', methods=['POST'])
@login_required
def create_ecr_manual():
    """Manually create ECR repository"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide Access Key, Secret Key and Region.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        create_ecr_repo(session, region)

        ecr = session.client("ecr")
        resp = ecr.describe_repositories(repositoryNames=[ECR_REPO_NAME])
        repo_uri = resp['repositories'][0]['repositoryUri']

        return jsonify({
            'success': True,
            'repo_uri': repo_uri
        })
    except Exception as e:
        logger.error(f"Error creating ECR repository: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/inspect-resources', methods=['POST'])
@login_required
def inspect_resources():
    """Inspect AWS resources"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide Access Key, Secret Key and Region.'}), 400

        session = get_boto3_session(access_key, secret_key, region)

        # Inspect IAM
        iam_roles = inspect_iam(session)
        ecr_repos = inspect_ecr(session)
        s3_buckets = inspect_s3(session)
        lambdas = inspect_lambdas(session)

        return jsonify({
            'success': True,
            'iam_roles': iam_roles,
            'ecr_repos': ecr_repos,
            's3_buckets': s3_buckets,
            'lambdas': lambdas
        })
    except Exception as e:
        logger.error(f"Error inspecting resources: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/create-lambdas', methods=['POST'])
@login_required
def create_lambdas():
    """Create/Update production Lambda(s) based on user count"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()
        ecr_uri = data.get('ecr_uri', '').strip()
        s3_bucket = data.get('s3_bucket', '').strip()
        user_count = data.get('user_count', 0)  # Number of users (auto-calculated from input field)
        users_per_function = 10  # Fixed at 10 users per function as requested
        create_multiple = data.get('create_multiple', False)  # Whether to create multiple functions

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        if not ecr_uri or 'amazonaws.com' not in ecr_uri:
            return jsonify({'success': False, 'error': 'ECR Image URI is not set. Connect and prepare EC2 build box first.'}), 400

        if not s3_bucket:
            return jsonify({'success': False, 'error': 'Please enter S3 Bucket name for app passwords storage.'}), 400

        session = get_boto3_session(access_key, secret_key, region)

        # Verify ECR image exists
        ecr = session.client("ecr")
        try:
            ecr.describe_images(
                repositoryName=ECR_REPO_NAME,
                imageIds=[{"imageTag": ECR_IMAGE_TAG}],
            )
        except ClientError as ce:
            return jsonify({
                'success': False,
                'error': 'ECR image does not appear to exist yet. Launch EC2 build box, wait a few minutes, then try again.'
            }), 400

        # Ensure IAM role
        role_arn = ensure_lambda_role(session)

        # Environment variables (removed SFTP)
        chromium_env = {
            "DYNAMODB_TABLE_NAME": "gbot-app-passwords",  # DynamoDB table for password storage
            "APP_PASSWORDS_S3_BUCKET": s3_bucket,
            "APP_PASSWORDS_S3_KEY": "app-passwords.txt",
        }

        # Calculate number of Lambda functions to create
        if create_multiple and user_count > 0 and users_per_function > 0:
            num_functions = (user_count + users_per_function - 1) // users_per_function  # Ceiling division
            num_functions = max(1, num_functions)  # At least 1 function
            logger.info(f"[LAMBDA] Creating {num_functions} Lambda function(s) for {user_count} users ({users_per_function} users per function)")
        else:
            num_functions = 1
            logger.info(f"[LAMBDA] Creating single Lambda function")

        # Return immediately and create functions in background to avoid nginx timeout
        # Creating 5 functions sequentially can take 5+ minutes, which exceeds nginx timeout
        created_functions = []
        for i in range(num_functions):
            if num_functions == 1:
                function_name = PRODUCTION_LAMBDA_NAME
            else:
                function_name = f"{PRODUCTION_LAMBDA_NAME}-{i+1}"
            created_functions.append(function_name)
        
        # Start background thread to create/update Lambda functions
        # Use 900 seconds (15 minutes) timeout for batch processing (10 users can take 5-10 minutes)
        def create_lambdas_background(session, function_names, role_arn, timeout, env_vars, package_type, image_uri):
            try:
                for function_name in function_names:
                    try:
                        create_or_update_lambda(
                            session=session,
                            function_name=function_name,
                            role_arn=role_arn,
                            timeout=timeout,
                            env_vars=env_vars,
                            package_type=package_type,
                            image_uri=image_uri,
                        )
                        logger.info(f"[LAMBDA] ✓ Created/Updated Lambda: {function_name}")
                    except Exception as func_error:
                        logger.error(f"[LAMBDA] ✗ Failed to create/update {function_name}: {func_error}")
                        logger.error(traceback.format_exc())
            except Exception as bg_error:
                logger.error(f"[LAMBDA] Background Lambda creation error: {bg_error}")
                logger.error(traceback.format_exc())
        
        # Start background thread
        # Use 900 seconds (15 minutes) - AWS Lambda maximum timeout
        # This allows processing up to 10 users per batch (each user takes ~30-60 seconds)
        threading.Thread(
            target=create_lambdas_background,
            args=(session, created_functions, role_arn, 900, chromium_env, "Image", ecr_uri),
            daemon=True
        ).start()
        
        message = f'Started creating/updating {len(created_functions)} Lambda function(s): {", ".join(created_functions)}'
        if create_multiple:
            message += f' (for {user_count} users, {users_per_function} users per function). Functions are being created in the background.'
        else:
            message += '. Function is being created in the background.'

        return jsonify({
            'success': True,
            'message': message,
            'functions_created': created_functions,
            'num_functions': len(created_functions),
            'note': 'Lambda functions are being created/updated in the background. This may take a few minutes.'
        })
    except Exception as e:
        logger.error(f"Error creating Lambda: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/check-aws-limits', methods=['POST'])
@login_required
def check_aws_limits():
    """Check ALL AWS limits that could affect Lambda concurrency"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        lam = session.client("lambda")
        service_quotas = session.client("service-quotas", region_name=region)
        
        limits_info = {
            'lambda_function': {},
            'account_limits': {},
            'service_quotas': {},
            'recommendations': []
        }
        
        # 1. Check Lambda Function Concurrency Settings
        try:
            func_config = lam.get_function_configuration(FunctionName=PRODUCTION_LAMBDA_NAME)
            limits_info['lambda_function']['name'] = PRODUCTION_LAMBDA_NAME
            limits_info['lambda_function']['state'] = func_config.get('State', 'Unknown')
            limits_info['lambda_function']['state_reason'] = func_config.get('StateReason', 'N/A')
            
            # Check Reserved Concurrency
            try:
                concurrency_config = lam.get_function_concurrency(FunctionName=PRODUCTION_LAMBDA_NAME)
                reserved = concurrency_config.get('ReservedConcurrentExecutions')
                limits_info['lambda_function']['reserved_concurrency'] = reserved
                if reserved and reserved < 1000:
                    limits_info['recommendations'].append(
                        f"⚠️ CRITICAL: Lambda has Reserved Concurrency = {reserved}. This limits concurrent executions to {reserved}!"
                    )
            except lam.exceptions.ResourceNotFoundException:
                limits_info['lambda_function']['reserved_concurrency'] = None
                limits_info['lambda_function']['reserved_concurrency_status'] = "Unreserved (Good - uses account limit)"
            
            # Check Provisioned Concurrency
            try:
                prov_configs = lam.list_provisioned_concurrency_configs(FunctionName=PRODUCTION_LAMBDA_NAME)
                if prov_configs.get('ProvisionedConcurrencyConfigs'):
                    limits_info['lambda_function']['provisioned_concurrency'] = prov_configs['ProvisionedConcurrencyConfigs']
                    limits_info['recommendations'].append(
                        "⚠️ Provisioned Concurrency is set (this doesn't limit, but costs money)"
                    )
                else:
                    limits_info['lambda_function']['provisioned_concurrency'] = None
            except Exception as e:
                limits_info['lambda_function']['provisioned_concurrency_error'] = str(e)
                
        except lam.exceptions.ResourceNotFoundException:
            limits_info['lambda_function']['error'] = f"Lambda function {PRODUCTION_LAMBDA_NAME} not found"
            limits_info['recommendations'].append("❌ Lambda function does not exist. Create it first.")
        except Exception as e:
            limits_info['lambda_function']['error'] = str(e)
        
        # 2. Check Account-Level Limits
        try:
            account_settings = lam.get_account_settings()
            account_limits = account_settings.get('AccountLimit', {})
            limits_info['account_limits']['total_concurrent_executions'] = account_limits.get('TotalCodeSize', 'N/A')
            limits_info['account_limits']['unreserved_concurrent_executions'] = account_limits.get('UnreservedConcurrentExecutions', 'N/A')
            
            # This is the KEY limit!
            unreserved = account_limits.get('UnreservedConcurrentExecutions')
            if unreserved and unreserved < 1000:
                limits_info['recommendations'].append(
                    f"⚠️ CRITICAL: Account Unreserved Concurrent Executions = {unreserved}. This is the hard limit!"
                )
            elif unreserved:
                limits_info['account_limits']['status'] = f"✅ Account limit is {unreserved} (sufficient for 1000+ users)"
        except Exception as e:
            limits_info['account_limits']['error'] = str(e)
            limits_info['recommendations'].append(f"Could not check account limits: {e}")
        
        # 3. Check Service Quotas (if available)
        try:
            # Try to get Lambda concurrent executions quota
            quota_code = "L-B99A9384"  # Lambda concurrent executions quota code
            try:
                quota = service_quotas.get_service_quota(
                    ServiceCode='lambda',
                    QuotaCode=quota_code
                )
                quota_value = quota['Quota']['Value']
                limits_info['service_quotas']['lambda_concurrent_executions'] = quota_value
                if quota_value < 1000:
                    limits_info['recommendations'].append(
                        f"⚠️ Service Quota limits Lambda to {quota_value} concurrent executions. Request increase via AWS Support."
                    )
            except service_quotas.exceptions.NoSuchResourceException:
                limits_info['service_quotas']['lambda_concurrent_executions'] = "Not found (using default)"
            except Exception as e:
                limits_info['service_quotas']['error'] = str(e)
        except Exception as e:
            limits_info['service_quotas']['error'] = f"Service Quotas API not available: {e}"
        
        # 4. Check current concurrent executions (if possible)
        try:
            # Get function metrics
            cloudwatch = session.client('cloudwatch', region_name=region)
            end_time = time.time()
            start_time = end_time - 300  # Last 5 minutes
            
            metrics = cloudwatch.get_metric_statistics(
                Namespace='AWS/Lambda',
                MetricName='ConcurrentExecutions',
                Dimensions=[
                    {'Name': 'FunctionName', 'Value': PRODUCTION_LAMBDA_NAME}
                ],
                StartTime=time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(start_time)),
                EndTime=time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(end_time)),
                Period=60,
                Statistics=['Maximum']
            )
            
            if metrics.get('Datapoints'):
                max_concurrent = max([dp['Maximum'] for dp in metrics['Datapoints']])
                limits_info['lambda_function']['recent_max_concurrent'] = max_concurrent
                if max_concurrent <= 10:
                    limits_info['recommendations'].append(
                        f"⚠️ Recent max concurrent executions was {max_concurrent} (confirms 10-user limit)"
                    )
        except Exception as e:
            limits_info['metrics_error'] = str(e)
        
        return jsonify({
            'success': True,
            'limits': limits_info,
            'summary': f"Found {len(limits_info['recommendations'])} potential issues"
        })
        
    except Exception as e:
        logger.error(f"Error checking AWS limits: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/request-quota-increase', methods=['POST'])
@login_required
def request_quota_increase():
    """Request Lambda concurrent executions quota increase"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()
        requested_limit = data.get('requested_limit', 1000)  # Default to 1000

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        
        try:
            service_quotas = session.client("service-quotas", region_name=region)
            
            # Lambda concurrent executions quota code
            quota_code = "L-B99A9384"
            service_code = "lambda"
            
            # Get current quota
            try:
                current_quota = service_quotas.get_service_quota(
                    ServiceCode=service_code,
                    QuotaCode=quota_code
                )
                current_value = current_quota['Quota']['Value']
                
                if current_value >= requested_limit:
                    return jsonify({
                        'success': True,
                        'message': f'Current quota ({current_value}) is already sufficient. No increase needed.',
                        'current_quota': current_value
                    })
                
                # Request quota increase
                logger.info(f"[QUOTA] Requesting increase from {current_value} to {requested_limit}")
                
                # Request quota increase
                try:
                    quota_request = service_quotas.request_service_quota_increase(
                        ServiceCode=service_code,
                        QuotaCode=quota_code,
                        DesiredValue=requested_limit
                    )
                    
                    request_id = quota_request['RequestedQuota']['RequestId']
                    logger.info(f"[QUOTA] ✓ Quota increase requested. Request ID: {request_id}")
                    
                    return jsonify({
                        'success': True,
                        'message': f'Quota increase requested: {current_value} → {requested_limit}',
                        'request_id': request_id,
                        'current_quota': current_value,
                        'requested_quota': requested_limit,
                        'note': 'AWS Support will review and approve (usually within 24 hours)'
                    })
                except service_quotas.exceptions.DependencyAccessDeniedException:
                    return jsonify({
                        'success': False,
                        'error': 'Service Quotas API not available. Request quota increase manually via AWS Support Center → Service Quotas → Lambda → Concurrent executions'
                    }), 403
                except service_quotas.exceptions.QuotaExceededException:
                    return jsonify({
                        'success': False,
                        'error': f'Cannot request {requested_limit}. Maximum allowed is lower. Check AWS Console for limits.'
                    }), 400
                except Exception as e:
                    error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
                    if error_code == 'AccessDenied':
                        return jsonify({
                            'success': False,
                            'error': 'Access denied. Request quota increase manually via AWS Support Center.'
                        }), 403
                    raise
                    
            except service_quotas.exceptions.NoSuchResourceException:
                return jsonify({
                    'success': False,
                    'error': 'Quota not found. This account may not have Service Quotas enabled.'
                }), 404
                
        except Exception as e:
            logger.error(f"Error requesting quota increase: {e}")
            return jsonify({
                'success': False,
                'error': f'Could not request quota increase: {str(e)}. Request manually via AWS Support Center.'
            }), 500
            
    except Exception as e:
        logger.error(f"Error requesting quota increase: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/fix-lambda-concurrency', methods=['POST'])
@login_required
def fix_lambda_concurrency():
    """Remove reserved concurrency limit to allow 1000+ concurrent executions"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        lam = session.client("lambda")

        try:
            # Check current concurrency settings
            concurrency_config = lam.get_function_concurrency(FunctionName=PRODUCTION_LAMBDA_NAME)
            reserved_concurrency = concurrency_config.get('ReservedConcurrentExecutions')
            
            if reserved_concurrency:
                logger.info(f"[LAMBDA] Current reserved concurrency: {reserved_concurrency}")
                # Delete reserved concurrency to use account limit (1000+)
                lam.delete_function_concurrency(FunctionName=PRODUCTION_LAMBDA_NAME)
                logger.info(f"[LAMBDA] ✓ Removed reserved concurrency limit ({reserved_concurrency} → account limit)")
                return jsonify({
                    'success': True,
                    'message': f'Removed reserved concurrency limit ({reserved_concurrency}). Lambda can now use account limit (1000+).',
                    'previous_limit': reserved_concurrency,
                    'new_limit': 'Account limit (1000+)'
                })
            else:
                return jsonify({
                    'success': True,
                    'message': 'No reserved concurrency limit found. Lambda is using account limit (1000+).',
                    'current_limit': 'Account limit (1000+)'
                })
        except lam.exceptions.ResourceNotFoundException:
            return jsonify({
                'success': False,
                'error': f'Lambda function {PRODUCTION_LAMBDA_NAME} not found. Create it first.'
            }), 404
        except Exception as e:
            # Try to delete anyway (might be a different error)
            try:
                lam.delete_function_concurrency(FunctionName=PRODUCTION_LAMBDA_NAME)
                logger.info(f"[LAMBDA] ✓ Removed reserved concurrency limit")
                return jsonify({
                    'success': True,
                    'message': 'Removed reserved concurrency limit. Lambda can now use account limit (1000+).'
                })
            except Exception as e2:
                logger.error(f"Error fixing concurrency: {e2}")
                return jsonify({
                    'success': False,
                    'error': f'Could not fix concurrency limit: {str(e2)}'
                }), 500

    except Exception as e:
        logger.error(f"Error fixing Lambda concurrency: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

# --- Bulk Generation Logic ---

@aws_manager.route('/api/aws/bulk-generate', methods=['POST'])
@login_required
def bulk_generate():
    """
    Start background job to generate app passwords in bulk.
    Invokes Lambdas synchronously on the server side and saves results to DB.
    """
    data = request.get_json()
    access_key = data.get('access_key', '').strip()
    secret_key = data.get('secret_key', '').strip()
    region = data.get('region', '').strip()
    users_raw = data.get('users', [])
    
    if not users_raw:
        return jsonify({'success': False, 'error': 'No users provided'}), 400

    # Auto-clear DynamoDB before starting new batch
    try:
        session_boto = get_boto3_session(access_key, secret_key, region)
        dynamodb = session_boto.resource('dynamodb')
        table = dynamodb.Table("gbot-app-passwords")
        
        # Quick scan and delete old items
        response = table.scan()
        items = response.get('Items', [])
        if items:
            with table.batch_writer() as batch:
                for item in items:
                    batch.delete_item(Key={'email': item['email']})
            logger.info(f"[DYNAMODB] ✓ Auto-cleared {len(items)} old items before new batch")
    except Exception as e:
        logger.warning(f"[DYNAMODB] Could not auto-clear (table may not exist): {e}")
        # Continue anyway - not critical

    # Parse users
    users = []
    for u in users_raw:
        parts = u.split(':', 1)
        if len(parts) == 2:
            users.append({'email': parts[0].strip(), 'password': parts[1].strip()})
    
    if not users:
        return jsonify({'success': False, 'error': 'No valid user:password pairs found'}), 400

    logger.info(f"[BULK] Received {len(users_raw)} raw user entries, parsed {len(users)} valid users")

    job_id = str(int(time.time()))
    with jobs_lock:
        active_jobs[job_id] = {
            'total': len(users),
            'completed': 0,
            'success': 0,
            'failed': 0,
            'results': [],
            'status': 'processing'
        }
    
    logger.info(f"[BULK] Created job {job_id} for {len(users)} users")

    # Start background thread
    # We pass app_context explicitly if needed, but db operations need app context inside the thread
    from app import app
    
    def background_process(app, job_id, users, access_key, secret_key, region):
        # Ensure job exists before starting processing
        with jobs_lock:
            if job_id not in active_jobs:
                logger.error(f"[BULK] Job {job_id} not found in active_jobs at start of background_process!")
                # Try to recreate it
                active_jobs[job_id] = {
                    'total': len(users),
                    'completed': 0,
                    'success': 0,
                    'failed': 0,
                    'results': [],
                    'status': 'processing'
                }
                logger.info(f"[BULK] Recreated job {job_id}")
        
        try:
            with app.app_context():
                # Pre-detect Lambda functions ONCE before parallel processing
                # This is much more efficient than detecting for each user
                lambda_functions = []
                try:
                    session_boto = boto3.Session(
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        region_name=region
                    )
                    lam_client = session_boto.client("lambda", config=Config(
                        max_pool_connections=10,
                        retries={'max_attempts': 3}
                    ))
                    
                    # List all Lambda functions that match our pattern
                    logger.info(f"[BULK] Detecting Lambda functions matching '{PRODUCTION_LAMBDA_NAME}'...")
                    all_functions = lam_client.list_functions()
                    
                    # Get all function names for debugging
                    all_function_names = [fn['FunctionName'] for fn in all_functions.get('Functions', [])]
                    logger.info(f"[BULK] All Lambda functions in account: {all_function_names[:20]}...")  # Show first 20
                    
                    # Match functions that start with PRODUCTION_LAMBDA_NAME (edu-gw-chromium)
                    # This will match: edu-gw-chromium, edu-gw-chromium-1, edu-gw-chromium-2, etc.
                    matching_functions = [
                        fn['FunctionName'] for fn in all_functions.get('Functions', [])
                        if fn['FunctionName'].startswith(PRODUCTION_LAMBDA_NAME)
                    ]
                    
                    # Sort to ensure consistent ordering (edu-gw-chromium, edu-gw-chromium-1, edu-gw-chromium-2, etc.)
                    # Custom sort: base name first, then numbered ones
                    def sort_key(name):
                        if name == PRODUCTION_LAMBDA_NAME:
                            return (0, 0)  # Base name comes first
                        # Extract number from name like "edu-gw-chromium-5" -> 5
                        try:
                            num = int(name.split('-')[-1])
                            return (1, num)  # Numbered functions come after
                        except:
                            return (2, name)  # Other variations come last
                    
                    matching_functions.sort(key=sort_key)
                    
                    if len(matching_functions) > 1:
                        lambda_functions = matching_functions
                        logger.info(f"[BULK] ✓ Found {len(lambda_functions)} Lambda functions: {', '.join(lambda_functions)}")
                    elif len(matching_functions) == 1:
                        lambda_functions = matching_functions
                        logger.info(f"[BULK] ✓ Found single Lambda function: {lambda_functions[0]}")
                    else:
                        # No matching functions found, use default
                        lambda_functions = [PRODUCTION_LAMBDA_NAME]
                        logger.warning(f"[BULK] ⚠️ No matching Lambda functions found, will use default: {PRODUCTION_LAMBDA_NAME}")
                except Exception as list_err:
                    logger.error(f"[BULK] Error detecting Lambda functions: {list_err}")
                    logger.error(traceback.format_exc())
                    # Fall back to default function name
                    lambda_functions = [PRODUCTION_LAMBDA_NAME]
                    logger.warning(f"[BULK] Using default Lambda function: {PRODUCTION_LAMBDA_NAME}")
            
            # NEW LOGIC: Calculate total functions based on user count
            # Distribute functions evenly across ALL available geos
            # Process functions sequentially within each geo
            
            import math
            
            USERS_PER_FUNCTION = 10  # Fixed: Each function handles exactly 10 users
            
            # Calculate total number of functions needed
            total_users = len(users)
            num_functions = math.ceil(total_users / USERS_PER_FUNCTION)
            
            logger.info("=" * 60)
            logger.info(f"[BULK] Function Calculation")
            logger.info(f"[BULK] Total users: {total_users}")
            logger.info(f"[BULK] Users per function: {USERS_PER_FUNCTION}")
            logger.info(f"[BULK] Total functions needed: {num_functions}")
            logger.info("=" * 60)
            
            # Get all available AWS regions (geos)
            # These are all AWS regions where Lambda can be deployed
            AVAILABLE_GEO_REGIONS = [
                'us-east-1',      # US East (N. Virginia)
                'us-east-2',      # US East (Ohio)
                'us-west-1',      # US West (N. California)
                'us-west-2',      # US West (Oregon)
                'af-south-1',     # Africa (Cape Town)
                'ap-east-1',      # Asia Pacific (Hong Kong)
                'ap-south-1',     # Asia Pacific (Mumbai)
                'ap-northeast-1', # Asia Pacific (Tokyo)
                'ap-northeast-2', # Asia Pacific (Seoul)
                'ap-northeast-3', # Asia Pacific (Osaka)
                'ap-southeast-1', # Asia Pacific (Singapore)
                'ap-southeast-2', # Asia Pacific (Sydney)
                'ap-southeast-3', # Asia Pacific (Jakarta)
                'ca-central-1',   # Canada (Central)
                'eu-central-1',   # Europe (Frankfurt)
                'eu-west-1',      # Europe (Ireland)
                'eu-west-2',      # Europe (London)
                'eu-west-3',      # Europe (Paris)
                'eu-north-1',     # Europe (Stockholm)
                'eu-south-1',     # Europe (Milan)
                'me-south-1',     # Middle East (Bahrain)
                'me-central-1',   # Middle East (UAE)
                'sa-east-1',      # South America (São Paulo)
            ]
            
            # Distribute functions evenly across all available geos using round-robin
            # Example: 17 functions, 23 geos → 1 function per geo (first 17 geos get 1 function each)
            # Example: 50 functions, 23 geos → ~2-3 functions per geo (distributed evenly)
            functions_per_geo = {}  # {geo: [list of function_numbers]}
            
            for func_num in range(num_functions):
                # Round-robin distribution: function 0 → geo 0, function 1 → geo 1, etc.
                geo_index = func_num % len(AVAILABLE_GEO_REGIONS)
                geo = AVAILABLE_GEO_REGIONS[geo_index]
                
                if geo not in functions_per_geo:
                    functions_per_geo[geo] = []
                functions_per_geo[geo].append(func_num + 1)  # Function numbers start at 1
            
            logger.info("=" * 60)
            logger.info(f"[BULK] Function Distribution Across Geos")
            logger.info(f"[BULK] Total functions: {num_functions}")
            logger.info(f"[BULK] Available geos: {len(AVAILABLE_GEO_REGIONS)}")
            logger.info(f"[BULK] Functions per geo:")
            for geo, func_numbers in sorted(functions_per_geo.items()):
                logger.info(f"[BULK]   - {geo}: {len(func_numbers)} function(s) {func_numbers}")
            logger.info("=" * 60)
            
            # Split users into batches of 10, assigning each batch to a function
            # Function 1 gets users 0-9, Function 2 gets users 10-19, etc.
            user_batches = []  # List of (function_number, geo, user_batch) tuples
            for func_num in range(num_functions):
                start_idx = func_num * USERS_PER_FUNCTION
                end_idx = min(start_idx + USERS_PER_FUNCTION, total_users)
                batch_users = users[start_idx:end_idx]
                
                if batch_users:
                    # Determine which geo this function belongs to
                    geo_index = func_num % len(AVAILABLE_GEO_REGIONS)
                    geo = AVAILABLE_GEO_REGIONS[geo_index]
                    user_batches.append((func_num + 1, geo, batch_users))
                    logger.info(f"[BULK] Function {func_num + 1} ({geo}) will process {len(batch_users)} user(s)")
            
            # BATCH PROCESSING: Process 10 users at a time, sequentially within each geo
            USERS_PER_BATCH = 10
            
            def process_user_batch_sync(user_batch, assigned_function_name, lambda_region=None):
                """
                Process a batch of up to 10 users synchronously (wait for completion).
                Returns list of results, one per user.
                This is used for sequential processing within each geo.
                
                Args:
                    user_batch: List of user dicts to process
                    assigned_function_name: Name of Lambda function to invoke
                    lambda_region: AWS region where Lambda function is deployed (defaults to 'region' variable)
                """
                with app.app_context():
                    # Use lambda_region if provided, otherwise fall back to user's selected region
                    target_region = lambda_region if lambda_region else region
                    
                    # Create INDEPENDENT boto3 session and clients for this batch
                    session_batch = boto3.Session(
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        region_name=target_region
                    )
                    
                    # Each batch gets its own Lambda client with extended timeout
                    # CRITICAL: Set read_timeout to 1000 seconds (16+ minutes) to handle batch processing
                    # Lambda timeout is 900 seconds, so we need client timeout > Lambda timeout
                    # IMPORTANT: Lambda client uses the region from session_batch (target_region)
                    lam_batch = session_batch.client("lambda", config=Config(
                        max_pool_connections=10,
                        retries={'max_attempts': 0},
                        read_timeout=1000,  # 16+ minutes - must exceed Lambda timeout (900s)
                        connect_timeout=60  # 60 seconds connection timeout
                    ))
                    
                    # Each batch gets its own DynamoDB resource
                    dynamodb_batch = session_batch.resource('dynamodb', config=Config(
                        max_pool_connections=10
                    ))
                    table_batch = dynamodb_batch.Table("gbot-app-passwords")
                    
                    # Check DynamoDB first for all users in batch
                    batch_results = []
                    users_to_process = []
                    
                    for user in user_batch:
                        email = user['email']
                        password = user['password']
                        
                        # Check if already exists in DynamoDB
                        try:
                            response = table_batch.get_item(Key={'email': email})
                            if 'Item' in response:
                                existing_password = response['Item'].get('app_password')
                                logger.info(f"[BULK] ✓ SKIPPED: {email} already has password in DynamoDB")
                                # Save to local DB too
                                try:
                                    save_app_password(email, existing_password)
                                except:
                                    pass
                                batch_results.append({
                                    'email': email,
                                    'success': True,
                                    'app_password': existing_password,
                                    'skipped': True
                                })
                                continue
                        except Exception as e:
                            logger.warning(f"[BULK] Could not check DynamoDB for {email}: {e}")
                        
                        # Check if email is already being processed
                        with processing_lock:
                            if email in processing_emails:
                                logger.warning(f"[BULK] ⚠️ SKIPPED: {email} is already being processed")
                                batch_results.append({
                                    'email': email,
                                    'success': False,
                                    'error': 'Duplicate - already processing'
                                })
                                continue
                            processing_emails.add(email)
                        
                        users_to_process.append(user)
                    
                    # If all users were skipped, return early
                    if not users_to_process:
                        return batch_results
                    
                    # Prepare batch payload for Lambda
                    batch_payload = {
                        "users": [
                            {"email": u['email'], "password": u['password']}
                            for u in users_to_process
                        ]
                    }
                    
                    logger.info(f"[BULK] [{assigned_function_name}] Invoking Lambda SYNC with batch of {len(users_to_process)} user(s)")
                    
                    # Rate limiting: Acquire semaphore to limit concurrent invocations
                    lambda_invocation_semaphore.acquire()
                    try:
                        # Retry logic for rate limiting
                        max_retries = 3
                        resp = None
                        for attempt in range(max_retries):
                            try:
                                # Use SYNC invocation to wait for completion (sequential processing)
                                resp = lam_batch.invoke(
                                    FunctionName=assigned_function_name,
                                    InvocationType="RequestResponse",  # SYNC - wait for completion
                                    Payload=json.dumps(batch_payload).encode("utf-8"),
                                )
                                
                                # Parse Lambda response
                                payload = resp.get("Payload")
                                body = payload.read().decode("utf-8") if payload else "{}"
                                logger.info(f"[BULK] Lambda batch response: {body[:500]}")
                                
                                try:
                                    lambda_response = json.loads(body)
                                except json.JSONDecodeError as je:
                                    logger.error(f"[BULK] Failed to parse Lambda response as JSON: {je}")
                                    # All users in batch fail
                                    for u in users_to_process:
                                        batch_results.append({
                                            'email': u['email'],
                                            'success': False,
                                            'error': f'Invalid JSON response: {body[:200]}'
                                        })
                                    return batch_results
                                
                                # Handle batch response format
                                if lambda_response.get("status") == "completed" and "results" in lambda_response:
                                    # Batch processing response
                                    lambda_results = lambda_response.get("results", [])
                                    for lambda_result in lambda_results:
                                        email = lambda_result.get("email", "unknown")
                                        lambda_status = lambda_result.get("status", "unknown")
                                        app_password = lambda_result.get("app_password")
                                        error_msg = lambda_result.get("error_message", "Unknown error")
                                        
                                        if lambda_status == 'success' and app_password:
                                            logger.info(f"[BULK] Saving password for {email} to DB")
                                            try:
                                                save_app_password(email, app_password)
                                                logger.info(f"[BULK] ✓ Successfully processed {email}")
                                            except Exception as db_err:
                                                logger.error(f"[BULK] Failed to save to DB for {email}: {db_err}")
                                            batch_results.append({
                                                'email': email,
                                                'success': True,
                                                'app_password': app_password
                                            })
                                        else:
                                            logger.warning(f"[BULK] ✗ Lambda failed for {email}: {error_msg}")
                                            batch_results.append({
                                                'email': email,
                                                'success': False,
                                                'error': error_msg
                                            })
                                    break  # Success, exit retry loop
                                else:
                                    # Fallback: single user response format (backward compatibility)
                                    lambda_status = lambda_response.get('status', 'unknown')
                                    app_password = lambda_response.get('app_password')
                                    error_msg = lambda_response.get('error_message', 'Unknown error')
                                    
                                    # If only one user in batch, use single response format
                                    if len(users_to_process) == 1:
                                        email = users_to_process[0]['email']
                                        if lambda_status == 'success' and app_password:
                                            try:
                                                save_app_password(email, app_password)
                                                logger.info(f"[BULK] ✓ Successfully processed {email}")
                                            except Exception as db_err:
                                                logger.error(f"[BULK] Failed to save to DB for {email}: {db_err}")
                                            batch_results.append({
                                                'email': email,
                                                'success': True,
                                                'app_password': app_password
                                            })
                                        else:
                                            batch_results.append({
                                                'email': email,
                                                'success': False,
                                                'error': error_msg
                                            })
                                        break  # Success, exit retry loop
                                    else:
                                        # Multiple users but got single response - all fail
                                        logger.error(f"[BULK] Expected batch response but got single user format")
                                        for u in users_to_process:
                                            batch_results.append({
                                                'email': u['email'],
                                                'success': False,
                                                'error': 'Invalid response format from Lambda'
                                            })
                                        return batch_results
                                    
                            except ClientError as ce:
                                error_code = ce.response['Error']['Code']
                                error_message = ce.response['Error'].get('Message', '')
                                
                                if error_code == 'ResourceNotFoundException':
                                    logger.error(f"[BULK] Lambda function {assigned_function_name} not found")
                                    # Try to fall back to default function
                                    if assigned_function_name != PRODUCTION_LAMBDA_NAME:
                                        logger.warning(f"[BULK] Falling back to default function {PRODUCTION_LAMBDA_NAME}")
                                        assigned_function_name = PRODUCTION_LAMBDA_NAME
                                        continue  # Retry with default function
                                    else:
                                        # All users in batch fail
                                        for u in users_to_process:
                                            batch_results.append({
                                                'email': u['email'],
                                                'success': False,
                                                'error': f'Lambda function {assigned_function_name} not found'
                                            })
                                        return batch_results
                                
                                if error_code == 'TooManyRequestsException' or error_code == 'ThrottlingException':
                                    if attempt < max_retries - 1:
                                        base_wait = (2 ** attempt) * 2
                                        jitter = random.uniform(0, 1)
                                        wait_time = base_wait + jitter
                                        logger.warning(f"[BULK] Rate limited for batch, retrying in {wait_time:.2f}s (attempt {attempt + 1}/{max_retries})")
                                        time.sleep(wait_time)
                                    else:
                                        # All users in batch fail
                                        for u in users_to_process:
                                            batch_results.append({
                                                'email': u['email'],
                                                'success': False,
                                                'error': f'Rate limited: {error_message}'
                                            })
                                        return batch_results
                                else:
                                    logger.error(f"[BULK] AWS error: {error_code} - {error_message}")
                                    # All users in batch fail
                                    for u in users_to_process:
                                        batch_results.append({
                                            'email': u['email'],
                                            'success': False,
                                            'error': f'AWS Error ({error_code}): {error_message}'
                                        })
                                    return batch_results
                            except Exception as invoke_err:
                                # Check if it's a timeout error
                                if 'Read timeout' in str(invoke_err) or 'timeout' in str(invoke_err).lower():
                                    logger.error(f"[BULK] Read timeout on attempt {attempt + 1} - Lambda may still be processing")
                                    if attempt == max_retries - 1:
                                        # Final attempt failed - mark as timeout
                                        for u in users_to_process:
                                            batch_results.append({
                                                'email': u['email'],
                                                'success': False,
                                                'error': f'Read timeout - Lambda processing may have exceeded timeout'
                                            })
                                        return batch_results
                                    time.sleep(5)
                                    continue
                                else:
                                    logger.error(f"[BULK] Invocation error: {invoke_err}")
                                    if attempt == max_retries - 1:
                                        # Final attempt failed
                                        for u in users_to_process:
                                            batch_results.append({
                                                'email': u['email'],
                                                'success': False,
                                                'error': f'Invocation error: {str(invoke_err)}'
                                            })
                                        return batch_results
                                    time.sleep(2)
                                    continue
                    finally:
                        lambda_invocation_semaphore.release()
                    
                    # Remove processed emails from tracking set
                    for u in users_to_process:
                        with processing_lock:
                            processing_emails.discard(u['email'])
                    
                    return batch_results
            
            # Group batches by geo for sequential processing within each geo
            batches_by_geo = {}  # {geo: [(function_number, user_batch), ...]}
            for func_num, geo, batch_users in user_batches:
                if geo not in batches_by_geo:
                    batches_by_geo[geo] = []
                batches_by_geo[geo].append((func_num, batch_users))
            
            logger.info("=" * 60)
            logger.info(f"[BULK] Batches per geo:")
            for geo, geo_batches in sorted(batches_by_geo.items()):
                total_users_in_geo = sum(len(batch) for _, batch in geo_batches)
                logger.info(f"[BULK]   - {geo}: {len(geo_batches)} function(s), {total_users_in_geo} user(s)")
            logger.info("=" * 60)
            
            def process_geo_sequentially(geo, geo_batches_list):
                """
                Process all batches in a geo sequentially (function by function).
                Creates Lambda functions as needed and processes them one at a time.
                Waits for each function to complete before starting the next.
                """
                logger.info(f"[BULK] [{geo}] Starting sequential processing: {len(geo_batches_list)} function(s)")
                
                # Create boto3 session for this geo (use the geo's region)
                try:
                    session_boto = boto3.Session(
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        region_name=geo  # Use geo as the region
                    )
                    lam_client = session_boto.client("lambda", config=Config(
                        max_pool_connections=10,
                        retries={'max_attempts': 3}
                    ))
                    all_functions = lam_client.list_functions()
                    existing_function_names = [fn['FunctionName'] for fn in all_functions.get('Functions', [])]
                except Exception as e:
                    logger.error(f"[BULK] [{geo}] Could not list existing functions: {e}")
                    logger.error(traceback.format_exc())
                    existing_function_names = []
                
                # Process each batch sequentially
                geo_results = []
                for batch_idx, (func_num, batch_users) in enumerate(geo_batches_list):
                    logger.info(f"[BULK] [{geo}] Processing function {func_num}/{len(geo_batches_list)} ({len(batch_users)} user(s))")
                    
                    # Generate function name: edu-gw-chromium-{geo_code}-{func_num}
                    geo_code = geo.replace('-', '')  # Remove dashes: us-east-1 -> useast1
                    func_name = f"{PRODUCTION_LAMBDA_NAME}-{geo_code}-{func_num}"
                    
                    # Create function if it doesn't exist
                    if func_name not in existing_function_names:
                        logger.info(f"[BULK] [{geo}] Creating Lambda function: {func_name}")
                        try:
                            role_arn = ensure_lambda_role(session_boto)
                            chromium_env = {
                                "DYNAMODB_TABLE_NAME": "gbot-app-passwords",
                                "APP_PASSWORDS_S3_BUCKET": S3_BUCKET_NAME,
                                "APP_PASSWORDS_S3_KEY": "app-passwords.txt",
                            }
                            
                            # Extract ECR URI from existing function or construct it
                            ecr_uri = None
                            try:
                                if existing_function_names:
                                    existing_func = lam_client.get_function(FunctionName=existing_function_names[0])
                                    code_location = existing_func.get('Code', {}).get('ImageUri')
                                    if code_location:
                                        ecr_uri = code_location
                                        logger.info(f"[BULK] [{geo}] Using ECR URI from existing function: {ecr_uri}")
                            except Exception as e:
                                logger.debug(f"[BULK] [{geo}] Could not get ECR URI from existing function: {e}")
                            
                            if not ecr_uri:
                                # Construct ECR URI for this geo's region
                                try:
                                    sts = session_boto.client('sts')
                                    account_id = sts.get_caller_identity()['Account']
                                    ecr_uri = f"{account_id}.dkr.ecr.{geo}.amazonaws.com/{ECR_REPO_NAME}:{ECR_IMAGE_TAG}"
                                    logger.info(f"[BULK] [{geo}] Constructed ECR URI: {ecr_uri}")
                                except Exception as e:
                                    logger.error(f"[BULK] [{geo}] Could not determine ECR URI for {func_name}: {e}")
                                    # Fall back to default function
                                    func_name = PRODUCTION_LAMBDA_NAME
                            
                            if func_name != PRODUCTION_LAMBDA_NAME:
                                create_or_update_lambda(
                                    session=session_boto,
                                    function_name=func_name,
                                    role_arn=role_arn,
                                    timeout=900,  # 15 minutes
                                    env_vars=chromium_env,
                                    package_type="Image",
                                    image_uri=ecr_uri,
                                )
                                logger.info(f"[BULK] [{geo}] ✓ Created Lambda function: {func_name}")
                                existing_function_names.append(func_name)
                        except Exception as create_err:
                            logger.error(f"[BULK] [{geo}] Failed to create {func_name}: {create_err}")
                            logger.error(traceback.format_exc())
                            # Fall back to default function
                            func_name = PRODUCTION_LAMBDA_NAME
                    
                    # Process this batch synchronously (wait for completion)
                    # Use the geo's region for Lambda client
                    batch_results = process_user_batch_sync(batch_users, func_name, lambda_region=geo)
                    geo_results.extend(batch_results)
                    
                    # Update job status after each batch
                    with jobs_lock:
                        if job_id in active_jobs:
                            for result in batch_results:
                                active_jobs[job_id]['completed'] += 1
                                if result['success']:
                                    active_jobs[job_id]['success'] += 1
                                    active_jobs[job_id]['results'].append({
                                        'email': result['email'],
                                        'app_password': result.get('app_password'),
                                        'success': True
                                    })
                                else:
                                    active_jobs[job_id]['failed'] += 1
                                    active_jobs[job_id]['results'].append({
                                        'email': result['email'],
                                        'error': result.get('error'),
                                        'success': False
                                    })
                    
                    logger.info(f"[BULK] [{geo}] Function {func_num}/{len(geo_batches_list)} completed: {sum(1 for r in batch_results if r['success'])}/{len(batch_results)} success")
                    
                    # Wait a moment before starting next function (functions process sequentially)
                    if batch_idx < len(geo_batches_list) - 1:
                        logger.info(f"[BULK] [{geo}] Waiting for next function to start...")
                        time.sleep(2)  # Small delay between functions
                
                logger.info(f"[BULK] [{geo}] Sequential processing completed: {sum(1 for r in geo_results if r['success'])}/{len(geo_results)} success")
                return geo_results
            
            # Process all geos in parallel (each geo processes its functions sequentially)
            logger.info("=" * 60)
            logger.info(f"[BULK] Starting Parallel Geo Processing with Sequential Functions")
            logger.info(f"[BULK] Total users: {total_users}")
            logger.info(f"[BULK] Total functions: {num_functions}")
            logger.info(f"[BULK] Number of geos: {len(batches_by_geo)}")
            logger.info(f"[BULK] Users per function: {USERS_PER_FUNCTION}")
            logger.info("=" * 60)
            
            # Process geos in parallel (each geo processes functions sequentially internally)
            max_geo_workers = len(batches_by_geo)  # One worker per geo
            logger.info(f"[BULK] Processing {len(batches_by_geo)} geo(s) in parallel...")
            
            with ThreadPoolExecutor(max_workers=max_geo_workers) as geo_pool:
                # Submit all geos for processing
                geo_futures = {}
                for geo, geo_batches_list in batches_by_geo.items():
                    future = geo_pool.submit(process_geo_sequentially, geo, geo_batches_list)
                    geo_futures[future] = geo
                
                logger.info(f"[BULK] ✓ Submitted {len(geo_futures)} geo(s) to thread pool")
                
                # Wait for all geos to complete
                for future in as_completed(geo_futures):
                    geo = geo_futures[future]
                    try:
                        geo_results = future.result()
                        logger.info(f"[BULK] [{geo}] Completed: {sum(1 for r in geo_results if r['success'])}/{len(geo_results)} success")
                    except Exception as e:
                        logger.error(f"[BULK] [{geo}] Exception: {e}")
                        logger.error(traceback.format_exc())
                
                logger.info("=" * 60)
                logger.info(f"[BULK] All geos completed processing")
                logger.info("=" * 60)
            
            # Set job status to completed (outside ThreadPoolExecutor but inside app_context)
            # Use lock to ensure thread-safe access
            with jobs_lock:
                if job_id in active_jobs:
                    completed_count = active_jobs[job_id].get('completed', 0)
                    success_count = active_jobs[job_id].get('success', 0)
                    failed_count = active_jobs[job_id].get('failed', 0)
                    active_jobs[job_id]['status'] = 'completed'
                    logger.info(f"[BULK] ✅ Job {job_id} completed successfully. Processed {completed_count}/{len(users)} users. Success: {success_count}, Failed: {failed_count}")
                else:
                    logger.error(f"[BULK] ⚠️ Job {job_id} not found in active_jobs when trying to mark as completed!")
                    # Try to create it if it doesn't exist (shouldn't happen, but safety check)
                    # Since we don't have the actual counts, use defaults
                    active_jobs[job_id] = {
                        'total': len(users),
                        'completed': 0,
                        'success': 0,
                        'failed': len(users),
                        'results': [],
                        'status': 'completed'
                    }
                    logger.warning(f"[BULK] Created fallback job entry for {job_id} with default values")
        except Exception as bg_error:
            logger.error(f"[BULK] ❌ CRITICAL ERROR in background_process: {bg_error}")
            logger.error(f"[BULK] Traceback: {traceback.format_exc()}")
            # Use lock to ensure thread-safe access
            with jobs_lock:
                if job_id in active_jobs:
                    active_jobs[job_id]['status'] = 'failed'
                    active_jobs[job_id]['error'] = str(bg_error)
                    active_jobs[job_id]['completed'] = active_jobs[job_id].get('completed', 0)
                else:
                    logger.error(f"[BULK] ⚠️ Job {job_id} not found in active_jobs when trying to mark as failed!")

    threading.Thread(target=background_process, args=(app, job_id, users, access_key, secret_key, region)).start()

    return jsonify({'success': True, 'job_id': job_id, 'message': f'Started processing {len(users)} users'})

@aws_manager.route('/api/aws/job-status/<job_id>', methods=['GET'])
@login_required
def get_job_status(job_id):
    try:
        with jobs_lock:
            job = active_jobs.get(job_id)
        if not job:
            logger.warning(f"[JOB_STATUS] Job {job_id} not found. Available jobs: {list(active_jobs.keys())}")
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        # Return the job status including the results list (which has the new passwords)
        return jsonify({'success': True, 'job': job})
    except Exception as e:
        logger.error(f"Error getting job status: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/fetch-from-dynamodb', methods=['POST'])
@login_required
def fetch_from_dynamodb():
    """Fetch app passwords from DynamoDB for specific users"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()
        emails = data.get('emails', [])  # List of emails to fetch
        
        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400
        
        if not emails:
            return jsonify({'success': False, 'error': 'No emails provided'}), 400
        
        session = get_boto3_session(access_key, secret_key, region)
        dynamodb = session.resource('dynamodb')
        table_name = "gbot-app-passwords"
        
        try:
            table = dynamodb.Table(table_name)
        except Exception as e:
            return jsonify({'success': False, 'error': f'DynamoDB table {table_name} not found: {e}'}), 404
        
        results = []
        for email in emails:
            try:
                response = table.get_item(Key={'email': email})
                if 'Item' in response:
                    item = response['Item']
                    app_password = item['app_password']
                    
                    # Save to local AwsGeneratedPassword table
                    try:
                        save_app_password(email, app_password)
                        logger.info(f"[DYNAMODB] ✓ Fetched and saved to local DB: {email}")
                    except Exception as db_err:
                        logger.warning(f"[DYNAMODB] Could not save to local DB for {email}: {db_err}")
                        # Continue anyway - we have the password
                    
                    results.append({
                        'email': item['email'],
                        'app_password': app_password,
                        'created_at': item.get('created_at', ''),
                        'success': True
                    })
                else:
                    logger.warning(f"[DYNAMODB] ⚠️ No entry found for {email}")
                    results.append({
                        'email': email,
                        'error': 'Not found in DynamoDB',
                        'success': False
                    })
            except Exception as e:
                logger.error(f"[DYNAMODB] Error fetching {email}: {e}")
                results.append({
                    'email': email,
                    'error': str(e),
                    'success': False
                })
        
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        logger.error(f"Error fetching from DynamoDB: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/generated-passwords', methods=['GET'])
@login_required
def get_generated_passwords():
    """Fetch all generated app passwords from local DB (deprecated - use DynamoDB)"""
    try:
        # Get recent passwords from AwsGeneratedPassword table
        passwords = AwsGeneratedPassword.query.order_by(AwsGeneratedPassword.created_at.desc()).all()
        result = []
        for p in passwords:
            result.append({
                'email': p.email,
                'app_password': p.app_password,
                'created_at': p.created_at.isoformat()
            })
        return jsonify({'success': True, 'passwords': result})
    except Exception as e:
        # If table doesn't exist or other DB error, return empty list to prevent frontend crash
        logger.error(f"Error fetching generated passwords: {e}")
        return jsonify({'success': True, 'passwords': [], 'error': str(e)})

def save_app_password(email, app_password):
    """Save app password to AwsGeneratedPassword table"""
    try:
        logger.info(f"[DB] Attempting to save password for {email}")
        # Check if exists
        existing = AwsGeneratedPassword.query.filter_by(email=email).first()
        if existing:
            logger.info(f"[DB] Updating existing entry for {email}")
            existing.app_password = app_password
            existing.updated_at = db.func.current_timestamp()
        else:
            logger.info(f"[DB] Creating new entry for {email}")
            new_entry = AwsGeneratedPassword(email=email, app_password=app_password)
            db.session.add(new_entry)
        
        db.session.commit()
        logger.info(f"[DB] ✓ Successfully saved password for {email}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"[DB] ✗ Error saving app password for {email}: {e}")
        logger.error(f"[DB] Exception details: {traceback.format_exc()}")

# --- End Bulk Logic ---

@aws_manager.route('/api/aws/invoke-lambda', methods=['POST'])
@login_required
def invoke_lambda():
    """Invoke production Lambda (Single invocation)"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        async_mode = data.get('async', False)

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        if not email or not password:
            return jsonify({'success': False, 'error': 'Please provide email and password.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        lam = session.client("lambda")

        # Determine which Lambda function to use
        lambda_function_name = PRODUCTION_LAMBDA_NAME
        try:
            # List all Lambda functions that match our pattern
            all_functions = lam.list_functions()
            matching_functions = [
                fn['FunctionName'] for fn in all_functions.get('Functions', [])
                if fn['FunctionName'].startswith(PRODUCTION_LAMBDA_NAME)
            ]
            
            if len(matching_functions) > 1:
                # Multiple functions exist - use hash to pick one consistently
                user_hash = int(hashlib.md5(email.encode()).hexdigest(), 16)
                function_index = user_hash % len(matching_functions)
                lambda_function_name = matching_functions[function_index]
                logger.info(f"[INVOKE] Using Lambda function {lambda_function_name} for {email} (distributed across {len(matching_functions)} functions)")
            elif len(matching_functions) == 1:
                # Only one function exists, use it
                lambda_function_name = matching_functions[0]
                logger.info(f"[INVOKE] Using Lambda function {lambda_function_name} for {email}")
            else:
                # No matching functions found, use default
                logger.warning(f"[INVOKE] No matching Lambda functions found, using default {PRODUCTION_LAMBDA_NAME}")
        except Exception as list_err:
            logger.warning(f"[INVOKE] Could not list Lambda functions, using default: {list_err}")

        event = {
            "email": email,
            "password": password,
        }

        invocation_type = "Event" if async_mode else "RequestResponse"
        resp = lam.invoke(
            FunctionName=lambda_function_name,
            InvocationType=invocation_type,
            Payload=json.dumps(event).encode("utf-8"),
        )

        if async_mode:
            status_code = resp.get("StatusCode", 0)
            if status_code == 202:
                return jsonify({
                    'success': True,
                    'status': 'invoked',
                    'message': 'Lambda invoked asynchronously'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': f'Unexpected status code: {status_code}'
                }), 500
        else:
            payload = resp.get("Payload")
            body = payload.read().decode("utf-8") if payload else ""
            try:
                response_data = json.loads(body)
                
                # Save to DB if successful
                if response_data.get('app_password'):
                    try:
                        save_app_password(email, response_data['app_password'])
                        logger.info(f"[INVOKE] ✓ Password saved for {email}")
                    except Exception as db_error:
                        logger.error(f"[INVOKE] Failed to save password to DB: {db_error}")
                        # Continue anyway - return the password even if DB save fails
                
                return jsonify({
                    'success': True,
                    **response_data
                })
            except Exception as parse_error:
                logger.warning(f"[INVOKE] Failed to parse response as JSON: {parse_error}")
                return jsonify({
                    'success': True,
                    'raw_response': body
                })
    except ClientError as ce:
        if ce.response['Error']['Code'] == 'ResourceNotFoundException':
            return jsonify({
                'success': False,
                'error': f'Production Lambda {PRODUCTION_LAMBDA_NAME} not found. Create it first.'
            }), 404
        return jsonify({'success': False, 'error': str(ce)}), 500
    except Exception as e:
        logger.error(f"Error invoking Lambda: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/delete-all-lambdas', methods=['POST'])
@login_required
def delete_all_lambdas():
    """Delete all production Lambdas"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        lam = session.client("lambda")

        deleted = []
        try:
            lam.delete_function(FunctionName=PRODUCTION_LAMBDA_NAME)
            deleted.append(PRODUCTION_LAMBDA_NAME)
        except lam.exceptions.ResourceNotFoundException:
            pass

        # Also check for any other edu-gw lambdas
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                if "edu-gw" in fn["FunctionName"] and fn["FunctionName"] not in deleted:
                    try:
                        lam.delete_function(FunctionName=fn["FunctionName"])
                        deleted.append(fn["FunctionName"])
                    except Exception as e:
                        logger.error(f"Error deleting {fn['FunctionName']}: {e}")

        return jsonify({
            'success': True,
            'deleted': deleted,
            'message': 'Lambda cleanup completed.'
        })
    except Exception as e:
        logger.error(f"Error deleting Lambdas: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/delete-s3-content', methods=['POST'])
@login_required
def delete_s3_content():
    """Delete all contents from S3 bucket
    
    Required AWS IAM permissions:
    - s3:ListBucket (to list objects)
    - s3:DeleteObject (to delete objects)
    - s3:ListBucketVersions (if versioning is enabled)
    - s3:DeleteObjectVersion (if versioning is enabled)
    """
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        s3 = session.client("s3")

        # First, check if bucket exists and we have ListBucket permission
        try:
            s3.head_bucket(Bucket=S3_BUCKET_NAME)
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == '404' or error_code == 'NoSuchBucket':
                return jsonify({
                    'success': False,
                    'error': f'S3 bucket {S3_BUCKET_NAME} does not exist.'
                }), 404
            elif error_code == '403' or 'AccessDenied' in str(e):
                return jsonify({
                    'success': False,
                    'error': f'Access Denied to S3 bucket {S3_BUCKET_NAME}. Your AWS credentials need the following IAM permissions:\n'
                             f'- s3:ListBucket\n'
                             f'- s3:DeleteObject\n'
                             f'- s3:ListBucketVersions (if versioning enabled)\n'
                             f'- s3:DeleteObjectVersion (if versioning enabled)\n\n'
                             f'You can attach the "AmazonS3FullAccess" policy to your IAM user, or create a custom policy with these permissions for bucket "{S3_BUCKET_NAME}".'
                }), 403
            else:
                raise e

        deleted_count = 0
        
        # Delete regular objects
        try:
            paginator = s3.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=S3_BUCKET_NAME):
                objects = page.get('Contents', [])
                if objects:
                    delete_keys = [{'Key': obj['Key']} for obj in objects]
                    try:
                        s3.delete_objects(
                            Bucket=S3_BUCKET_NAME,
                            Delete={'Objects': delete_keys}
                        )
                        deleted_count += len(delete_keys)
                        logger.info(f"[S3] Deleted {len(delete_keys)} objects from {S3_BUCKET_NAME}")
                    except ClientError as delete_err:
                        error_code = delete_err.response.get('Error', {}).get('Code', '')
                        if error_code == 'AccessDenied':
                            return jsonify({
                                'success': False,
                                'error': f'Access Denied when deleting objects. Your AWS credentials need s3:DeleteObject permission for bucket "{S3_BUCKET_NAME}".'
                            }), 403
                        raise delete_err
        except ClientError as list_err:
            error_code = list_err.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDenied':
                return jsonify({
                    'success': False,
                    'error': f'Access Denied when listing objects. Your AWS credentials need s3:ListBucket permission for bucket "{S3_BUCKET_NAME}".'
                }), 403
            raise list_err
        
        # Delete object versions if versioning is enabled
        try:
            version_paginator = s3.get_paginator('list_object_versions')
            for page in version_paginator.paginate(Bucket=S3_BUCKET_NAME):
                versions = page.get('Versions', [])
                delete_markers = page.get('DeleteMarkers', [])
                
                to_delete = []
                for version in versions:
                    to_delete.append({'Key': version['Key'], 'VersionId': version['VersionId']})
                for marker in delete_markers:
                    to_delete.append({'Key': marker['Key'], 'VersionId': marker['VersionId']})
                
                if to_delete:
                    try:
                        s3.delete_objects(
                            Bucket=S3_BUCKET_NAME,
                            Delete={'Objects': to_delete}
                        )
                        deleted_count += len(to_delete)
                        logger.info(f"[S3] Deleted {len(to_delete)} versions/markers from {S3_BUCKET_NAME}")
                    except ClientError as version_err:
                        error_code = version_err.response.get('Error', {}).get('Code', '')
                        if error_code == 'AccessDenied':
                            logger.warning(f"[S3] Access Denied when deleting versions (may not have s3:DeleteObjectVersion permission)")
                        else:
                            logger.warning(f"[S3] Could not delete versions: {version_err}")
        except ClientError as version_list_err:
            error_code = version_list_err.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDenied':
                logger.warning(f"[S3] Access Denied when listing versions (versioning may not be enabled or missing s3:ListBucketVersions permission)")
            else:
                logger.warning(f"[S3] Could not list versions (versioning may not be enabled): {version_list_err}")
        except Exception as version_err:
            logger.warning(f"[S3] Error handling versions: {version_err}")

        return jsonify({
            'success': True,
            'deleted_count': deleted_count,
            'message': f'S3 bucket {S3_BUCKET_NAME} contents deleted successfully. Deleted {deleted_count} object(s).'
        })
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        if error_code == 'NoSuchBucket':
            return jsonify({
                'success': False,
                'error': f'S3 bucket {S3_BUCKET_NAME} does not exist.'
            }), 404
        elif error_code == 'AccessDenied' or 'Access Denied' in error_message:
            return jsonify({
                'success': False,
                'error': f'Access Denied: {error_message}\n\n'
                         f'Required IAM permissions for bucket "{S3_BUCKET_NAME}":\n'
                         f'- s3:ListBucket\n'
                         f'- s3:DeleteObject\n'
                         f'- s3:ListBucketVersions (if versioning enabled)\n'
                         f'- s3:DeleteObjectVersion (if versioning enabled)\n\n'
                         f'Attach "AmazonS3FullAccess" policy to your IAM user, or create a custom policy.'
            }), 403
        else:
            logger.error(f"Error deleting S3 contents: {e}")
            return jsonify({'success': False, 'error': f'AWS Error ({error_code}): {error_message}'}), 500
    except Exception as e:
        logger.error(f"Error deleting S3 contents: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/delete-ecr-repo', methods=['POST'])
@login_required
def delete_ecr_repo():
    """Delete ECR repository and all images"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        ecr = session.client("ecr")

        ecr.delete_repository(
            repositoryName=ECR_REPO_NAME,
            force=True
        )

        return jsonify({
            'success': True,
            'message': f'ECR repository {ECR_REPO_NAME} deleted successfully.'
        })
    except ecr.exceptions.RepositoryNotFoundException:
        return jsonify({
            'success': False,
            'error': f'ECR repository {ECR_REPO_NAME} not found.'
        }), 404
    except Exception as e:
        logger.error(f"Error deleting ECR repository: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/delete-cloudwatch-logs', methods=['POST'])
@login_required
def delete_cloudwatch_logs():
    """Delete CloudWatch log groups for Lambdas"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        logs = session.client("logs")

        deleted_count = 0
        paginator = logs.get_paginator('describe_log_groups')
        for page in paginator.paginate():
            for log_group in page.get('logGroups', []):
                log_group_name = log_group['logGroupName']
                if '/aws/lambda/edu-gw' in log_group_name:
                    try:
                        logs.delete_log_group(logGroupName=log_group_name)
                        deleted_count += 1
                    except Exception as e:
                        logger.error(f"Error deleting {log_group_name}: {e}")

        return jsonify({
            'success': True,
            'deleted_count': deleted_count,
            'message': f'CloudWatch log cleanup completed. Deleted {deleted_count} log groups.'
        })
    except Exception as e:
        logger.error(f"Error deleting CloudWatch logs: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/ec2-create-build-box', methods=['POST'])
@login_required
def ec2_create_build_box():
    """Create/Prepare EC2 Build Box"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        account_id = get_account_id(session)

        # Ensure ECR repo exists
        if not create_ecr_repo(session, region):
            return jsonify({'success': False, 'error': 'Failed to create or verify ECR repository'}), 500

        # Verify ECR repo
        ecr = session.client("ecr")
        try:
            resp = ecr.describe_repositories(repositoryNames=[ECR_REPO_NAME])
            repo_uri = resp['repositories'][0]['repositoryUri']
        except Exception as e:
            return jsonify({'success': False, 'error': f'ECR repository verification failed: {e}'}), 500

        role_arn = ensure_ec2_role_profile(session)
        sg_id = ensure_ec2_security_group(session)
        ensure_ec2_key_pair(session)

        create_ec2_build_box(session, account_id, region, role_arn, sg_id)

        return jsonify({
            'success': True,
            'message': 'EC2 build box launch requested. Wait ~5–10 minutes for Docker build & ECR push to complete.'
        })
    except Exception as e:
        logger.error(f"Error creating EC2 build box: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/ec2-show-status', methods=['POST'])
@login_required
def ec2_show_status():
    """Show EC2 Build Box Status"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        inst = find_ec2_build_instance(session)

        if not inst:
            return jsonify({
                'success': False,
                'error': 'No EC2 build box found.'
            }), 404

        state = inst["State"]["Name"]
        iid = inst["InstanceId"]
        pubip = inst.get("PublicIpAddress", "N/A")

        status_msg = f"Instance: {iid}\nState: {state}\nPublic IP: {pubip}\n\n"
        console_output = ""
        build_status = ""

        try:
            ec2 = session.client("ec2")
            console_output_resp = ec2.get_console_output(InstanceId=iid)
            console_output = console_output_resp.get('Output', '')
            
            if console_output:
                if "ECR_PUSH_DONE" in console_output or "EC2 Build Box User Data Script Completed Successfully" in console_output:
                    build_status = "✅ BUILD COMPLETED SUCCESSFULLY!\n\n"
                elif "FATAL:" in console_output or "ERROR:" in console_output:
                    build_status = "❌ BUILD FAILED - Check logs below\n\n"
                elif state == "running":
                    build_status = "⏳ BUILD IN PROGRESS...\n\n"
                
                lines = console_output.split('\n')
                recent_lines = lines[-50:] if len(lines) > 50 else lines
                status_msg += build_status
                status_msg += "Recent Console Output (last 50 lines):\n"
                status_msg += "=" * 60 + "\n"
                status_msg += '\n'.join(recent_lines)
        except Exception as console_err:
            status_msg += f"Could not retrieve console output: {console_err}\n"

        return jsonify({
            'success': True,
            'instance_id': iid,
            'state': state,
            'public_ip': pubip,
            'build_status': build_status,
            'console_output': console_output,
            'status_message': status_msg
        })
    except Exception as e:
        logger.error(f"Error checking EC2 status: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@aws_manager.route('/api/aws/ec2-terminate', methods=['POST'])
@login_required
def ec2_terminate():
    """Terminate EC2 Build Box"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        inst = find_ec2_build_instance(session)

        if not inst:
            return jsonify({
                'success': False,
                'error': 'No EC2 build box to terminate.'
            }), 404

        iid = inst["InstanceId"]
        ec2 = session.client("ec2")
        ec2.terminate_instances(InstanceIds=[iid])

        return jsonify({
            'success': True,
            'instance_id': iid,
            'message': f'Terminate requested for EC2 build box: {iid}'
        })
    except Exception as e:
        logger.error(f"Error terminating EC2 instance: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

# Helper functions (adapted from aws.py)

def create_iam_role(session, role_name, service_principal, policy_arns):
    iam = session.client("iam")
    
    assume_role_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    try:
        resp = iam.get_role(RoleName=role_name)
        role_arn = resp["Role"]["Arn"]
        iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(assume_role_doc),
        )
    except iam.exceptions.NoSuchEntityException:
        resp = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_doc),
            Description=f"Education case study role for {role_name}",
        )
        role_arn = resp["Role"]["Arn"]

    for p in policy_arns:
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=p)
        except Exception as e:
            logger.warning(f"Could not attach policy {p} to {role_name}: {e}")

    time.sleep(10)  # Wait for propagation
    return role_arn

def ensure_lambda_role(session):
    iam = session.client("iam")
    lambda_policies = [
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",  # For app password storage
    ]
    
    try:
        resp = iam.get_role(RoleName=LAMBDA_ROLE_NAME)
        role_arn = resp["Role"]["Arn"]
        
        attached_policies = iam.list_attached_role_policies(RoleName=LAMBDA_ROLE_NAME)
        attached_policy_arns = [p['PolicyArn'] for p in attached_policies['AttachedPolicies']]
        
        for policy_arn in lambda_policies:
            if policy_arn not in attached_policy_arns:
                iam.attach_role_policy(RoleName=LAMBDA_ROLE_NAME, PolicyArn=policy_arn)
                time.sleep(2)
        
        return role_arn
    except iam.exceptions.NoSuchEntityException:
        return create_iam_role(
            session,
            role_name=LAMBDA_ROLE_NAME,
            service_principal="lambda.amazonaws.com",
            policy_arns=lambda_policies,
        )

def create_ecr_repo(session, region):
    ecr = session.client("ecr")
    try:
        resp = ecr.describe_repositories(repositoryNames=[ECR_REPO_NAME])
        return True
    except ecr.exceptions.RepositoryNotFoundException:
        try:
            ecr.create_repository(
                repositoryName=ECR_REPO_NAME,
                imageTagMutability='MUTABLE',
                imageScanningConfiguration={'scanOnPush': False}
            )
            time.sleep(2)
            return True
        except Exception as e:
            logger.error(f"Error creating ECR repository: {e}")
            raise

def create_s3_bucket(session, region):
    global S3_BUCKET_NAME
    s3 = session.client("s3")
    
    try:
        s3.list_objects_v2(Bucket=S3_BUCKET_NAME, MaxKeys=1)
        return
    except ClientError as list_err:
        list_error_code = list_err.response.get('Error', {}).get('Code', '')
        if list_error_code == 'NoSuchBucket':
            pass
        elif list_error_code in ['403', 'AccessDenied']:
            account_id = session.client('sts').get_caller_identity()['Account']
            S3_BUCKET_NAME = f"{S3_BUCKET_NAME}-{account_id}"
            return create_s3_bucket(session, region)
        else:
            raise list_err
    
    try:
        if region == 'us-east-1':
            s3.create_bucket(Bucket=S3_BUCKET_NAME)
        else:
            s3.create_bucket(
                Bucket=S3_BUCKET_NAME,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        
        try:
            s3.put_bucket_versioning(
                Bucket=S3_BUCKET_NAME,
                VersioningConfiguration={'Status': 'Enabled'}
            )
        except:
            pass
        
        try:
            s3.put_public_access_block(
                Bucket=S3_BUCKET_NAME,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
        except:
            pass
    except ClientError as ce:
        raise

def inspect_iam(session):
    iam = session.client("iam")
    roles = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            if "edu-gw" in role["RoleName"]:
                roles.append({
                    'name': role['RoleName'],
                    'arn': role['Arn']
                })
    return roles

def inspect_ecr(session):
    ecr = session.client("ecr")
    repos = []
    paginator = ecr.get_paginator("describe_repositories")
    for page in paginator.paginate():
        for repo in page.get("repositories", []):
            repos.append({
                'name': repo['repositoryName'],
                'uri': repo['repositoryUri']
            })
    return repos

def inspect_s3(session):
    s3 = session.client("s3")
    buckets = []
    try:
        resp = s3.list_buckets()
        for bucket in resp.get("Buckets", []):
            if "edu-gw" in bucket["Name"]:
                buckets.append({
                    'name': bucket['Name'],
                    'created': bucket.get('CreationDate', 'N/A').isoformat() if hasattr(bucket.get('CreationDate'), 'isoformat') else str(bucket.get('CreationDate', 'N/A'))
                })
    except Exception as e:
        logger.error(f"Error listing S3 buckets: {e}")
    return buckets

def inspect_lambdas(session):
    lam = session.client("lambda")
    lambdas = []
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            if "edu-gw" in fn["FunctionName"]:
                lambdas.append({
                    'name': fn['FunctionName'],
                    'runtime': fn.get('Runtime', 'N/A'),
                    'package_type': fn.get('PackageType', 'N/A')
                })
    return lambdas

def create_or_update_lambda(session, function_name, role_arn, timeout, env_vars, package_type, image_uri=None, code_str=None):
    lam = session.client("lambda")

    if package_type == "Image":
        if image_uri is None:
            raise ValueError("image_uri is required for Image package type")
        code_params = {"ImageUri": image_uri}
        runtime = None
        handler = None
    else:
        raise ValueError(f"Unsupported package type: {package_type}")

    try:
        lam.get_function(FunctionName=function_name)
        lam.update_function_code(FunctionName=function_name, **code_params, Publish=True)
        waiter = lam.get_waiter("function_updated")
        waiter.wait(FunctionName=function_name, WaiterConfig={"Delay": 5, "MaxAttempts": 12})

        config_update_params = {
            "FunctionName": function_name,
            "Role": role_arn,
            "Timeout": timeout,
            "MemorySize": 2048,
            "Environment": {"Variables": env_vars},
            "EphemeralStorage": {"Size": 2048}
        }
        lam.update_function_configuration(**config_update_params)
        
        # CRITICAL: Aggressively remove reserved concurrency limit
        # Try multiple times to ensure it's removed (sometimes AWS API is eventually consistent)
        logger.info(f"[LAMBDA] Aggressively removing any reserved concurrency limits...")
        for attempt in range(3):
            try:
                concurrency_config = lam.get_function_concurrency(FunctionName=function_name)
                reserved_concurrency = concurrency_config.get('ReservedConcurrentExecutions')
                if reserved_concurrency:
                    logger.warning(f"[LAMBDA] Attempt {attempt + 1}: Found reserved concurrency = {reserved_concurrency}, deleting...")
                    lam.delete_function_concurrency(FunctionName=function_name)
                    time.sleep(2)  # Wait for propagation
                    logger.info(f"[LAMBDA] ✓ Deleted reserved concurrency limit")
                else:
                    logger.info(f"[LAMBDA] ✓ No reserved concurrency limit (good!)")
                    break
            except lam.exceptions.ResourceNotFoundException:
                logger.info(f"[LAMBDA] ✓ No reserved concurrency limit found (good!)")
                break
            except Exception as e:
                logger.warning(f"[LAMBDA] Attempt {attempt + 1} failed: {e}")
                if attempt < 2:
                    time.sleep(2)
                else:
                    # Final attempt: try to delete anyway
                    try:
                        lam.delete_function_concurrency(FunctionName=function_name)
                        logger.info(f"[LAMBDA] ✓ Force-deleted reserved concurrency limit")
                    except:
                        logger.error(f"[LAMBDA] Could not remove concurrency limit after 3 attempts")
    except lam.exceptions.ResourceNotFoundException:
        create_params = {
            "FunctionName": function_name,
            "Role": role_arn,
            "Code": code_params,
            "Timeout": timeout,
            "MemorySize": 2048,
            "Publish": True,
            "PackageType": package_type,
            "Environment": {"Variables": env_vars},
            "EphemeralStorage": {"Size": 2048}
        }
        lam.create_function(**create_params)
        
        # CRITICAL: Wait for function to be Active before modifying concurrency
        try:
            logger.info(f"[LAMBDA] Waiting for {function_name} to be active...")
            waiter = lam.get_waiter("function_active")
            waiter.wait(FunctionName=function_name, WaiterConfig={"Delay": 5, "MaxAttempts": 60})
            logger.info(f"[LAMBDA] {function_name} is now active.")
        except Exception as e:
            logger.warning(f"[LAMBDA] Warning waiting for active state: {e}")

        # CRITICAL: Aggressively ensure no reserved concurrency limit for new functions
        logger.info(f"[LAMBDA] Aggressively ensuring no reserved concurrency limits on new function...")
        for attempt in range(3):
            try:
                concurrency_config = lam.get_function_concurrency(FunctionName=function_name)
                reserved_concurrency = concurrency_config.get('ReservedConcurrentExecutions')
                if reserved_concurrency:
                    logger.warning(f"[LAMBDA] Attempt {attempt + 1}: New function has reserved concurrency {reserved_concurrency}, deleting...")
                    lam.delete_function_concurrency(FunctionName=function_name)
                    time.sleep(2)  # Wait for propagation
                    logger.info(f"[LAMBDA] ✓ Deleted reserved concurrency limit for new function")
                else:
                    logger.info(f"[LAMBDA] ✓ New function created without reserved concurrency limit - using account limit (1000+)")
                    break
            except lam.exceptions.ResourceNotFoundException:
                logger.info(f"[LAMBDA] ✓ New function created without reserved concurrency limit - using account limit (1000+)")
                break
            except Exception as e:
                logger.warning(f"[LAMBDA] Attempt {attempt + 1} failed: {e}")
                if attempt < 2:
                    time.sleep(2)
                else:
                    # Final attempt: try to delete anyway
                    try:
                        lam.delete_function_concurrency(FunctionName=function_name)
                        logger.info(f"[LAMBDA] ✓ Force-deleted reserved concurrency limit for new function")
                    except:
                        logger.error(f"[LAMBDA] Could not remove concurrency limit after 3 attempts")

def ensure_ec2_role_profile(session):
    iam = session.client("iam")
    ec2_policies = [
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess",
        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
        "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    ]

    role_arn = create_iam_role(
        session,
        role_name=EC2_ROLE_NAME,
        service_principal="ec2.amazonaws.com",
        policy_arns=ec2_policies,
    )

    try:
        iam.get_instance_profile(InstanceProfileName=EC2_INSTANCE_PROFILE_NAME)
    except iam.exceptions.NoSuchEntityException:
        iam.create_instance_profile(InstanceProfileName=EC2_INSTANCE_PROFILE_NAME)

    try:
        iam.add_role_to_instance_profile(
            InstanceProfileName=EC2_INSTANCE_PROFILE_NAME,
            RoleName=EC2_ROLE_NAME,
        )
    except iam.exceptions.LimitExceededException:
        pass

    time.sleep(10)
    return role_arn

def ensure_ec2_security_group(session):
    ec2 = session.client("ec2")
    vpcs = ec2.describe_vpcs()
    default_vpc_id = vpcs["Vpcs"][0]["VpcId"]

    try:
        resp = ec2.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": [EC2_SECURITY_GROUP_NAME]},
                {"Name": "vpc-id", "Values": [default_vpc_id]},
            ]
        )
        if resp["SecurityGroups"]:
            return resp["SecurityGroups"][0]["GroupId"]
    except:
        pass

    resp = ec2.create_security_group(
        GroupName=EC2_SECURITY_GROUP_NAME,
        Description="EC2 build box security group for docker-selenium-lambda",
        VpcId=default_vpc_id,
    )
    sg_id = resp["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH from anywhere (demo)"}],
            }
        ],
    )

    return sg_id

def ensure_ec2_key_pair(session):
    ec2 = session.client("ec2")
    try:
        ec2.describe_key_pairs(KeyNames=[EC2_KEY_PAIR_NAME])
    except ClientError:
        resp = ec2.create_key_pair(KeyName=EC2_KEY_PAIR_NAME)
        private_key = resp["KeyMaterial"]
        key_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            f"{EC2_KEY_PAIR_NAME}.pem"
        )
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(private_key)
        os.chmod(key_path, 0o400)

def create_ec2_build_box(session, account_id, region, role_arn, sg_id):
    ec2 = session.client("ec2")
    ssm = session.client("ssm")
    s3 = session.client("s3")

    # Ensure S3 bucket exists before uploading
    logger.info(f"[EC2] Ensuring S3 bucket {S3_BUCKET_NAME} exists...")
    try:
        create_s3_bucket(session, region)
    except Exception as e:
        logger.warning(f"[EC2] S3 bucket creation warning: {e}")

    # Upload custom files to S3 for EC2 to download
    s3_build_prefix = "ec2-build-files"
    repo_files_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "repo_aws_files")
    main_py_path = os.path.join(repo_files_dir, "main.py")
    dockerfile_path = os.path.join(repo_files_dir, "Dockerfile")
    
    if not os.path.exists(main_py_path):
        raise Exception(f"Custom main.py not found at {main_py_path}. Please ensure repo_aws_files/main.py exists.")
    
    # Upload main.py
    logger.info(f"[EC2] Uploading custom main.py to S3: s3://{S3_BUCKET_NAME}/{s3_build_prefix}/main.py")
    
    try:
        with open(main_py_path, 'rb') as f:
            s3.put_object(
                Bucket=S3_BUCKET_NAME,
                Key=f"{s3_build_prefix}/main.py",
                Body=f.read(),
                ContentType="text/x-python"
            )
        logger.info(f"[EC2] Custom main.py uploaded successfully")
        
        # Upload Dockerfile if it exists
        if os.path.exists(dockerfile_path):
            logger.info(f"[EC2] Uploading custom Dockerfile to S3: s3://{S3_BUCKET_NAME}/{s3_build_prefix}/Dockerfile")
            with open(dockerfile_path, 'rb') as f:
                s3.put_object(
                    Bucket=S3_BUCKET_NAME,
                    Key=f"{s3_build_prefix}/Dockerfile",
                    Body=f.read(),
                    ContentType="text/plain"
                )
            logger.info(f"[EC2] Custom Dockerfile uploaded successfully")
        else:
            logger.warning(f"[EC2] Dockerfile not found at {dockerfile_path}, will use default from repo")
            
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'AccessDenied':
            raise Exception(f"Access Denied to S3 bucket {S3_BUCKET_NAME}. Please ensure your AWS credentials have S3 write permissions (s3:PutObject).")
        else:
            raise Exception(f"Failed to upload files to S3: {e}")
    except Exception as e:
        logger.error(f"[EC2] Failed to upload files to S3: {e}")
        raise Exception(f"Failed to upload files to S3: {e}")

    param = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )
    ami_id = param["Parameter"]["Value"]

    instance_type = "t3.small"  # Using t3.small for reliable Docker builds

    repo_uri_base = f"{account_id}.dkr.ecr.{region}.amazonaws.com/{ECR_REPO_NAME}"

    # User data script that downloads custom main.py from S3
    user_data = f"""#!/bin/bash
set -xe
exec > >(tee /var/log/user-data.log) 2>&1
echo "=== EC2 Build Box User Data Script Started ==="
date

yum update -y
amazon-linux-extras install docker -y || yum install -y docker
systemctl enable docker
systemctl start docker
usermod -a -G docker ec2-user
yum install -y git unzip

curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install

cd /home/ec2-user
echo "Cloning docker-selenium-lambda repo..."
git clone https://github.com/umihico/docker-selenium-lambda.git
cd docker-selenium-lambda

echo "Downloading custom files from S3..."
aws s3 cp s3://{S3_BUCKET_NAME}/{s3_build_prefix}/main.py ./main.py
if [ $? -eq 0 ]; then
    echo "Custom main.py downloaded successfully"
    chmod 644 main.py
else
    echo "WARNING: Failed to download custom main.py, using default from repo"
fi

aws s3 cp s3://{S3_BUCKET_NAME}/{s3_build_prefix}/Dockerfile ./Dockerfile
if [ $? -eq 0 ]; then
    echo "Custom Dockerfile downloaded successfully"
    chmod 644 Dockerfile
else
    echo "INFO: No custom Dockerfile found, using default from repo"
fi

echo "Verifying ECR repository exists..."
ECR_FOUND=0
for i in {{1..60}}; do
    if aws ecr describe-repositories --repository-names {ECR_REPO_NAME} --region {region} 2>/dev/null; then
        echo "ECR repository found!"
        ECR_FOUND=1
        break
    fi
    echo "Waiting for ECR repository... ($i/60)"
    sleep 1
done

if [ $ECR_FOUND -eq 0 ]; then
    echo "WARNING: ECR repository {ECR_REPO_NAME} not found after 60 seconds!"
    if aws ecr create-repository --repository-name {ECR_REPO_NAME} --region {region} --image-tag-mutability MUTABLE 2>/dev/null; then
        echo "ECR repository created successfully!"
        sleep 3
        ECR_FOUND=1
    fi
fi

if [ $ECR_FOUND -eq 0 ]; then
    echo "FATAL: ECR repository verification failed. Exiting."
    exit 1
fi

echo "Logging into ECR..."
aws ecr get-login-password --region {region} | docker login --username AWS --password-stdin {account_id}.dkr.ecr.{region}.amazonaws.com

echo "Building Docker image..."
docker build -t {ECR_REPO_NAME}:{ECR_IMAGE_TAG} .

echo "Tagging Docker image..."
docker tag {ECR_REPO_NAME}:{ECR_IMAGE_TAG} {repo_uri_base}:{ECR_IMAGE_TAG}

echo "Pushing Docker image to ECR..."
docker push {repo_uri_base}:{ECR_IMAGE_TAG}

echo "Verifying image push..."
aws ecr describe-images --repository-name {ECR_REPO_NAME} --image-ids imageTag={ECR_IMAGE_TAG} --region {region}

touch /home/ec2-user/ECR_PUSH_DONE
echo "=== EC2 Build Box User Data Script Completed Successfully ==="
date
"""

    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        IamInstanceProfile={"Name": EC2_INSTANCE_PROFILE_NAME},
        SecurityGroupIds=[sg_id],
        KeyName=EC2_KEY_PAIR_NAME,
        UserData=user_data,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": EC2_INSTANCE_NAME},
                    {"Key": "Purpose", "Value": "docker-selenium-lambda-build"},
                ],
            }
        ],
    )
    return resp["Instances"][0]["InstanceId"]

def find_ec2_build_instance(session):
    ec2 = session.client("ec2")
    resp = ec2.describe_instances(
        Filters=[
            {"Name": "tag:Name", "Values": [EC2_INSTANCE_NAME]},
            {
                "Name": "instance-state-name",
                "Values": ["pending", "running", "stopping", "stopped"],
            },
        ]
    )
    for r in resp.get("Reservations", []):
        for inst in r.get("Instances", []):
            return inst
    return None
