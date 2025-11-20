"""
AWS Management routes for AWS infrastructure, Lambda, and EC2 management.
"""
import os
import boto3
from botocore.exceptions import ClientError
import json
import io
import zipfile
import time
import traceback
import logging
import threading
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Blueprint, request, jsonify, session, render_template, copy_current_request_context
from functools import wraps
from database import db, UserAppPassword, AwsGeneratedPassword

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

# Global set to track emails currently being processed (prevent duplicates within a job)
processing_emails = set()
processing_lock = threading.Lock()

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
        if 'aws_generated_password' not in inspector.get_table_names():
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
    """Create/Update production Lambda"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()
        ecr_uri = data.get('ecr_uri', '').strip()
        s3_bucket = data.get('s3_bucket', '').strip()
        sftp_host = data.get('sftp_host', '').strip()
        sftp_user = data.get('sftp_user', '').strip()
        sftp_password = data.get('sftp_password', '').strip()
        sftp_dir = data.get('sftp_dir', '/home/brightmindscampus/').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        if not ecr_uri or 'amazonaws.com' not in ecr_uri:
            return jsonify({'success': False, 'error': 'ECR Image URI is not set. Connect and prepare EC2 build box first.'}), 400

        if not s3_bucket:
            return jsonify({'success': False, 'error': 'Please enter S3 Bucket name for app passwords storage.'}), 400

        if not sftp_host or not sftp_user:
            return jsonify({'success': False, 'error': 'Please enter SFTP Host and User for secret key storage.'}), 400

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

        # Environment variables
        chromium_env = {
            "DYNAMODB_TABLE_NAME": "gbot-app-passwords",  # DynamoDB table for password storage
            "APP_PASSWORDS_S3_BUCKET": s3_bucket,
            "APP_PASSWORDS_S3_KEY": "app-passwords.txt",
            "SECRET_SFTP_HOST": sftp_host,
            "SECRET_SFTP_USER": sftp_user,
            "SECRET_SFTP_PASSWORD": sftp_password,
            "SECRET_SFTP_PORT": "22",
            "SECRET_SFTP_REMOTE_DIR": sftp_dir,
        }

        # Create/Update Lambda
        create_or_update_lambda(
            session=session,
            function_name=PRODUCTION_LAMBDA_NAME,
            role_arn=role_arn,
            timeout=600,
            env_vars=chromium_env,
            package_type="Image",
            image_uri=ecr_uri,
        )

        return jsonify({
            'success': True,
            'message': 'PRODUCTION Lambda is ready.'
        })
    except Exception as e:
        logger.error(f"Error creating Lambda: {e}")
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

    job_id = str(int(time.time()))
    active_jobs[job_id] = {
        'total': len(users),
        'completed': 0,
        'success': 0,
        'failed': 0,
        'results': [],
        'status': 'processing'
    }

    # Start background thread
    # We pass app_context explicitly if needed, but db operations need app context inside the thread
    from app import app
    
    def background_process(app, job_id, users, access_key, secret_key, region):
        with app.app_context():
            session_boto = get_boto3_session(access_key, secret_key, region)
            lam = session_boto.client("lambda")
            
            def process_single_user(user):
                with app.app_context():
                    email = user['email']
                    password = user['password']
                    
                    # Check DynamoDB first - if password already exists, skip
                    try:
                        dynamodb = session_boto.resource('dynamodb')
                        table = dynamodb.Table("gbot-app-passwords")
                        response = table.get_item(Key={'email': email})
                        if 'Item' in response:
                            existing_password = response['Item'].get('app_password')
                            logger.info(f"[BULK] ✓ SKIPPED: {email} already has password in DynamoDB")
                            # Save to local DB too
                            try:
                                save_app_password(email, existing_password)
                            except:
                                pass
                            return {'email': email, 'success': True, 'app_password': existing_password, 'skipped': True}
                    except Exception as e:
                        logger.warning(f"[BULK] Could not check DynamoDB for {email}: {e}")
                    
                    # Check if email is already being processed in memory (deduplicate)
                    with processing_lock:
                        if email in processing_emails:
                            logger.warning(f"[BULK] ⚠️ SKIPPED: {email} is already being processed")
                            return {'email': email, 'success': False, 'error': 'Duplicate - already processing'}
                        processing_emails.add(email)
                    
                    try:
                        logger.info(f"[BULK] Invoking Lambda for {email}")
                        
                        # Retry logic for rate limiting (optimized for high concurrency)
                        max_retries = 5  # Increased retries for high concurrency scenarios
                        for attempt in range(max_retries):
                            try:
                                resp = lam.invoke(
                                    FunctionName=PRODUCTION_LAMBDA_NAME,
                                    InvocationType="RequestResponse", # Sync
                                    Payload=json.dumps({"email": email, "password": password}).encode("utf-8"),
                                )
                                break  # Success, exit retry loop
                            except ClientError as ce:
                                error_code = ce.response['Error']['Code']
                                if error_code == 'TooManyRequestsException' or error_code == 'ThrottlingException':
                                    if attempt < max_retries - 1:
                                        # Exponential backoff with jitter to prevent thundering herd
                                        base_wait = (2 ** attempt) * 2  # 2s, 4s, 8s, 16s, 32s
                                        jitter = random.uniform(0, 1)  # Add random jitter
                                        wait_time = base_wait + jitter
                                        logger.warning(f"[BULK] Rate limited for {email}, retrying in {wait_time:.2f}s (attempt {attempt + 1}/{max_retries})")
                                        time.sleep(wait_time)
                                    else:
                                        raise  # Final attempt failed
                                else:
                                    raise  # Other AWS error, don't retry
                        
                        payload = resp.get("Payload")
                        body = payload.read().decode("utf-8") if payload else "{}"
                        logger.info(f"[BULK] Lambda response for {email}: {body[:500]}")  # Show more of response
                        
                        try:
                            data = json.loads(body)
                        except json.JSONDecodeError as je:
                            logger.error(f"[BULK] Failed to parse Lambda response as JSON for {email}: {je}")
                            return {'email': email, 'success': False, 'error': f'Invalid JSON response: {body[:200]}'}
                        
                        # Check Lambda status first
                        lambda_status = data.get('status', 'unknown')
                        app_password = data.get('app_password')
                        error_msg = data.get('error_message', 'Unknown error')
                        
                        logger.info(f"[BULK] Lambda status for {email}: {lambda_status}, has_password: {bool(app_password)}")
                        
                        # If successful and has app_password, save to DB
                        if lambda_status == 'success' and app_password:
                            logger.info(f"[BULK] Saving password for {email} to DB")
                            try:
                                save_app_password(email, app_password)
                                logger.info(f"[BULK] ✓ Successfully processed {email}")
                            except Exception as db_err:
                                logger.error(f"[BULK] Failed to save to DB for {email}: {db_err}")
                                # Continue anyway - we have the password
                            return {'email': email, 'success': True, 'app_password': app_password}
                        else:
                            logger.warning(f"[BULK] ✗ Lambda failed for {email}: {error_msg}")
                            return {'email': email, 'success': False, 'error': error_msg}
                    except Exception as e:
                        logger.error(f"[BULK] Exception for {email}: {e}")
                        logger.error(f"[BULK] Traceback: {traceback.format_exc()}")
                        return {'email': email, 'success': False, 'error': str(e)}
                    finally:
                        # Remove from processing set when done
                        with processing_lock:
                            processing_emails.discard(email)

            # Execute in parallel
            # Use 1000 workers for maximum concurrency (Lambda supports up to 1000 concurrent executions)
            with ThreadPoolExecutor(max_workers=1000) as pool: 
                futures = {pool.submit(process_single_user, u): u for u in users}
                
                for future in as_completed(futures):
                    result = future.result()
                    active_jobs[job_id]['completed'] += 1
                    if result['success']:
                        active_jobs[job_id]['success'] += 1
                        active_jobs[job_id]['results'].append({
                            'email': result['email'],
                            'app_password': result['app_password'],
                            'success': True
                        })
                    else:
                        active_jobs[job_id]['failed'] += 1
                        active_jobs[job_id]['results'].append({
                            'email': result['email'],
                            'error': result.get('error'),
                            'success': False
                        })
            
            active_jobs[job_id]['status'] = 'completed'

    threading.Thread(target=background_process, args=(app, job_id, users, access_key, secret_key, region)).start()

    return jsonify({'success': True, 'job_id': job_id, 'message': f'Started processing {len(users)} users'})

@aws_manager.route('/api/aws/job-status/<job_id>', methods=['GET'])
@login_required
def get_job_status(job_id):
    job = active_jobs.get(job_id)
    if not job:
        return jsonify({'success': False, 'error': 'Job not found'}), 404
    # Return the job status including the results list (which has the new passwords)
    return jsonify({'success': True, 'job': job})

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

        event = {
            "email": email,
            "password": password,
        }

        invocation_type = "Event" if async_mode else "RequestResponse"
        resp = lam.invoke(
            FunctionName=PRODUCTION_LAMBDA_NAME,
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
    """Delete all contents from S3 bucket"""
    try:
        data = request.get_json()
        access_key = data.get('access_key', '').strip()
        secret_key = data.get('secret_key', '').strip()
        region = data.get('region', '').strip()

        if not access_key or not secret_key or not region:
            return jsonify({'success': False, 'error': 'Please provide AWS credentials.'}), 400

        session = get_boto3_session(access_key, secret_key, region)
        s3 = session.client("s3")

        deleted_count = 0
        paginator = s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=S3_BUCKET_NAME):
            objects = page.get('Contents', [])
            if objects:
                delete_keys = [{'Key': obj['Key']} for obj in objects]
                s3.delete_objects(
                    Bucket=S3_BUCKET_NAME,
                    Delete={'Objects': delete_keys}
                )
                deleted_count += len(delete_keys)

        return jsonify({
            'success': True,
            'deleted_count': deleted_count,
            'message': f'S3 bucket {S3_BUCKET_NAME} contents deleted successfully.'
        })
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'NoSuchBucket':
            return jsonify({
                'success': False,
                'error': f'S3 bucket {S3_BUCKET_NAME} does not exist.'
            }), 404
        return jsonify({'success': False, 'error': str(e)}), 500
    except Exception as e:
        logger.error(f"Error deleting S3 contents: {e}")
        traceback.print_exc()
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
