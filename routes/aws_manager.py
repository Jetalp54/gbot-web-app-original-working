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
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Blueprint, request, jsonify, session, render_template, copy_current_request_context
from functools import wraps
from database import db, UserAppPassword

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
                email = user['email']
                password = user['password']
                try:
                    resp = lam.invoke(
                        FunctionName=PRODUCTION_LAMBDA_NAME,
                        InvocationType="RequestResponse", # Sync
                        Payload=json.dumps({"email": email, "password": password}).encode("utf-8"),
                    )
                    payload = resp.get("Payload")
                    body = payload.read().decode("utf-8") if payload else "{}"
                    data = json.loads(body)
                    
                    # If successful and has app_password, save to DB
                    if data.get('app_password'):
                        save_app_password(email, data['app_password'])
                        return {'email': email, 'success': True, 'app_password': data['app_password']}
                    else:
                        error_msg = data.get('error_message', 'Unknown error')
                        return {'email': email, 'success': False, 'error': error_msg}
                except Exception as e:
                    return {'email': email, 'success': False, 'error': str(e)}

            # Execute in parallel
            with ThreadPoolExecutor(max_workers=10) as pool: # Server-side concurrency limit
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
    return jsonify({'success': True, 'job': job})

@aws_manager.route('/api/aws/generated-passwords', methods=['GET'])
@login_required
def get_generated_passwords():
    """Fetch all generated app passwords from DB"""
    try:
        # Get recent passwords
        passwords = UserAppPassword.query.order_by(UserAppPassword.created_at.desc()).all()
        result = []
        for p in passwords:
            email = f"{p.username}@{p.domain}"
            result.append({
                'email': email,
                'app_password': p.app_password,
                'created_at': p.created_at.isoformat()
            })
        return jsonify({'success': True, 'passwords': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def save_app_password(email, app_password):
    """Save app password to DB, splitting email into username and domain"""
    try:
        if '@' in email:
            username, domain = email.split('@', 1)
        else:
            username = email
            domain = 'unknown'
            
        # Check if exists
        existing = UserAppPassword.query.filter_by(username=username, domain=domain).first()
        if existing:
            existing.app_password = app_password
            existing.updated_at = db.func.current_timestamp()
        else:
            new_entry = UserAppPassword(username=username, domain=domain, app_password=app_password)
            db.session.add(new_entry)
        
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving app password for {email}: {e}")

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
                    save_app_password(email, response_data['app_password'])
                
                return jsonify({
                    'success': True,
                    **response_data
                })
            except:
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

    param = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )
    ami_id = param["Parameter"]["Value"]

    instance_type = "t3.small"  # Using t3.small for reliable Docker builds

    repo_uri_base = f"{account_id}.dkr.ecr.{region}.amazonaws.com/{ECR_REPO_NAME}"

    # User data script (simplified - full version would upload files to S3)
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
