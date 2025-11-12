"""
DNS Manager routes for domain addition and verification.
"""
import logging
import uuid
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from flask import Blueprint, request, jsonify, session
from database import db, DomainOperation, GoogleAccount, NamecheapConfig
from services.zone_utils import to_apex, matching_zone_in_namecheap
from services.google_domains_service import GoogleDomainsService
from services.namecheap_dns_service import NamecheapDNSService

logger = logging.getLogger(__name__)

dns_manager = Blueprint('dns_manager', __name__)

# Store active jobs
active_jobs = {}
job_lock = threading.Lock()

def process_domain_verification(job_id: str, domain: str, account_name: str, dry_run: bool, skip_verified: bool):
    """
    Process domain verification for a single domain in background thread.
    
    Args:
        job_id: Job UUID
        domain: Input domain (can be subdomain)
        account_name: Google account name
        dry_run: If True, skip DNS writes
        skip_verified: If True, skip already verified domains
    """
    # Create Flask app context for background thread
    from app import app
    with app.app_context():
        operation_id = str(uuid.uuid4())
        operation = DomainOperation(
            id=operation_id,
            job_id=job_id,
            input_domain=domain,
            apex_domain='',
            workspace_status='pending',
            dns_status='pending',
            verify_status='pending',
            message='Initializing...',
            raw_log=[]
        )
        db.session.add(operation)
        db.session.commit()
        
        log_entry = lambda step, status, msg: {
            'step': step,
            'status': status,
            'message': msg,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Step 1: Convert to apex
            apex = to_apex(domain)
            operation.apex_domain = apex
            operation.raw_log = [log_entry('apex', 'success', f'Converted {domain} to apex: {apex}')]
            db.session.commit()
            
            # Step 2: Check if already verified (if skip_verified is True)
            if skip_verified:
                try:
                    google_service = GoogleDomainsService(account_name)
                    if google_service.is_verified(apex):
                        operation.workspace_status = 'skipped'
                        operation.dns_status = 'skipped'
                        operation.verify_status = 'skipped'
                        operation.message = 'Domain already verified (skipped)'
                        operation.raw_log.append(log_entry('check', 'skipped', 'Domain already verified'))
                        db.session.commit()
                        return
                except Exception as e:
                    logger.warning(f"Error checking verification status for {apex}: {e}")
                    # Continue with process
            
            # Step 3: Add domain to Workspace
            try:
                google_service = GoogleDomainsService(account_name)
                result = google_service.ensure_domain_added(apex)
                
                if result.get('already_exists'):
                    operation.workspace_status = 'success'
                    operation.raw_log.append(log_entry('workspace', 'success', 'Domain already exists in Workspace'))
                elif result.get('created'):
                    operation.workspace_status = 'success'
                    operation.raw_log.append(log_entry('workspace', 'success', 'Domain added to Workspace'))
                else:
                    raise Exception("Unexpected result from ensure_domain_added")
                
                db.session.commit()
            
            except Exception as e:
                operation.workspace_status = 'failed'
                operation.message = f'Failed to add domain to Workspace: {str(e)}'
                operation.raw_log.append(log_entry('workspace', 'failed', str(e)))
                db.session.commit()
                return
            
            # Step 4: Get verification token
            try:
                token_result = google_service.get_verification_token(apex)
                token = token_result['token']
                host = token_result.get('host', '@')
                txt_value = token_result.get('txt_value', f'google-site-verification={token}')
                
                operation.raw_log.append(log_entry('token', 'success', f'Retrieved verification token'))
                db.session.commit()
            
            except Exception as e:
                operation.dns_status = 'failed'
                operation.message = f'Failed to get verification token: {str(e)}'
                operation.raw_log.append(log_entry('token', 'failed', str(e)))
                db.session.commit()
                return
            
            # Step 5: Create TXT record in Namecheap (unless dry-run)
            if dry_run:
                operation.dns_status = 'dry-run'
                operation.message = 'Dry-run: DNS TXT record not created'
                operation.raw_log.append(log_entry('dns', 'dry-run', 'Dry-run mode: skipping DNS write'))
                db.session.commit()
            else:
                try:
                    dns_service = NamecheapDNSService()
                    dns_result = dns_service.upsert_txt_record(apex, host, txt_value, ttl=300)
                    
                    operation.dns_status = 'success'
                    operation.message = f'TXT record created: {dns_result.get("message", "Success")}'
                    operation.raw_log.append(log_entry('dns', 'success', f'TXT record created: {txt_value}'))
                    db.session.commit()
                
                except Exception as e:
                    operation.dns_status = 'failed'
                    operation.message = f'Failed to create TXT record: {str(e)}'
                    operation.raw_log.append(log_entry('dns', 'failed', str(e)))
                    db.session.commit()
                    return
            
            # Step 6: Verify domain (with retries)
            if not dry_run:
                max_attempts = 10
                attempt = 0
                verified = False
                
                while attempt < max_attempts and not verified:
                    attempt += 1
                    try:
                        time.sleep(20)  # Wait for DNS propagation
                        verify_result = google_service.verify_domain(apex)
                        
                        if verify_result.get('verified'):
                            verified = True
                            operation.verify_status = 'success'
                            operation.message = 'Domain verified successfully'
                            operation.raw_log.append(log_entry('verify', 'success', f'Verified on attempt {attempt}'))
                        else:
                            operation.raw_log.append(log_entry('verify', 'pending', f'Attempt {attempt}/{max_attempts}: Not yet verified'))
                            if attempt < max_attempts:
                                time.sleep(30)  # Wait longer between retries
                    
                    except Exception as e:
                        operation.raw_log.append(log_entry('verify', 'error', f'Attempt {attempt} error: {str(e)}'))
                        if attempt < max_attempts:
                            time.sleep(30)
                
                if not verified:
                    operation.verify_status = 'failed'
                    operation.message = f'Verification failed after {max_attempts} attempts'
                    operation.raw_log.append(log_entry('verify', 'failed', 'Verification timeout'))
                
                db.session.commit()
            else:
                operation.verify_status = 'skipped'
                operation.message = 'Dry-run: Verification skipped'
                operation.raw_log.append(log_entry('verify', 'skipped', 'Dry-run mode'))
                db.session.commit()
        
        except Exception as e:
            logger.error(f"Error processing domain {domain}: {e}")
            operation.message = f'Unexpected error: {str(e)}'
            operation.raw_log.append(log_entry('error', 'failed', str(e)))
            db.session.commit()

@dns_manager.route('/api/domains/add-and-verify', methods=['POST'])
def add_and_verify_domains():
    """
    Start domain addition and verification process.
    
    Request body:
        {
            "domains": ["example.com", "sub.team.io"],
            "dryRun": false,
            "skipVerified": true
        }
    
    Returns:
        {
            "job_id": "<uuid>",
            "accepted": <n>
        }
    """
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        dry_run = data.get('dryRun', False)
        skip_verified = data.get('skipVerified', True)
        
        if not domains:
            return jsonify({'success': False, 'error': 'No domains provided'}), 400
        
        # Get current account name from session
        account_name = session.get('current_account_name')
        if not account_name:
            return jsonify({'success': False, 'error': 'No authenticated account'}), 401
        
        # Verify account exists
        account = GoogleAccount.query.filter_by(account_name=account_name).first()
        if not account:
            return jsonify({'success': False, 'error': 'Account not found'}), 404
        
        # Normalize domains: trim, lowercase, remove duplicates, ignore empty
        normalized_domains = []
        seen = set()
        for domain in domains:
            domain = domain.strip().lower()
            if domain and domain not in seen:
                normalized_domains.append(domain)
                seen.add(domain)
        
        if not normalized_domains:
            return jsonify({'success': False, 'error': 'No valid domains after normalization'}), 400
        
        # Create job
        job_id = str(uuid.uuid4())
        
        with job_lock:
            active_jobs[job_id] = {
                'status': 'running',
                'total': len(normalized_domains),
                'started_at': datetime.now().isoformat()
            }
        
        # Start background processing
        max_workers = min(5, len(normalized_domains))  # Cap at 5 parallel domains
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for domain in normalized_domains:
                executor.submit(
                    process_domain_verification,
                    job_id,
                    domain,
                    account_name,
                    dry_run,
                    skip_verified
                )
        
        logger.info(f"Started domain verification job {job_id} for {len(normalized_domains)} domains")
        
        return jsonify({
            'success': True,
            'job_id': job_id,
            'accepted': len(normalized_domains)
        })
    
    except Exception as e:
        logger.error(f"Error starting domain verification: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@dns_manager.route('/api/namecheap-config', methods=['GET', 'POST'])
def namecheap_config():
    """
    Get or save Namecheap configuration.
    
    GET: Returns current configuration
    POST: Saves configuration
        {
            "api_user": "...",
            "api_key": "...",
            "username": "...",
            "client_ip": "..."
        }
    """
    try:
        if request.method == 'GET':
            config = NamecheapConfig.query.filter_by(is_configured=True).first()
            if config:
                return jsonify({
                    'success': True,
                    'config': {
                        'api_user': config.api_user,
                        'username': config.username,
                        'client_ip': config.client_ip,
                        'is_configured': config.is_configured
                    }
                })
            else:
                return jsonify({
                    'success': True,
                    'config': None
                })
        
        else:  # POST
            data = request.get_json()
            api_user = data.get('api_user', '').strip()
            api_key = data.get('api_key', '').strip()
            username = data.get('username', '').strip()
            client_ip = data.get('client_ip', '').strip()
            
            if not all([api_user, api_key, username, client_ip]):
                return jsonify({'success': False, 'error': 'All fields required'}), 400
            
            # Get or create config
            config = NamecheapConfig.query.filter_by(is_configured=True).first()
            if not config:
                config = NamecheapConfig()
            
            config.api_user = api_user
            config.api_key = api_key
            config.username = username
            config.client_ip = client_ip
            config.is_configured = True
            
            db.session.add(config)
            db.session.commit()
            
            logger.info("Namecheap configuration saved")
            return jsonify({'success': True, 'message': 'Configuration saved'})
    
    except Exception as e:
        logger.error(f"Error managing Namecheap config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@dns_manager.route('/api/domains/status', methods=['GET'])
def get_domain_status():
    """
    Get status of domain verification job.
    
    Query params:
        job_id: Job UUID
    
    Returns:
        Array of domain operation status objects
    """
    try:
        job_id = request.args.get('job_id')
        if not job_id:
            return jsonify({'success': False, 'error': 'job_id required'}), 400
        
        # Get all operations for this job
        operations = DomainOperation.query.filter_by(job_id=job_id).order_by(DomainOperation.updated_at).all()
        
        results = []
        for op in operations:
            results.append({
                'domain': op.input_domain,
                'apex': op.apex_domain,
                'workspace': op.workspace_status,
                'dns': op.dns_status,
                'verify': op.verify_status,
                'message': op.message,
                'updated_at': op.updated_at.isoformat() if op.updated_at else None
            })
        
        return jsonify({
            'success': True,
            'results': results,
            'total': len(results)
        })
    
    except Exception as e:
        logger.error(f"Error getting domain status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
