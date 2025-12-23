"""
DNS Manager routes for domain addition and verification.
"""
import logging
import uuid
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from flask import Blueprint, request, jsonify, session, redirect, url_for
from functools import wraps
from database import db, DomainOperation, GoogleAccount, ServiceAccount, CloudflareConfig
from services.zone_utils import to_apex
from services.google_domains_service import GoogleDomainsService
from services.namecheap_dns_service import NamecheapDNSService
from services.cloudflare_dns_service import CloudflareDNSService

logger = logging.getLogger(__name__)

dns_manager = Blueprint('dns_manager', __name__)

# Login required decorator (matches app.py implementation)
def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

# Store active jobs
active_jobs = {}
job_lock = threading.Lock()

def process_domain_verification(job_id: str, domain: str, account_name: str, dry_run: bool, skip_verified: bool, provider: str = 'namecheap', stop_event=None):
    """
    Process domain verification for a single domain in background thread.
    
    Args:
        job_id: Job UUID
        domain: Input domain (can be subdomain)
        account_name: Google account name
        dry_run: If True, skip DNS writes
        skip_verified: If True, skip already verified domains
        provider: DNS provider ('namecheap' or 'cloudflare')
        stop_event: threading.Event to signal stopping
    """
    # Create Flask app context for background thread
    from app import app
    with app.app_context():
        # Check stop event at start
        if stop_event and stop_event.is_set():
            logger.info(f"Job {job_id}: Domain {domain} processing stopped by user (before start)")
            return

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
        
        logger.info(f"Job {job_id}: Started processing domain {domain} (Operation {operation_id})")
        
        log_entry = lambda step, status, msg: {
            'step': step,
            'status': status,
            'message': msg,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Step 1: Identify apex domain
            if stop_event and stop_event.is_set():
                operation.message = 'Stopped by user'
                operation.raw_log.append(log_entry('stop', 'stopped', 'Process stopped by user'))
                db.session.commit()
                return

            apex = to_apex(domain)
            logger.info(f"Processing domain: {domain} -> Apex: {apex} (Provider: {provider})")
            
            # Determine TXT host (subdomain part or @)
            txt_host = '@'
            if domain.lower() != apex.lower():
                # It's a subdomain
                # domain = sub.example.com, apex = example.com
                # host = sub
                domain_parts = domain.lower().split('.')
                apex_parts = apex.lower().split('.')
                # Subdomain is the part of domain not in apex
                if len(domain_parts) > len(apex_parts):
                    subdomain_part = domain_parts[:len(domain_parts) - len(apex_parts)]
                    txt_host = '.'.join(subdomain_part)
            
            logger.info(f"TXT Host for {domain} (Apex: {apex}): {txt_host}")
            
            operation.apex_domain = apex
            operation.raw_log = [log_entry('apex', 'success', f'Converted {domain} to apex: {apex}, TXT host: {txt_host}')]
            db.session.commit()
            
            # Step 2: Check if already verified (if skip_verified is True)
            if stop_event and stop_event.is_set():
                operation.message = 'Stopped by user'
                operation.raw_log.append(log_entry('stop', 'stopped', 'Process stopped by user'))
                db.session.commit()
                return

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
            
            # Step 3: Add domain to Workspace (or continue if already exists)
            if stop_event and stop_event.is_set():
                operation.message = 'Stopped by user'
                operation.raw_log.append(log_entry('stop', 'stopped', 'Process stopped by user'))
                db.session.commit()
                return

            google_service = None
            try:
                logger.info(f"Job {job_id}: Step 3 - Adding {domain} to Workspace")
                google_service = GoogleDomainsService(account_name)
                result = google_service.ensure_domain_added(domain)
                
                if result.get('already_exists'):
                    operation.workspace_status = 'success'
                    operation.message = 'Domain exists, getting verification token...'
                    operation.raw_log.append(log_entry('workspace', 'success', 'Domain already exists in Workspace - continuing with verification'))
                    logger.info(f"Domain {domain} already exists, continuing with verification process")
                    db.session.commit()
                elif result.get('created'):
                    operation.workspace_status = 'success'
                    operation.message = 'Domain added, getting verification token...'
                    operation.raw_log.append(log_entry('workspace', 'success', 'Domain added to Workspace'))
                    logger.info(f"Domain {domain} added to Workspace")
                    db.session.commit()
                else:
                    raise Exception("Unexpected result from ensure_domain_added")
                
                db.session.commit()
                # IMPORTANT: Continue to next step even if domain already exists
            
            except Exception as e:
                error_msg = str(e)
                # Check for common error types
                if 'insufficient' in error_msg.lower() or 'scope' in error_msg.lower():
                    error_msg = f'Missing required Google API scopes. Please re-authenticate with site verification scope: {error_msg}'
                    operation.workspace_status = 'failed'
                    operation.message = error_msg
                    operation.raw_log.append(log_entry('workspace', 'failed', error_msg))
                    db.session.commit()
                    return
                elif '403' in error_msg or 'forbidden' in error_msg.lower() or 'not authorized' in error_msg.lower():
                    # 403 error - Permission denied
                    # This is now a hard failure because we can't verify if the domain exists
                    error_msg = f"Permission denied (403) accessing Google Workspace. Please check your Service Account permissions and Domain-Wide Delegation. Error: {error_msg}"
                    operation.workspace_status = 'failed'
                    operation.message = error_msg
                    operation.raw_log.append(log_entry('workspace', 'failed', error_msg))
                    db.session.commit()
                    return
                elif 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower() or 'conflict' in error_msg.lower() or '409' in error_msg.lower():
                    # Domain already exists, treat as success and CONTINUE
                    operation.workspace_status = 'success'
                    operation.raw_log.append(log_entry('workspace', 'success', f'Domain already exists: {error_msg} - continuing with verification'))
                    logger.info(f"Domain {apex} already exists (from exception), continuing with verification")
                    db.session.commit()
                    # Continue to next step - don't return!
                    if not google_service:
                        google_service = GoogleDomainsService(account_name)
                else:
                    # Other errors - check if it's a permission issue that we can work around
                    if 'permission' in error_msg.lower() and 'domain' in error_msg.lower():
                        # Permission issue but domain might exist - continue
                        logger.warning(f"Permission issue for {apex}, but continuing assuming domain exists")
                        operation.workspace_status = 'success'
                        operation.raw_log.append(log_entry('workspace', 'success', f'Domain exists (continuing despite permission warning)'))
                        db.session.commit()
                        if not google_service:
                            google_service = GoogleDomainsService(account_name)
                    else:
                        operation.workspace_status = 'failed'
                        operation.message = f'Failed to add domain to Workspace: {error_msg}'
                        operation.raw_log.append(log_entry('workspace', 'failed', error_msg))
                        db.session.commit()
                        return
            
            # Step 4: Get verification token (always proceed, even if domain already existed)
            if stop_event and stop_event.is_set():
                operation.message = 'Stopped by user'
                operation.raw_log.append(log_entry('stop', 'stopped', 'Process stopped by user'))
                db.session.commit()
                return

            try:
                operation.message = 'Getting verification token from Google...'
                db.session.commit()
                
                logger.info(f"Job {job_id}: Step 4 - Getting verification token for {domain}")
                if not google_service:
                    google_service = GoogleDomainsService(account_name)
                    
                token_result = google_service.get_verification_token(domain, apex_domain=apex)
                token = token_result['token']
                # Use the calculated subdomain host, not the default '@' from Google
                # Google returns '@' for apex, but we need the subdomain part for subdomains
                txt_value = token_result.get('txt_value', f'google-site-verification={token}')
                
                # Fix for double prefix issue: ensure we don't have "google-site-verification=google-site-verification=..."
                if txt_value.startswith('google-site-verification=google-site-verification='):
                    logger.warning(f"Detected double prefix in TXT value: {txt_value}. Fixing...")
                    txt_value = txt_value.replace('google-site-verification=', '', 1)
                
                operation.message = f'Token received, creating DNS TXT record...'
                operation.raw_log.append(log_entry('token', 'success', f'Retrieved verification token, will use host: {txt_host}'))
                logger.info(f"Got verification token for {domain}, will add TXT record with host: {txt_host}")
                db.session.commit()
            
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Job {job_id}: Step 4 FAILED for {domain}: {error_msg}", exc_info=True)
                # Check for scope/permission errors
                if 'insufficient' in error_msg.lower() or 'scope' in error_msg.lower() or 'permission' in error_msg.lower():
                    error_msg = f'Missing Google Site Verification API scope. Please re-authenticate: {error_msg}'
                elif 'not found' in error_msg.lower() or '404' in error_msg.lower():
                    error_msg = f'Domain not found in Google Workspace. Ensure domain is added first: {error_msg}'
                
                operation.dns_status = 'failed'
                operation.verify_status = 'failed'
                operation.message = f'Failed to get verification token: {error_msg}'
                operation.raw_log.append(log_entry('token', 'failed', error_msg))
                db.session.commit()
                return
            
            # Step 5: Create TXT record in DNS (unless dry-run)
            if stop_event and stop_event.is_set():
                operation.message = 'Stopped by user'
                operation.raw_log.append(log_entry('stop', 'stopped', 'Process stopped by user'))
                db.session.commit()
                return

            if dry_run:
                operation.dns_status = 'dry-run'
                operation.message = f'Dry-run: DNS TXT record not created (would use host: {txt_host})'
                operation.raw_log.append(log_entry('dns', 'dry-run', f'Dry-run mode: would add TXT @ {txt_host} with value: {txt_value}'))
                db.session.commit()
            else:
                try:
                    dns_result = None
                    operation.message = f'Creating TXT record in {provider.capitalize()}...'
                    db.session.commit()
                    
                    if provider == 'cloudflare':
                        logger.info(f"Adding TXT record to Cloudflare: apex={apex}, host={txt_host}, value={txt_value}")
                        dns_service = CloudflareDNSService()
                        # Cloudflare uses TTL 1 for automatic
                        dns_result = dns_service.upsert_txt_record(apex, txt_host, txt_value, ttl=1)
                    else:
                        # Default to Namecheap
                        logger.info(f"Adding TXT record to Namecheap: apex={apex}, host={txt_host}, value={txt_value}")
                        dns_service = NamecheapDNSService()
                        # Use TTL 1799 (Automatic) as requested by user and seen in logs
                        dns_result = dns_service.upsert_txt_record(apex, txt_host, txt_value, ttl=1799)
                    
                    logger.info(f"Job {job_id}: Step 5 - DNS result: {dns_result}")
                    
                    operation.dns_status = 'success'
                    operation.message = f'TXT record created! Verifying domain...'
                    operation.raw_log.append(log_entry('dns', 'success', f'TXT record created @ {txt_host}: {dns_result}'))
                    db.session.commit()
                    
                    # Short wait for DNS propagation before verification
                    logger.info(f"Job {job_id}: Waiting 5 seconds for DNS propagation...")
                    time.sleep(5)
                    
                except Exception as e:
                    error_msg = f"DNS API Error ({provider}): {str(e)}"
                    logger.error(f"Job {job_id}: Step 5 FAILED: {error_msg}", exc_info=True)
                    operation.dns_status = 'failed'
                    operation.message = error_msg
                    operation.raw_log.append(log_entry('dns', 'failed', error_msg))
                    db.session.commit()
                    return
            
            # Step 6: Verify domain (with retries)
            if stop_event and stop_event.is_set():
                operation.message = 'Stopped by user'
                operation.raw_log.append(log_entry('stop', 'stopped', 'Process stopped by user'))
                db.session.commit()
                return

            if not dry_run:
                # Wait 10 seconds after DNS TXT record creation before first verification attempt
                logger.info(f"Waiting 10 seconds for DNS propagation before verification...")
                time.sleep(10)
                
                max_attempts = 10
                attempt = 0
                verified = False
                
                while attempt < max_attempts and not verified:
                    if stop_event and stop_event.is_set():
                        operation.message = 'Stopped by user'
                        operation.raw_log.append(log_entry('stop', 'stopped', 'Process stopped by user'))
                        db.session.commit()
                        return

                    attempt += 1
                    try:
                        logger.info(f"Verification attempt {attempt}/{max_attempts} for {domain}")
                        verify_result = google_service.verify_domain(domain)
                        
                        if verify_result.get('verified'):
                            verified = True
                            operation.verify_status = 'success'
                            operation.message = 'Domain verified successfully'
                            operation.raw_log.append(log_entry('verify', 'success', f'Verified on attempt {attempt}'))
                            logger.info(f"Domain {apex} verified successfully on attempt {attempt}")
                        else:
                            operation.raw_log.append(log_entry('verify', 'pending', f'Attempt {attempt}/{max_attempts}: Not yet verified'))
                            if attempt < max_attempts:
                                time.sleep(30)  # Wait 30 seconds between retries
                    
                    except Exception as e:
                        error_msg = str(e)
                        logger.warning(f"Verification attempt {attempt} error for {apex}: {error_msg}")
                        # Check for scope/permission errors
                        if 'insufficient' in error_msg.lower() or 'scope' in error_msg.lower() or 'permission' in error_msg.lower():
                            error_msg = f'Missing Google Site Verification API scope. Please re-authenticate: {error_msg}'
                            operation.verify_status = 'failed'
                            operation.message = error_msg
                            operation.raw_log.append(log_entry('verify', 'failed', error_msg))
                            db.session.commit()
                            return
                        
                        operation.raw_log.append(log_entry('verify', 'error', f'Attempt {attempt} error: {error_msg}'))
                        if attempt < max_attempts:
                            time.sleep(30)
                
                if not verified:
                    operation.verify_status = 'failed'
                    operation.message = f'Verification failed after {max_attempts} attempts. DNS may not have propagated yet.'
                    operation.raw_log.append(log_entry('verify', 'failed', 'Verification timeout'))
                    logger.warning(f"Domain {apex} verification failed after {max_attempts} attempts")
                
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
@login_required
def add_and_verify_domains():
    """
    Start domain addition and verification process.
    
    Request body:
        {
            "domains": ["example.com", "sub.team.io"],
            "dryRun": false,
            "skipVerified": true,
            "provider": "namecheap" (or "cloudflare")
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
        provider = data.get('provider', 'namecheap') # Default to namecheap
        
        if not domains:
            return jsonify({'success': False, 'error': 'No domains provided'}), 400
        
        # Get current account name from session
        account_name = session.get('current_account_name')
        if not account_name:
            return jsonify({'success': False, 'error': 'No authenticated account'}), 401
        
        # Verify account exists (Check Service Account first, then Google Account)
        service_account = ServiceAccount.query.filter_by(name=account_name).first()
        account = None
        
        if not service_account:
            # Fallback to old Google Account (deprecated but kept for compatibility)
            account = GoogleAccount.query.filter_by(account_name=account_name).first()
            
        if not service_account and not account:
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
                'started_at': datetime.now().isoformat(),
                'stop_event': threading.Event()
            }
        
        # Stop any other running jobs
        with job_lock:
            for jid, job in active_jobs.items():
                if jid != job_id and job.get('status') == 'running':
                    logger.info(f"Stopping existing job {jid} to start new job {job_id}")
                    if 'stop_event' in job:
                        job['stop_event'].set()
                    job['status'] = 'stopped'
        
        # Start background processing in a separate thread to allow immediate return
        def run_batch():
            # Create app context for the batch thread
            from app import app
            with app.app_context():
                max_workers = min(5, len(normalized_domains))  # Cap at 5 parallel domains
                logger.info(f"Job {job_id}: Starting batch processing with {max_workers} workers")
                
                try:
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        futures = []
                        for domain in normalized_domains:
                            # Check stop event before submitting
                            if active_jobs[job_id]['stop_event'].is_set():
                                logger.info(f"Job {job_id}: Stop event detected, halting submission")
                                break
                                
                            future = executor.submit(
                                process_domain_verification,
                                job_id,
                                domain,
                                account_name,
                                dry_run,
                                skip_verified,
                                provider,
                                active_jobs[job_id]['stop_event']
                            )
                            futures.append(future)
                        
                        # Wait for all tasks to complete and check for exceptions
                        for future in futures:
                            try:
                                future.result()
                            except Exception as exc:
                                logger.error(f"Job {job_id}: Thread generated an exception: {exc}")
                        
                    # Update final status
                    with job_lock:
                        if job_id in active_jobs:
                            if active_jobs[job_id]['stop_event'].is_set():
                                active_jobs[job_id]['status'] = 'stopped'
                                logger.info(f"Job {job_id}: Marked as stopped")
                            else:
                                active_jobs[job_id]['status'] = 'completed'
                                logger.info(f"Job {job_id}: Marked as completed")
                                
                except Exception as e:
                    logger.error(f"Job {job_id}: Error in batch processing: {e}", exc_info=True)
                    with job_lock:
                        if job_id in active_jobs:
                            active_jobs[job_id]['status'] = 'failed'

        # Start the batch thread
        batch_thread = threading.Thread(target=run_batch)
        batch_thread.daemon = True
        batch_thread.start()
        
        logger.info(f"Started domain verification job {job_id} for {len(normalized_domains)} domains (Provider: {provider})")
        
        return jsonify({
            'success': True,
            'job_id': job_id,
            'accepted': len(normalized_domains)
        })
    
    except Exception as e:
        logger.error(f"Error starting domain verification: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@dns_manager.route('/api/domains/stop', methods=['POST'])
@login_required
def stop_domain_verification():
    """
    Stop a running domain verification job.
    """
    try:
        data = request.get_json()
        job_id = data.get('job_id')
        
        count = 0
        with job_lock:
            if job_id:
                # Stop specific job
                if job_id in active_jobs and active_jobs[job_id]['status'] == 'running':
                    if 'stop_event' in active_jobs[job_id]:
                        active_jobs[job_id]['stop_event'].set()
                    active_jobs[job_id]['status'] = 'stopped'
                    count = 1
            else:
                # Stop ALL running jobs
                for jid, job in active_jobs.items():
                    if job.get('status') == 'running':
                        if 'stop_event' in job:
                            job['stop_event'].set()
                        job['status'] = 'stopped'
                        count += 1
        
        return jsonify({'success': True, 'stopped_count': count})
    except Exception as e:
        logger.error(f"Error stopping domain verification: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@dns_manager.route('/api/namecheap-domains', methods=['GET'])
@login_required
def get_namecheap_domains():
    """
    Get list of domains from Namecheap account.
    
    Returns:
        {
            "success": bool,
            "domains": [{"name": "...", "expire_date": "..."}, ...],
            "error": "..." (if failed),
            "debug_info": "..." (if available)
        }
    """
    try:
        logger.info("API: Fetching Namecheap domains...")
        dns_service = NamecheapDNSService()
        domains = dns_service.get_domains_list()
        
        logger.info(f"API: Successfully retrieved {len(domains)} domains")
        return jsonify({
            'success': True,
            'domains': domains,
            'total': len(domains)
        })
    
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error fetching Namecheap domains: {error_msg}", exc_info=True)
        
        # Provide more detailed error information
        debug_info = None
        troubleshooting = []
        
        if "configuration not found" in error_msg.lower():
            debug_info = "Namecheap credentials not configured. Please save configuration in Settings first."
            troubleshooting.append("1. Fill in all Namecheap API credentials in Settings")
            troubleshooting.append("2. Click 'Save Namecheap Configuration'")
        elif "client ip" in error_msg.lower() or "whitelist" in error_msg.lower():
            debug_info = "Client IP may not be whitelisted in Namecheap account settings."
            troubleshooting.append("1. Log in to your Namecheap account")
            troubleshooting.append("2. Go to Profile > Tools > API Access")
            troubleshooting.append("3. Add your server's IP address to the whitelist")
        elif "api error" in error_msg.lower() or "invalid" in error_msg.lower():
            debug_info = "Check API credentials (API User, API Key, Username) and ensure they are correct."
            troubleshooting.append("1. Verify API User matches your Namecheap API username")
            troubleshooting.append("2. Verify API Key is correct")
            troubleshooting.append("3. Verify Username is correct")
        
        return jsonify({
            'success': False,
            'error': error_msg,
            'debug_info': debug_info,
            'troubleshooting': troubleshooting
        }), 500

@dns_manager.route('/api/domains/status', methods=['GET'])
@login_required
def get_domain_verification_status():
    """
    Get status of domain verification job.
    
    Query params:
        job_id: Job UUID
    """
    job_id = request.args.get('job_id')
    if not job_id:
        return jsonify({'success': False, 'error': 'No job_id provided'}), 400
    
    try:
        # Query operations by job_id
        # We use job_id column which is indexed
        operations = DomainOperation.query.filter_by(job_id=job_id).order_by(DomainOperation.updated_at.desc()).all()
        
        if not operations:
            # Fallback to active_jobs check just in case DB write hasn't happened yet
            with job_lock:
                if job_id in active_jobs:
                     return jsonify({'success': True, 'status': active_jobs[job_id]['status'], 'results': []})
            
            return jsonify({'success': False, 'error': 'Job not found'}), 404
            
        # Determine overall status
        # If any operation is pending, job is running
        is_running = any(op.verify_status == 'pending' or op.workspace_status == 'pending' or op.dns_status == 'pending' for op in operations)
        status = 'running' if is_running else 'completed'
        
        results = []
        for op in operations:
            results.append({
                'domain': op.input_domain, # Use input_domain as per model
                'workspace': op.workspace_status,
                'dns': op.dns_status,
                'verify': op.verify_status,
                'message': op.message,
                'updated_at': op.updated_at.isoformat() if op.updated_at else None
            })
            
        return jsonify({
            'success': True,
            'status': status,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error fetching job status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@dns_manager.route('/api/cloudflare-domains', methods=['GET'])
@login_required
def get_cloudflare_domains():
    """
    Get list of domains (zones) from Cloudflare account.
    """
    try:
        logger.info("API: Fetching Cloudflare domains...")
        dns_service = CloudflareDNSService()
        zones = dns_service.get_zones()
        
        # Format for frontend
        domains = []
        for zone in zones:
            domains.append({
                'name': zone['name'],
                'id': zone['id'],
                'status': zone['status'],
                'expire_date': 'N/A' # Cloudflare doesn't provide expiry in basic zone info
            })
            
        logger.info(f"API: Successfully retrieved {len(domains)} Cloudflare domains")
        return jsonify({
            'success': True,
            'domains': domains,
            'total': len(domains)
        })
    
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error fetching Cloudflare domains: {error_msg}", exc_info=True)
        return jsonify({
            'success': False,
            'error': error_msg
        }), 500

