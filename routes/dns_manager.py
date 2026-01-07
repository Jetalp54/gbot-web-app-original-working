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

            # [USER-FIX] STRICT PARSING Logic
            # Rule: "the alias is the word before the first . and the rest is the domain"
            # This applies for any domain with 3 or more parts (e.g. sub.example.com -> sub + example.com)
            # For 2 parts (example.com), we use standard behavior (@ + example.com)
            domain_parts = domain.lower().split('.')
            
            logger.info(f"PARSING DOMAIN: {domain}, parts: {len(domain_parts)}")
            
            if len(domain_parts) >= 3:
                # STRICT USER RULE: First part is host, rest is ZONE.
                # e.g. anjins.learnatory.info -> Host: anjins, Zone: learnatory.info
                # e.g. angel.mentorcrafter.it.com -> Host: angel, Zone: mentorcrafter.it.com
                
                txt_host = domain_parts[0]
                apex = '.'.join(domain_parts[1:])
                logger.info(f" [STRICT MODE] Custom split -> Host: {txt_host}, Zone: {apex}")
            else:
                # Fallback for standard domains (e.g. example.com)
                apex = to_apex(domain)
                logger.info(f" [STD MODE] standard apex: {apex}")
                
                txt_host = '@'
                if domain.lower() != apex.lower():
                    # This path might not be reached if to_apex works well for 2-part domains
                     # But keeping logical fallback just in case
                    apex_parts = apex.lower().split('.')
                    if len(domain_parts) > len(apex_parts):
                        subdomain_part = domain_parts[:len(domain_parts) - len(apex_parts)]
                        txt_host = '.'.join(subdomain_part)
            
            logger.info(f"Processing domain: {domain} -> Apex: {apex} (Provider: {provider})")
            
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
                    db.session.rollback()
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
                db.session.rollback()
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
                
                # Get verification token for the SUBDOMAIN (full domain being added)
                # The TXT record will go at txt_host (subdomain prefix) in the apex zone
                # Verification will be for the full subdomain
                logger.info(f"Job {job_id}: Step 4 - Getting verification token for SUBDOMAIN: {domain}")
                logger.info(f"Job {job_id}: TXT will be placed at host '{txt_host}' in zone '{apex}'")
                if not google_service:
                    google_service = GoogleDomainsService(account_name)
                
                # Get token for the SUBDOMAIN - this is what we're adding and verifying
                token_result = google_service.get_verification_token(domain)
                token = token_result['token']
                txt_value = token_result.get('txt_value', f'google-site-verification={token}')
                token_delegation_mode = token_result.get('without_delegation')  # Track which credential mode was used
                
                # Fix for double prefix issue
                if txt_value.startswith('google-site-verification=google-site-verification='):
                    logger.warning(f"Detected double prefix in TXT value: {txt_value}. Fixing...")
                    txt_value = txt_value.replace('google-site-verification=', '', 1)
                
                # NOTE: txt_host was calculated earlier (lines 103-115) based on the domain structure
                # For subdomain verification, we keep that value (e.g., 'almertnas' for almertnas.brainshifthub.it.com)
                
                operation.message = f'Token received, creating DNS TXT record...'
                operation.raw_log.append(log_entry('token', 'success', f'Retrieved verification token for {domain}, will use host: {txt_host}'))
                logger.info(f"Got verification token for {domain}, TXT host: {txt_host} in zone: {apex}")
                db.session.commit()
            
            except Exception as e:
                db.session.rollback()
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
                    db.session.rollback()
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
                # EXPLICIT LOG: Verification is starting
                logger.info(f"=== STEP 6 START === Job {job_id}: Domain {domain} - Starting verification process")
                logger.info(f"Job {job_id}: Current operation status - workspace: {operation.workspace_status}, dns: {operation.dns_status}")
                
                # Wait 30 seconds (User recommended 30s-120s) after DNS TXT record creation before first verification attempt
                logger.info(f"Waiting 30 seconds for DNS propagation before verification...")
                time.sleep(30)
                
                max_attempts = 10
                attempt = 0
                verified = False
                
                logger.info(f"Job {job_id}: Starting verification loop - max {max_attempts} attempts for {domain}")
                
                while attempt < max_attempts and not verified:
                    if stop_event and stop_event.is_set():
                        operation.message = 'Stopped by user'
                        operation.raw_log.append(log_entry('stop', 'stopped', 'Process stopped by user'))
                        db.session.commit()
                        logger.warning(f"Job {job_id}: Verification stopped by user event")
                        return

                    attempt += 1
                    
                    # Update status to show progress
                    if attempt > 1:
                        operation.message = f'Verifying domain... (Attempt {attempt}/{max_attempts})'
                        db.session.commit()
                    
                    try:
                        logger.info(f"=== VERIFICATION ATTEMPT {attempt}/{max_attempts} === Domain: {domain}, Apex: {apex}, delegation_mode={token_delegation_mode}")
                        verify_result = google_service.verify_domain(domain, apex_domain=apex, without_delegation=token_delegation_mode)
                        
                        logger.info(f"Job {job_id}: Verification result for {domain}: {verify_result}")
                        
                        if verify_result.get('verified'):
                            verified = True
                            operation.verify_status = 'success'
                            operation.message = 'Domain verified successfully'
                            operation.raw_log.append(log_entry('verify', 'success', f'Verified on attempt {attempt}'))
                            db.session.commit()  # Commit success immediately
                            logger.info(f"=== VERIFICATION SUCCESS === Domain {apex} verified on attempt {attempt}")
                        else:
                            # Use logic to show more detailed status
                            status_msg = verify_result.get('error', f'Attempt {attempt}/{max_attempts}: Not yet verified')
                            if verify_result.get('status') == 'pending':
                                # This means Site Verification passed, but Workspace sync is pending
                                status_msg = f"Attempt {attempt}: Site Verification OK, waiting for Workspace sync..."
                            
                            operation.message = status_msg
                            operation.raw_log.append(log_entry('verify', 'pending', status_msg))
                            db.session.commit()  # Commit log update immediately
                            
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
                        db.session.commit()  # Commit error log
                        
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
            db.session.rollback()
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

@dns_manager.route('/api/domains/verify-unverified', methods=['POST'])
@login_required
def verify_unverified_domains():
    """
    Verify all domains that are not yet verified in Google Workspace.
    This endpoint:
    1. Fetches all domains from Admin SDK
    2. Filters to only unverified domains
    3. Triggers verification for each in parallel
    """
    try:
        data = request.get_json() or {}
        
        # Get current account name from session
        account_name = session.get('current_account_name')
        if not account_name:
            return jsonify({'success': False, 'error': 'No authenticated account'}), 401
        
        logger.info(f"=== VERIFY UNVERIFIED DOMAINS === Account: {account_name}")
        
        # Verify account exists (Check Service Account first)
        service_account = ServiceAccount.query.filter_by(name=account_name).first()
        if not service_account:
            account = GoogleAccount.query.filter_by(account_name=account_name).first()
            if not account:
                return jsonify({'success': False, 'error': 'Account not found'}), 404
        
        # Initialize Google Domains Service
        google_service = GoogleDomainsService(account_name=account_name)
        
        # Get all domains from Admin SDK
        try:
            admin_service = google_service._get_admin_service()
            response = admin_service.domains().list(customer='my_customer').execute()
            all_domains = response.get('domains', [])
            logger.info(f"Found {len(all_domains)} total domains in Workspace")
        except Exception as e:
            logger.error(f"Error fetching domains from Admin SDK: {e}")
            return jsonify({'success': False, 'error': f'Error fetching domains: {str(e)}'}), 500
        
        # Filter to unverified domains only
        unverified_domains = []
        for domain in all_domains:
            domain_name = domain.get('domainName', '')
            is_verified = domain.get('verified', False)
            logger.info(f"Domain: {domain_name} - Verified: {is_verified}")
            if not is_verified and domain_name:
                unverified_domains.append(domain_name)
        
        if not unverified_domains:
            logger.info("No unverified domains found")
            return jsonify({
                'success': True,
                'message': 'All domains are already verified!',
                'total_domains': 0,
                'domains': []
            })
        
        logger.info(f"Found {len(unverified_domains)} unverified domains: {unverified_domains}")
        
        # Create job for verification
        job_id = str(uuid.uuid4())
        
        with job_lock:
            active_jobs[job_id] = {
                'status': 'running',
                'total': len(unverified_domains),
                'started_at': datetime.now().isoformat(),
                'stop_event': threading.Event()
            }
        
        # Start background processing for verification
        def verify_domains_batch():
            from app import app
            with app.app_context():
                max_workers = min(5, len(unverified_domains))
                logger.info(f"Job {job_id}: Starting parallel verification with {max_workers} workers")
                
                try:
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        futures = []
                        for domain in unverified_domains:
                            if active_jobs[job_id]['stop_event'].is_set():
                                logger.info(f"Job {job_id}: Stop requested during submission")
                                break
                            
                            # Create operation record
                            operation = DomainVerificationOperation(
                                job_id=job_id,
                                domain=domain,
                                apex_domain=domain,  # These are apex domains from Admin SDK
                                account_name=account_name,
                                workspace_status='skipped',  # Domain already added
                                dns_status='skipped',  # TXT record already exists
                                verify_status='pending',
                                message='Starting verification...',
                                raw_log=[]
                            )
                            db.session.add(operation)
                            db.session.commit()
                            
                            # Submit verification task
                            future = executor.submit(
                                verify_single_domain,
                                job_id,
                                domain,
                                account_name,
                                active_jobs[job_id]['stop_event']
                            )
                            futures.append((domain, future))
                        
                        # Wait for all futures to complete
                        for domain, future in futures:
                            try:
                                result = future.result(timeout=300)  # 5 min timeout per domain
                                logger.info(f"Job {job_id}: Verification result for {domain}: {result}")
                            except Exception as exc:
                                logger.error(f"Job {job_id}: Verification error for {domain}: {exc}")
                        
                        # Update final status
                        with job_lock:
                            if job_id in active_jobs:
                                if active_jobs[job_id]['stop_event'].is_set():
                                    active_jobs[job_id]['status'] = 'stopped'
                                else:
                                    active_jobs[job_id]['status'] = 'completed'
                                    
                except Exception as e:
                    logger.error(f"Job {job_id}: Error in verification batch: {e}", exc_info=True)
                    with job_lock:
                        if job_id in active_jobs:
                            active_jobs[job_id]['status'] = 'failed'
        
        # Start the batch thread
        batch_thread = threading.Thread(target=verify_domains_batch)
        batch_thread.daemon = True
        batch_thread.start()
        
        logger.info(f"Started verification job {job_id} for {len(unverified_domains)} domains")
        
        return jsonify({
            'success': True,
            'job_id': job_id,
            'total_domains': len(unverified_domains),
            'domains': unverified_domains,
            'message': f'Started verification for {len(unverified_domains)} unverified domains'
        })
        
    except Exception as e:
        logger.error(f"Error in verify-unverified endpoint: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


def verify_single_domain(job_id: str, domain: str, account_name: str, stop_event):
    """
    Verify a single domain - called from the parallel executor.
    """
    from app import app
    with app.app_context():
        try:
            # Get the operation record
            operation = DomainVerificationOperation.query.filter_by(
                job_id=job_id, domain=domain
            ).first()
            
            if not operation:
                logger.error(f"Operation not found for {domain}")
                return {'success': False, 'error': 'Operation not found'}
            
            if stop_event.is_set():
                operation.verify_status = 'stopped'
                operation.message = 'Stopped by user'
                db.session.commit()
                return {'success': False, 'error': 'Stopped by user'}
            
            logger.info(f"=== VERIFYING DOMAIN {domain} ===")
            operation.message = 'Calling verification API...'
            db.session.commit()
            
            # Initialize Google service and verify
            google_service = GoogleDomainsService(account_name=account_name)
            verify_result = google_service.verify_domain(domain)
            
            logger.info(f"Verification result for {domain}: {verify_result}")
            
            if verify_result.get('verified'):
                operation.verify_status = 'success'
                operation.message = 'Domain verified successfully!'
                logger.info(f"✅ Domain {domain} verified successfully!")
            else:
                error_msg = verify_result.get('error', 'Verification pending')
                operation.verify_status = 'failed'
                operation.message = error_msg
                logger.warning(f"❌ Domain {domain} verification failed: {error_msg}")
            
            db.session.commit()
            return verify_result
            
        except Exception as e:
            logger.error(f"Error verifying {domain}: {e}", exc_info=True)
            if operation:
                operation.verify_status = 'failed'
                operation.message = str(e)
                db.session.commit()
            return {'success': False, 'error': str(e)}

# ===== BULK MULTI-ACCOUNT DOMAIN VERIFICATION =====
bulk_multi_jobs = {}
bulk_multi_lock = threading.Lock()

@dns_manager.route('/api/domains/bulk-multi-account/start', methods=['POST'])
@login_required
def start_bulk_multi_account():
    """
    Start bulk multi-account domain verification.
    Each entry has: domain, adminEmail, accountDomain, password
    """
    try:
        data = request.get_json()
        entries = data.get('entries', [])
        provider = data.get('provider', 'namecheap')
        
        if not entries:
            return jsonify({'success': False, 'error': 'No entries provided'}), 400
        
        job_id = str(uuid.uuid4())
        logger.info(f"=== BULK MULTI-ACCOUNT START === Job: {job_id}, Entries: {len(entries)}, Provider: {provider}")
        
        # Initialize job state
        with bulk_multi_lock:
            bulk_multi_jobs[job_id] = {
                'status': 'running',
                'stop_event': threading.Event(),
                'entries': [],
                'started_at': datetime.now().isoformat()
            }
            
            # Initialize entry statuses
            for entry in entries:
                bulk_multi_jobs[job_id]['entries'].append({
                    'index': entry.get('index'),
                    'domain': entry.get('domain'),
                    'adminEmail': entry.get('adminEmail'),
                    'accountDomain': entry.get('accountDomain'),
                    'authStatus': 'pending',
                    'workspaceStatus': 'pending',
                    'dnsStatus': 'pending',
                    'verifyStatus': 'pending',
                    'message': 'Queued'
                })
        
        # Start background processing with PARALLEL execution
        def process_bulk_multi():
            from app import app
            from concurrent.futures import ThreadPoolExecutor
            
            def process_single_entry(entry_data):
                """Process a single entry - calls existing process_domain_verification"""
                entry_idx, entry, job, provider_name = entry_data
                
                with app.app_context():
                    if job['stop_event'].is_set():
                        entry['message'] = 'Stopped'
                        return
                    
                    try:
                        domain = entry['domain']
                        admin_email = entry['adminEmail']
                        account_domain = entry['accountDomain']
                        
                        logger.info(f"Job {job_id}: Processing entry {entry['index']}: {domain} -> {admin_email}")
                        
                        # Step 1: Find account by NAME (same lookup as single-account feature)
                        entry['authStatus'] = 'running'
                        entry['message'] = 'Finding account...'
                        
                        # Try exact NAME match first (main lookup method)
                        service_account = ServiceAccount.query.filter_by(name=admin_email).first()
                        lookup_method = 'name' if service_account else None
                        
                        # Try by admin_email
                        if not service_account:
                            service_account = ServiceAccount.query.filter_by(admin_email=admin_email).first()
                            lookup_method = 'admin_email' if service_account else None
                        
                        # Try by account domain name
                        if not service_account and account_domain:
                            service_account = ServiceAccount.query.filter_by(name=account_domain).first()
                            lookup_method = 'domain_name' if service_account else None
                        
                        # Fallback: partial match
                        if not service_account:
                            all_accounts = ServiceAccount.query.all()
                            for acc in all_accounts:
                                if account_domain in (acc.name or '') or account_domain in (acc.admin_email or ''):
                                    service_account = acc
                                    lookup_method = 'partial_match'
                                    break
                        
                        if not service_account:
                            entry['authStatus'] = 'failed'
                            entry['message'] = f'Account not found for {admin_email}'
                            logger.warning(f"Job {job_id}: Account not found for {admin_email}")
                            return
                        
                        account_name = service_account.name
                        logger.info(f"Job {job_id}: Found account '{account_name}' via {lookup_method}")
                        
                        entry['authStatus'] = 'success'
                        entry['message'] = f'Using: {account_name}'
                        
                        # Step 2: CALL THE EXISTING WORKING FUNCTION
                        # This is the key - use the same function as single-account feature!
                        entry['workspaceStatus'] = 'running'
                        entry['message'] = 'Adding to Workspace...'
                        
                        # Call existing process_domain_verification directly
                        # Use a proper UUID for the entry job (database column is 36 chars max)
                        import uuid as uuid_module
                        entry_job_id = str(uuid_module.uuid4())
                        # CRITICAL: Save operation ID to entry so status endpoint can look it up
                        entry['operation_id'] = entry_job_id
                        
                        try:
                            # Call the working function
                            process_domain_verification(
                                job_id=entry_job_id,
                                domain=domain,
                                account_name=account_name,  # Same account_name session.get() would give
                                dry_run=False,
                                skip_verified=False,
                                provider=provider_name,
                                stop_event=job['stop_event']
                            )
                            
                            # Check the operation result from database
                            from database import DomainOperation
                            # Force a fresh query to ensure we get the latest status
                            db.session.expire_all()
                            operation = DomainOperation.query.filter_by(job_id=entry_job_id).first()
                            
                            if operation:
                                # Copy results to entry status
                                entry['workspaceStatus'] = operation.workspace_status or 'failed'
                                entry['dnsStatus'] = operation.dns_status or 'pending'
                                entry['verifyStatus'] = operation.verify_status or 'pending'
                                entry['message'] = operation.message or 'Completed'
                                logger.info(f"Job {job_id} Entry {entry['index']}: "
                                           f"Workspace={operation.workspace_status}, "
                                           f"DNS={operation.dns_status}, "
                                           f"Verify={operation.verify_status}")
                            else:
                                logger.warning(f"Job {job_id} Entry {entry['index']}: Operation record not found for {entry_job_id}")
                                entry['message'] = 'Processing failed (no operation record)'
                                entry['workspaceStatus'] = 'failed'
                                entry['dnsStatus'] = 'failed'
                                entry['verifyStatus'] = 'failed'

                        except Exception as inner_e:
                            logger.error(f"Job {job_id}: Core function error for entry {entry.get('index')}: {inner_e}", exc_info=True)
                            entry['message'] = f'Error: {str(inner_e)[:100]}'
                            entry['workspaceStatus'] = 'failed'
                            entry['dnsStatus'] = 'failed'
                            
                    except Exception as e:
                        logger.error(f"Job {job_id}: Error processing entry {entry.get('index')}: {e}", exc_info=True)
                        entry['message'] = f'Error: {str(e)[:100]}'
                        entry['workspaceStatus'] = 'failed'
            
            # Main thread function
            with app.app_context():
                job = bulk_multi_jobs[job_id]
                entries = job['entries']
                
                # Process entries in PARALLEL (max 5 concurrent)
                max_workers = min(5, len(entries))
                logger.info(f"Job {job_id}: Starting parallel processing with {max_workers} workers")
                
                try:
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        # Prepare entry data for parallel processing
                        entry_data_list = [
                            (i, entry, job, provider) 
                            for i, entry in enumerate(entries)
                        ]
                        
                        # Submit all tasks
                        futures = [executor.submit(process_single_entry, data) for data in entry_data_list]
                        
                        # Wait for all to complete
                        for future in futures:
                            try:
                                future.result(timeout=600)  # 10 min per entry max
                            except Exception as e:
                                logger.error(f"Job {job_id}: Thread error: {e}")
                                
                except Exception as e:
                    logger.error(f"Job {job_id}: Executor error: {e}", exc_info=True)
                
                # Mark job complete
                if job['stop_event'].is_set():
                    job['status'] = 'stopped'
                else:
                    job['status'] = 'completed'
                logger.info(f"Job {job_id}: Finished with status {job['status']}")
        
        # Start the thread
        thread = threading.Thread(target=process_bulk_multi)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'job_id': job_id,
            'message': f'Started processing {len(entries)} entries'
        })
        
    except Exception as e:
        logger.error(f"Error starting bulk multi-account: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@dns_manager.route('/api/domains/bulk-multi-account/stop', methods=['POST'])
@login_required
def stop_bulk_multi_account():
    """Stop a bulk multi-account job."""
    try:
        data = request.get_json()
        job_id = data.get('job_id')
        
        with bulk_multi_lock:
            if job_id and job_id in bulk_multi_jobs:
                bulk_multi_jobs[job_id]['stop_event'].set()
                bulk_multi_jobs[job_id]['status'] = 'stopped'
                return jsonify({'success': True})
        
        return jsonify({'success': False, 'error': 'Job not found'})
        
    except Exception as e:
        logger.error(f"Error stopping bulk multi-account: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@dns_manager.route('/api/domains/bulk-multi-account/status/<job_id>', methods=['GET'])
@login_required
def get_bulk_multi_account_status(job_id):
    """Get status of a bulk multi-account job."""
    try:
        with bulk_multi_lock:
            if job_id not in bulk_multi_jobs:
                return jsonify({'success': False, 'error': 'Job not found'}), 404
            
            job = bulk_multi_jobs[job_id]
            
            # Hybrid status: Merge memory state with DB state for active operations
            # This ensures we see granular progress updates (e.g. 'Creating DNS TXT')
            # instead of being stuck on 'Adding to Workspace' until the whole thing finishes.
            from database import DomainOperation
            from app import db # Ensure db is available
            
            final_entries = []
            loop_success = False
            
            # We must use an app context to query DB
            from app import app
            try:
                with app.app_context():
                    try:
                        # Refresh DB session to get latest data
                        db.session.expire_all()
                        
                        for entry in job['entries']:
                            # Create a copy so we don't mutate memory state during read if not needed
                            e_copy = entry.copy()
                            
                            op_id = entry.get('operation_id')
                            if op_id:
                                 # Check DB for live status
                                try:
                                    op = DomainOperation.query.filter_by(job_id=op_id).first()
                                    if op:
                                        # Overlay DB status onto entry
                                        e_copy['workspaceStatus'] = op.workspace_status or e_copy['workspaceStatus']
                                        e_copy['dnsStatus'] = op.dns_status or e_copy['dnsStatus']
                                        e_copy['verifyStatus'] = op.verify_status or e_copy['verifyStatus']
                                        e_copy['message'] = op.message or e_copy['message']
                                except Exception as db_err:
                                    # If DB access fails (lock, etc), just use memory state
                                    logger.warning(f"Status poll DB error for op {op_id}: {db_err}")
                            
                            final_entries.append(e_copy)
                        
                        loop_success = True
                            
                    except Exception as loop_err:
                         logger.error(f"Error in status loop (inner): {loop_err}", exc_info=True)
                         # Continue to fallback
                         
            except Exception as context_err:
                logger.error(f"Error creating app context or outer loop: {context_err}", exc_info=True)

            # Fallback if loop failed
            if not loop_success or not final_entries:
                final_entries = job['entries']

            return jsonify({
                'success': True,
                'job_id': job_id,
                'status': job['status'],
                'entries': final_entries
            })
            
    except Exception as e:
        logger.error(f"Error getting bulk multi-account status (CRITICAL): {e}", exc_info=True)
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
    Supports both DomainOperation (add/verify) and DomainVerificationOperation (verify existing).
    """
    job_id = request.args.get('job_id')
    if not job_id:
        return jsonify({'success': False, 'error': 'No job_id provided'}), 400
    
    try:
        from database import DomainOperation, DomainVerificationOperation
        
        # 1. Try DomainOperation (standard add+verify flow)
        operations = DomainOperation.query.filter_by(job_id=job_id).order_by(DomainOperation.updated_at.desc()).all()
        
        # 2. If no operations found, try DomainVerificationOperation (verify-only flow)
        if not operations:
             operations = DomainVerificationOperation.query.filter_by(job_id=job_id).all()
        
        if not operations:
            # Fallback to active_jobs check just in case DB write hasn't happened yet
            with job_lock:
                if job_id in active_jobs:
                     return jsonify({'success': True, 'status': active_jobs[job_id]['status'], 'results': []})
            
            return jsonify({'success': False, 'error': 'Job not found'}), 404
            
        # Determine overall status
        # If any operation is pending, job is running
        is_running = any(op.verify_status == 'pending' or (hasattr(op, 'workspace_status') and op.workspace_status == 'pending') or (hasattr(op, 'dns_status') and op.dns_status == 'pending') for op in operations)
        status = 'running' if is_running else 'completed'
        
        results = []
        for op in operations:
            # Normalize fields (DomainVerificationOperation might differ slightly)
            domain_name = getattr(op, 'input_domain', getattr(op, 'domain', 'Unknown'))
            workspace_status = getattr(op, 'workspace_status', 'N/A')
            dns_status = getattr(op, 'dns_status', 'N/A')
            app_updated = getattr(op, 'updated_at', None)
            
            results.append({
                'domain': domain_name,
                'workspace': workspace_status,
                'dns': dns_status,
                'verify': op.verify_status,
                'message': op.message,
                'updated_at': app_updated.isoformat() if app_updated else None
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

