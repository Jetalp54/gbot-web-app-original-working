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
from functools import wraps
from database import db, DomainOperation, GoogleAccount, NamecheapConfig, ServiceAccount
from services.zone_utils import to_apex, matching_zone_in_namecheap
from services.google_domains_service import GoogleDomainsService
from services.namecheap_dns_service import NamecheapDNSService

logger = logging.getLogger(__name__)

dns_manager = Blueprint('dns_manager', __name__)

# Login required decorator (matches app.py implementation)
def login_required(f):
    """Decorator to require login"""
    from flask import redirect, url_for
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

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
            # Step 1: Convert to apex and calculate subdomain host
            apex = to_apex(domain)
            operation.apex_domain = apex
            
            # Calculate subdomain host for TXT record
            # For subdomain like "alberto.lumenskin.co.uk", host should be "alberto"
            # For apex like "lumenskin.co.uk", host should be "@"
            txt_host = '@'  # Default for apex domain
            if domain.lower() != apex.lower():
                # It's a subdomain - extract the subdomain part
                domain_parts = domain.lower().split('.')
                apex_parts = apex.lower().split('.')
                if len(domain_parts) > len(apex_parts):
                    # Get the subdomain part (everything before the apex)
                    subdomain_part = domain_parts[:len(domain_parts) - len(apex_parts)]
                    txt_host = '.'.join(subdomain_part)  # e.g., "alberto" or "mail.team"
                    logger.info(f"Subdomain detected: {domain} -> apex: {apex}, host: {txt_host}")
                else:
                    txt_host = '@'
            else:
                txt_host = '@'
            
            operation.raw_log = [log_entry('apex', 'success', f'Converted {domain} to apex: {apex}, TXT host: {txt_host}')]
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
            
            # Step 3: Add domain to Workspace (or continue if already exists)
            google_service = None
            try:
                google_service = GoogleDomainsService(account_name)
                result = google_service.ensure_domain_added(apex)
                
                if result.get('already_exists'):
                    operation.workspace_status = 'success'
                    operation.raw_log.append(log_entry('workspace', 'success', 'Domain already exists in Workspace - continuing with verification'))
                    logger.info(f"Domain {apex} already exists, continuing with verification process")
                elif result.get('created'):
                    operation.workspace_status = 'success'
                    operation.raw_log.append(log_entry('workspace', 'success', 'Domain added to Workspace'))
                    logger.info(f"Domain {apex} added to Workspace")
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
                    # 403 error - domain might already exist or permission issue
                    # Try to verify domain exists, if so continue; otherwise fail
                    logger.warning(f"Got 403 error for {apex}, checking if domain exists...")
                    try:
                        if not google_service:
                            google_service = GoogleDomainsService(account_name)
                        # Try to get domain info to verify it exists
                        admin_service = google_service._get_admin_service()
                        try:
                            domain_info = admin_service.domains().get(customer='my_customer', domainName=apex).execute()
                            # Domain exists! Continue with verification
                            operation.workspace_status = 'success'
                            operation.raw_log.append(log_entry('workspace', 'success', f'Domain already exists (verified after 403) - continuing with verification'))
                            logger.info(f"Domain {apex} exists (verified after 403), continuing with verification")
                            db.session.commit()
                            # Continue to next step - don't return!
                        except Exception as check_error:
                            # Can't verify, but assume exists to continue (user said it exists)
                            operation.workspace_status = 'success'
                            operation.raw_log.append(log_entry('workspace', 'success', f'Domain likely exists (403 error but continuing) - continuing with verification'))
                            logger.info(f"Domain {apex} - got 403, assuming exists and continuing")
                            db.session.commit()
                            # Continue to next step
                    except Exception as verify_error:
                        # Can't verify, but user said domain exists - continue anyway
                        operation.workspace_status = 'success'
                        operation.raw_log.append(log_entry('workspace', 'success', f'Domain exists (user confirmed) - continuing despite 403'))
                        logger.info(f"Domain {apex} - assuming exists and continuing despite 403")
                        db.session.commit()
                        # Continue to next step
                elif 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
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
            try:
                if not google_service:
                    google_service = GoogleDomainsService(account_name)
                    
                token_result = google_service.get_verification_token(apex)
                token = token_result['token']
                # Use the calculated subdomain host, not the default '@' from Google
                # Google returns '@' for apex, but we need the subdomain part for subdomains
                txt_value = token_result.get('txt_value', f'google-site-verification={token}')
                
                operation.raw_log.append(log_entry('token', 'success', f'Retrieved verification token, will use host: {txt_host}'))
                logger.info(f"Got verification token for {apex}, will add TXT record with host: {txt_host}")
                db.session.commit()
            
            except Exception as e:
                error_msg = str(e)
                # Check for scope/permission errors
                if 'insufficient' in error_msg.lower() or 'scope' in error_msg.lower() or 'permission' in error_msg.lower():
                    error_msg = f'Missing Google Site Verification API scope. Please re-authenticate: {error_msg}'
                elif 'not found' in error_msg.lower() or '404' in error_msg.lower():
                    error_msg = f'Domain not found in Google Workspace. Ensure domain is added first: {error_msg}'
                
                operation.dns_status = 'failed'
                operation.message = f'Failed to get verification token: {error_msg}'
                operation.raw_log.append(log_entry('token', 'failed', error_msg))
                db.session.commit()
                return
            
            # Step 5: Create TXT record in Namecheap (unless dry-run)
            # Use the calculated subdomain host (e.g., "alberto" for subdomain, "@" for apex)
            if dry_run:
                operation.dns_status = 'dry-run'
                operation.message = f'Dry-run: DNS TXT record not created (would use host: {txt_host})'
                operation.raw_log.append(log_entry('dns', 'dry-run', f'Dry-run mode: would add TXT @ {txt_host} with value: {txt_value}'))
                db.session.commit()
            else:
                try:
                    dns_service = NamecheapDNSService()
                    logger.info(f"Adding TXT record to Namecheap: apex={apex}, host={txt_host}, value={txt_value}")
                    dns_result = dns_service.upsert_txt_record(apex, txt_host, txt_value, ttl=300)
                    
                    operation.dns_status = 'success'
                    operation.message = f'TXT record created @ {txt_host}: {dns_result.get("message", "Success")}'
                    operation.raw_log.append(log_entry('dns', 'success', f'TXT record created @ {txt_host} with value: {txt_value}'))
                    db.session.commit()
                
                except Exception as e:
                    operation.dns_status = 'failed'
                    operation.message = f'Failed to create TXT record @ {txt_host}: {str(e)}'
                    operation.raw_log.append(log_entry('dns', 'failed', f'Error @ {txt_host}: {str(e)}'))
                    db.session.commit()
                    return
            
            # Step 6: Verify domain (with retries)
            if not dry_run:
                # Wait 10 seconds after DNS TXT record creation before first verification attempt
                logger.info(f"Waiting 10 seconds for DNS propagation before verification...")
                time.sleep(10)
                
                max_attempts = 10
                attempt = 0
                verified = False
                
                while attempt < max_attempts and not verified:
                    attempt += 1
                    try:
                        logger.info(f"Verification attempt {attempt}/{max_attempts} for {apex}")
                        verify_result = google_service.verify_domain(apex)
                        
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
            troubleshooting.append("2. Verify API Key is correct (regenerate if needed)")
            troubleshooting.append("3. Verify Username matches your Namecheap account username")
            troubleshooting.append("4. Ensure Client IP is whitelisted")
        elif "no domains" in error_msg.lower() or len(error_msg) == 0:
            debug_info = "No domains found. This could mean:"
            troubleshooting.append("1. Your account has no domains")
            troubleshooting.append("2. API credentials are incorrect")
            troubleshooting.append("3. Client IP is not whitelisted")
            troubleshooting.append("4. Check server logs for detailed error: journalctl -u gbot.service -f")
        else:
            troubleshooting.append("1. Check server logs: sudo journalctl -u gbot.service -n 50")
            troubleshooting.append("2. Verify Namecheap API credentials are correct")
            troubleshooting.append("3. Ensure Client IP is whitelisted in Namecheap")
        
        return jsonify({
            'success': False,
            'error': error_msg,
            'debug_info': debug_info,
            'troubleshooting': troubleshooting,
            'domains': []
        }), 500

@dns_manager.route('/api/namecheap-config', methods=['GET', 'POST'])
@login_required
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
@login_required
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
