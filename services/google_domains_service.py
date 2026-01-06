"""
Google Workspace domain management service.
Handles domain addition, verification token retrieval, and domain verification.
"""
import logging
import time
import random
from typing import Dict, Optional
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import google.auth.transport.requests
from database import GoogleAccount, GoogleToken, ServiceAccount

logger = logging.getLogger(__name__)

class GoogleDomainsService:
    """Service for managing Google Workspace domains."""
    
    def __init__(self, account_name: str):
        """
        Initialize service with Google account credentials.
        
        Args:
            account_name: Name of the Google account to use
        """
        self.account_name = account_name
        self._admin_service = None
        self._site_verification_service = None
    
    def _get_credentials(self) -> Optional[Credentials]:
        """Get and refresh Google credentials."""
        try:
            # Try Service Account first
            service_account = ServiceAccount.query.filter_by(name=self.account_name).first()
            if service_account:
                logger.info(f"Auth path: ServiceAccount DWD for '{self.account_name}'")
                from services.google_service_account import GoogleServiceAccount
                gsa = GoogleServiceAccount(service_account.id)
                return gsa.get_credentials()

            # Fallback to Google Account (deprecated)
            account = GoogleAccount.query.filter_by(account_name=self.account_name).first()
            if account and account.tokens:
                logger.info(f"Auth path: GoogleAccount OAuth for '{self.account_name}'")
            if not account or not account.tokens:
                logger.error(f"No tokens found for account: {self.account_name}")
                return None
            
            token = account.tokens[0]
            scopes = [scope.name for scope in token.scopes]
            
            creds = Credentials(
                token=token.token,
                refresh_token=token.refresh_token,
                token_uri=token.token_uri,
                client_id=account.client_id,
                client_secret=account.client_secret,
                scopes=scopes
            )
            
            if creds.expired and creds.refresh_token:
                creds.refresh(google.auth.transport.requests.Request())
            
            return creds if creds.valid else None
        
        except Exception as e:
            logger.error(f"Error getting credentials for {self.account_name}: {e}")
            return None
    
    def _get_admin_service(self):
        """Get or create Admin SDK service."""
        if self._admin_service:
            return self._admin_service
        
        creds = self._get_credentials()
        if not creds:
            raise Exception("Failed to get valid credentials")
        
        self._admin_service = build('admin', 'directory_v1', credentials=creds)
        return self._admin_service
    
    def _get_site_verification_service(self, force_refresh=False, without_delegation=False):
        """Get or create Site Verification API service.
        
        Args:
            force_refresh: Force rebuild the service with new credentials
            without_delegation: If True, use service account without impersonating admin
        """
        cache_key = 'without_delegation' if without_delegation else 'with_delegation'
        
        if not force_refresh and hasattr(self, '_sv_cache') and cache_key in self._sv_cache:
            return self._sv_cache[cache_key]
        
        if force_refresh:
            logger.info(f"Force refreshing Site Verification service (without_delegation={without_delegation})")
        
        try:
            # Get credentials for Site Verification
            creds = self._get_credentials_for_site_verification(without_delegation)
            if not creds:
                raise Exception("Failed to get valid credentials for Site Verification API")
            
            service = build('siteVerification', 'v1', credentials=creds)
            
            # Cache the service
            if not hasattr(self, '_sv_cache'):
                self._sv_cache = {}
            self._sv_cache[cache_key] = service
            
            logger.info(f"Site Verification service built successfully (without_delegation={without_delegation})")
            return service
        except Exception as e:
            logger.error(f"Failed to build Site Verification service: {e}")
            raise
    
    def _get_credentials_for_site_verification(self, without_delegation=False):
        """Get credentials specifically for Site Verification API."""
        try:
            service_account_row = ServiceAccount.query.filter_by(name=self.account_name).first()
            if service_account_row:
                from services.google_service_account import GoogleServiceAccount
                import json
                from google.oauth2 import service_account as sa_lib
                
                gsa = GoogleServiceAccount(service_account_row.id)
                
                if without_delegation:
                    # Use service account credentials WITHOUT impersonating a user
                    # Some APIs work better with direct service account auth
                    logger.info("Using Site Verification credentials WITHOUT domain delegation")
                    creds = sa_lib.Credentials.from_service_account_info(
                        gsa.credentials_info,
                        scopes=['https://www.googleapis.com/auth/siteverification']
                    )
                    return creds
                else:
                    # Use standard delegated credentials (impersonate admin)
                    logger.info(f"Using Site Verification credentials WITH domain delegation to {gsa.admin_email}")
                    return gsa.get_credentials()
            
            # Fallback to standard credentials
            return self._get_credentials()
        except Exception as e:
            logger.error(f"Error getting Site Verification credentials: {e}")
            return None
    
    def ensure_domain_added(self, apex: str) -> Dict:
        """
        Add domain to Google Workspace if not already present.
        If domain already exists or we get permission errors, treat as success and continue.
        
        Args:
            apex: Apex domain to add
        
        Returns:
            Dict with 'created' (bool) and 'already_exists' (bool)
        """
        try:
            service = self._get_admin_service()
            
            # First, check if domain already exists by trying to get it
            try:
                domain_info = service.domains().get(customer='my_customer', domainName=apex).execute()
                logger.info(f"Domain {apex} already exists in Workspace (verified via get)")
                return {'created': False, 'already_exists': True}
            except HttpError as get_error:
                if get_error.resp.status == 404:
                    # Domain doesn't exist, continue to add it
                    logger.info(f"Domain {apex} not found, will attempt to add")
                elif get_error.resp.status == 403:
                    # Permission denied
                    # Try listing domains to check if it really exists
                    logger.warning(f"403 error getting domain {apex}, checking via list...")
                    try:
                        domains = service.domains().list(customer='my_customer').execute()
                        existing_domains = [d.get('domainName', '') for d in domains.get('domains', [])]
                        if apex in existing_domains:
                            logger.info(f"Domain {apex} found in domain list - already exists")
                            return {'created': False, 'already_exists': True}
                        else:
                            # Domain doesn't exist and we got 403. 
                            # DO NOT assume success. This is a hard failure.
                            error_msg = f"Permission denied (403) accessing Google Workspace. Domain {apex} not found in account."
                            logger.error(error_msg)
                            raise Exception(error_msg)
                    except Exception as list_error:
                        # If we can't even list domains, we definitely don't have access
                        logger.error(f"Error listing domains: {list_error}")
                        raise Exception(f"Permission denied (403) and unable to list domains: {str(list_error)}")
                else:
                    # Other error, continue to try adding
                    logger.warning(f"Error getting domain {apex}: {get_error}")
            
            # Try to list all domains to check existence
            try:
                domains = service.domains().list(customer='my_customer').execute()
                existing_domains = [d.get('domainName', '') for d in domains.get('domains', [])]
                
                if apex in existing_domains:
                    logger.info(f"Domain {apex} already exists in Workspace (from list)")
                    return {'created': False, 'already_exists': True}
            except HttpError as list_error:
                logger.warning(f"Error listing domains: {list_error}")
                # Continue to try adding
            
            # Add domain
            domain_body = {'domainName': apex}
            try:
                result = service.domains().insert(customer='my_customer', body=domain_body).execute()
                logger.info(f"Successfully added domain {apex} to Workspace")
                return {'created': True, 'already_exists': False, 'domain': result}
            
            except HttpError as e:
                error_str = str(e)
                status_code = e.resp.status if hasattr(e, 'resp') else None
                
                if 'already exists' in error_str.lower() or 'duplicate' in error_str.lower():
                    logger.info(f"Domain {apex} already exists (caught during insert)")
                    return {'created': False, 'already_exists': True}
                elif status_code == 403:
                    # Permission denied during insert
                    logger.error(f"403 Forbidden adding domain {apex}. Check permissions/scopes.")
                    raise Exception(f"Permission denied (403) adding domain. Check Service Account scopes and Domain-Wide Delegation.")
                else:
                    raise
        
        except HttpError as e:
            error_str = str(e)
            status_code = e.resp.status if hasattr(e, 'resp') else None
            
            if status_code == 403:
                logger.error(f"403 Forbidden accessing Google Workspace API for {apex}")
                raise Exception(f"Permission denied (403) accessing Google Workspace. Check credentials.")
            
            logger.error(f"HTTP error adding domain {apex}: {e}")
            raise Exception(f"Failed to add domain: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error adding domain {apex}: {e}")
            raise
    
    def get_verification_token(self, domain: str, apex_domain: str = None) -> Dict:
        """
        Get DNS TXT verification token from Google Site Verification API.
        
        Args:
            domain: Domain to verify (can be subdomain or apex)
            apex_domain: Optional apex domain to fall back to if subdomain fails
        
        Returns:
            Dict with 'token' (str), 'host' (str, default '@'), 'method' (str)
        """
        # Try to get token, with fallback to apex domain if subdomain fails
        domains_to_try = [domain]
        if apex_domain and apex_domain != domain:
            domains_to_try.append(apex_domain)
        
        last_error = None
        
        for try_domain in domains_to_try:
            try:
                logger.info(f"Requesting verification token for: {try_domain}")
                token_result = self._request_verification_token(try_domain)
                if token_result:
                    return token_result
            except Exception as e:
                last_error = e
                logger.warning(f"Failed to get token for {try_domain}: {e}")
                if try_domain != domains_to_try[-1]:
                    logger.info(f"Trying next domain in fallback list...")
                    continue
                raise
        
        if last_error:
            raise last_error
        raise Exception("Failed to get verification token from Google")
    
    def _request_verification_token(self, domain: str) -> Dict:
        """Internal method to request verification token for a specific domain.
        
        Tries with domain delegation first, then without if that fails with 503.
        """
        # Try with delegation first, then without
        delegation_modes = [False, True]  # Try WITH delegation, then WITHOUT
        
        for without_delegation in delegation_modes:
            try:
                service = self._get_site_verification_service(without_delegation=without_delegation)
                
                verification_request = {
                    'site': {
                        'type': 'INET_DOMAIN',
                        'identifier': domain
                    },
                    'verificationMethod': 'DNS_TXT'
                }
                
                # Retry logic for 503 errors
                token_response = None
                max_retries = 3  # Fewer retries per mode
                last_error = None
                
                for attempt in range(max_retries):
                    try:
                        token_response = service.webResource().getToken(body=verification_request).execute()
                        logger.info(f"Successfully got token for {domain} (without_delegation={without_delegation})")
                        break
                    except HttpError as e:
                        last_error = e
                        if e.resp.status == 503:
                            if attempt < max_retries - 1:
                                wait_time = 2 + (attempt * 2) + random.uniform(0, 1)
                                logger.warning(f"503 error for {domain} (mode={without_delegation}), retry in {wait_time:.1f}s (Attempt {attempt+1}/{max_retries})")
                                time.sleep(wait_time)
                                continue
                            else:
                                # All retries for this mode failed
                                logger.warning(f"503 errors exhausted for {domain} with without_delegation={without_delegation}")
                                break  # Try next delegation mode
                        raise e
                
                if token_response:
                    token = token_response.get('token', '')
                    if token:
                        logger.info(f"Got verification token for {domain}: {token[:40]}...")
                        
                        # Fix: Check if token already contains the prefix (Google sometimes returns the full value)
                        if token.startswith('google-site-verification='):
                            txt_value = token
                            # Extract the actual token for the return value
                            actual_token = token.replace('google-site-verification=', '', 1)
                        else:
                            txt_value = f'google-site-verification={token}'
                            actual_token = token
                        
                        return {
                            'token': actual_token,
                            'host': '@',
                            'method': 'DNS_TXT',
                            'txt_value': txt_value
                        }
                    else:
                        logger.error(f"Empty token for {domain}. Response: {token_response}")
                        raise Exception("No token returned from Google")
                
            except HttpError as e:
                if e.resp.status != 503:
                    raise  # Non-503 error, don't retry with different mode
                last_error = e
            except Exception as e:
                last_error = e
                logger.error(f"Error with without_delegation={without_delegation}: {e}")
        
        # All modes failed
        if last_error:
            raise last_error
        raise Exception("Failed to get verification token from Google Site Verification API")
    
    
    def verify_domain(self, domain: str, apex_domain: str = None) -> Dict:
        """
        Verify domain in Google Workspace after DNS TXT record is created.
        
        This is a TWO-STEP process:
        1. Verify domain ownership via Site Verification API (proves we own the domain)
        2. Verify the domain in Google Workspace Admin SDK (marks it as verified for Workspace use)
        
        Args:
            domain: Domain to verify (can be subdomain like 'sub.example.com' or apex 'example.com')
            apex_domain: Optional pre-calculated apex domain for Admin SDK verification.
        
        Returns:
            Dict with 'verified' (bool) and 'status' (str)
        """
        logger.info(f"Starting domain verification for {domain}")
        
        # Use provided apex or calculate it (for Admin SDK, which needs apex)
        if apex_domain:
            apex = apex_domain
            logger.info(f"Using provided apex domain: {apex}")
        else:
            from services.zone_utils import to_apex
            apex = to_apex(domain)
            logger.info(f"Calculated apex domain: {apex}")
        
        # For Site Verification API, we verify the EXACT domain being added
        # If adding a subdomain, we verify the subdomain (not the apex)
        # The TXT record is at the subdomain, so Google looks for it there
        verification_domain = domain
        logger.info(f"Will verify domain: {verification_domain} (apex for Admin SDK: {apex})")
        
        # STEP 1: Site Verification API - Verify ownership
        site_verification_success = False
        site_verification_error = None
        
        for without_delegation in [False, True]:
            try:
                logger.info(f"Step 1: Site Verification for {verification_domain} (without_delegation={without_delegation})")
                service = self._get_site_verification_service(without_delegation=without_delegation)
                
                # Get admin email for owner field
                service_account_row = ServiceAccount.query.filter_by(name=self.account_name).first()
                admin_email = service_account_row.admin_email if service_account_row else None
                
                # Create verification resource - USE THE SUBDOMAIN being verified
                verification_resource = {
                    'site': {
                        'type': 'INET_DOMAIN',
                        'identifier': verification_domain  # Use subdomain (full domain being added)
                    }
                }
                
                if admin_email:
                    verification_resource['owners'] = [admin_email]
                    logger.info(f"Using admin email as owner: {admin_email}")
                
                # Try to insert/verify the domain
                result = service.webResource().insert(
                    verificationMethod='DNS_TXT',
                    body=verification_resource
                ).execute()
                
                logger.info(f"Site Verification API response for {verification_domain}: {result}")
                
                # Check if we got a valid response
                if result.get('id') or result.get('site', {}).get('identifier') == verification_domain:
                    logger.info(f"Site Verification succeeded for {verification_domain}")
                    site_verification_success = True
                    break
                    
            except HttpError as e:
                error_str = str(e)
                status = e.resp.status if hasattr(e, 'resp') else 'unknown'
                logger.warning(f"Site Verification HTTP {status} for {verification_domain}: {error_str}")
                
                # 409 means already verified in Site Verification - that's okay
                if status == 409 or 'already exists' in error_str.lower():
                    logger.info(f"Site Verification already exists for {verification_domain}")
                    site_verification_success = True
                    break
                
                # 400 means DNS not propagated - this is a real failure
                if status == 400:
                    error_msg = "DNS TXT record not found. Please wait for DNS propagation."
                    if 'verification token could not be found' in error_str.lower():
                        error_msg = f"DNS TXT verification token not found for {verification_domain}. Check that the TXT record was created at the apex domain."
                    logger.error(f"Site Verification failed for {verification_domain}: {error_msg}")
                    return {'verified': False, 'status': 'failed', 'error': error_msg}
                
                # 503 - try other mode
                if status == 503 and not without_delegation:
                    logger.info("503 error, trying without delegation...")
                    site_verification_error = error_str
                    continue
                
                site_verification_error = error_str
                
            except Exception as e:
                site_verification_error = str(e)
                logger.error(f"Site Verification error for {verification_domain}: {e}")
        
        if not site_verification_success:
            error_msg = f"Site Verification failed: {site_verification_error or 'Unknown error'}"
            logger.error(error_msg)
            return {'verified': False, 'status': 'failed', 'error': error_msg}
        
        # STEP 2: Google Admin SDK - Verify domain in Workspace
        try:
            logger.info(f"Step 2: Verifying domain {apex} in Google Workspace Admin SDK")
            admin_service = self._get_admin_service()
            
            # First check current verification status
            try:
                domain_info = admin_service.domains().get(customer='my_customer', domainName=apex).execute()
                current_verified = domain_info.get('verified', False)
                logger.info(f"Current Workspace verification status for {apex}: {current_verified}")
                
                if current_verified:
                    logger.info(f"Domain {apex} is already verified in Workspace!")
                    return {'verified': True, 'status': 'verified'}
                    
            except HttpError as e:
                if e.resp.status == 404:
                    logger.warning(f"Domain {apex} not found in Workspace, will try to add it")
                    # Try to add the domain first
                    try:
                        add_result = self.ensure_domain_added(apex)
                        logger.info(f"Added domain {apex} to Workspace: {add_result}")
                    except Exception as add_error:
                        logger.warning(f"Could not add domain {apex}: {add_error}")
                else:
                    logger.warning(f"Error getting domain {apex}: {e}")
            
            # Now try to verify the domain in Workspace
            # The Admin SDK domains().verify() method triggers verification
            try:
                verify_result = admin_service.domains().get(customer='my_customer', domainName=apex).execute()
                
                # After Site Verification succeeds and DNS is correct,
                # Google should automatically verify the domain on the next check
                # Let's check the verified status
                is_verified = verify_result.get('verified', False)
                
                if is_verified:
                    logger.info(f"Domain {apex} is NOW verified in Google Workspace!")
                    return {'verified': True, 'status': 'verified'}
                else:
                    # Domain exists but not verified yet
                    # This could happen if DNS just propagated
                    logger.warning(f"Domain {apex} exists in Workspace but not yet verified. Status: {verify_result}")
                    return {
                        'verified': False, 
                        'status': 'pending', 
                        'error': 'Domain added to Workspace but verification pending. TXT record may still be propagating.'
                    }
                    
            except HttpError as e:
                error_str = str(e)
                status = e.resp.status if hasattr(e, 'resp') else 'unknown'
                logger.error(f"Admin SDK verification error for {apex}: HTTP {status} - {error_str}")
                
                return {
                    'verified': False,
                    'status': 'failed',
                    'error': f'Admin SDK error: {error_str}'
                }
                
        except Exception as e:
            logger.error(f"Workspace verification error for {apex}: {e}", exc_info=True)
            return {
                'verified': False,
                'status': 'failed', 
                'error': f'Workspace verification error: {str(e)}'
            }
    
    def is_verified(self, apex: str) -> bool:
        """
        Check if domain is already verified in Google Workspace.
        
        Args:
            apex: Apex domain to check
        
        Returns:
            True if verified, False otherwise
        """
        try:
            admin_service = self._get_admin_service()
            
            # Get domain info
            try:
                domain_info = admin_service.domains().get(customer='my_customer', domainName=apex).execute()
                verified = domain_info.get('verified', False)
                logger.info(f"Domain {apex} verification status: {verified}")
                return verified
            
            except HttpError as e:
                if e.resp.status == 404:
                    logger.info(f"Domain {apex} not found in Workspace")
                    return False
                else:
                    logger.error(f"Error checking verification status for {apex}: {e}")
                    return False
        
        except Exception as e:
            logger.error(f"Error checking if domain {apex} is verified: {e}")
            return False
