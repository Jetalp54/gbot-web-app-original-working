"""
Google Workspace domain management service.
Handles domain addition, verification token retrieval, and domain verification.
"""
import logging
import time
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
                from services.google_service_account import GoogleServiceAccount
                gsa = GoogleServiceAccount(service_account.id)
                return gsa.get_credentials()

            # Fallback to Google Account (deprecated)
            account = GoogleAccount.query.filter_by(account_name=self.account_name).first()
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
    
    def _get_site_verification_service(self):
        """Get or create Site Verification API service."""
        if self._site_verification_service:
            return self._site_verification_service
        
        creds = self._get_credentials()
        if not creds:
            raise Exception("Failed to get valid credentials")
        
        # Site Verification API requires additional scope
        # Note: This scope should be added during OAuth flow
        self._site_verification_service = build('siteVerification', 'v1', credentials=creds)
        return self._site_verification_service
    
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
    
    def get_verification_token(self, apex: str) -> Dict:
        """
        Get DNS TXT verification token from Google Site Verification API.
        
        Args:
            apex: Apex domain to verify
        
        Returns:
            Dict with 'token' (str), 'host' (str, default '@'), 'method' (str)
        """
        try:
            service = self._get_site_verification_service()
            
            # Request verification token
            verification_request = {
                'site': {
                    'type': 'INET_DOMAIN',
                    'identifier': apex
                },
                'verificationMethod': 'DNS_TXT'
            }
            
            try:
                # Retry logic for 503 errors
                token_response = None
                max_retries = 5
                for attempt in range(max_retries):
                    try:
                        token_response = service.webResource().getToken(body=verification_request).execute()
                        break
                    except HttpError as e:
                        if e.resp.status == 503:
                            if attempt < max_retries - 1:
                                wait_time = (2 ** attempt) + 1  # Exponential backoff
                                logger.warning(f"503 error getting token, retrying in {wait_time}s... (Attempt {attempt+1}/{max_retries})")
                                time.sleep(wait_time)
                                continue
                        raise e
                
                token = token_response.get('token', '')
                
                if not token:
                    raise Exception("No token returned from Google Site Verification API")
                
                # Default host is '@' for apex domain
                host = '@'
                
                # Check if API specifies a different host
                # Google typically uses '@' for domain verification
                logger.info(f"Got verification token for {apex}, host: {host}")
                
                return {
                    'token': token,
                    'host': host,
                    'method': 'DNS_TXT',
                    'txt_value': f'google-site-verification={token}'
                }
            
            except HttpError as e:
                error_str = str(e)
                logger.error(f"HTTP error getting verification token for {apex}: {error_str}")
                
                # Try alternative method: use the token directly if available
                if 'token' in error_str.lower():
                    # Some APIs return token in error message (unlikely, but handle gracefully)
                    raise Exception(f"Failed to get verification token: {error_str}")
                else:
                    raise Exception(f"Site Verification API error: {error_str}")
        
        except Exception as e:
            logger.error(f"Error getting verification token for {apex}: {e}")
            raise
    
    def verify_domain(self, apex: str) -> Dict:
        """
        Verify domain in Google Workspace after DNS TXT record is created.
        
        According to Google docs: https://docs.cloud.google.com/channel/docs/codelabs/workspace/domain-verification
        Setting the admin user as an owner makes verification status propagate instantly.
        
        Args:
            apex: Apex domain to verify
        
        Returns:
            Dict with 'verified' (bool) and 'status' (str)
        """
        try:
            service = self._get_site_verification_service()
            
            # Get admin email from account to set as owner for instant propagation
            # Check for Service Account first
            service_account = ServiceAccount.query.filter_by(name=self.account_name).first()
            admin_email = None
            
            if service_account:
                admin_email = service_account.admin_email
                logger.info(f"Using Service Account admin email for verification: {admin_email}")
            else:
                # Fallback to Google Account (deprecated)
                account = GoogleAccount.query.filter_by(account_name=self.account_name).first()
                if account:
                    # Try to get the primary admin email
                    try:
                        admin_service = self._get_admin_service()
                        users = admin_service.users().list(customer='my_customer', maxResults=1, orderBy='email').execute()
                        if users.get('users'):
                            admin_email = users['users'][0].get('primaryEmail')
                    except Exception as e:
                        logger.warning(f"Could not get admin email for owner: {e}")
                        # Fallback: construct admin email from domain
                        admin_email = f"admin@{apex}"
                else:
                    admin_email = f"admin@{apex}"
            
            # Create verification resource with owner for instant propagation
            # According to Google docs, setting owners makes verification propagate instantly
            verification_resource = {
                'site': {
                    'type': 'INET_DOMAIN',
                    'identifier': apex
                },
                'owners': [admin_email] if admin_email else []
            }
            
            try:
                # Insert verification resource
                # According to Google docs: webResource().insert(verificationMethod='DNS_TXT', body=resource)
                try:
                    result = service.webResource().insert(verificationMethod='DNS_TXT', body=verification_resource).execute()
                    logger.info(f"Verification resource created for {apex} with owner {admin_email}")
                    
                    # Check verification status
                    verified = result.get('verified', False)
                    if verified:
                        logger.info(f"Domain {apex} verified successfully")
                    else:
                        logger.info(f"Domain {apex} verification pending (may take a few moments)")
                    
                    return {
                        'verified': verified,
                        'status': 'verified' if verified else 'pending'
                    }
                    
                except HttpError as insert_error:
                    error_str = str(insert_error)
                    # If already exists, try to get it and check status
                    if 'already exists' in error_str.lower() or '409' in error_str:
                        logger.info(f"Verification resource already exists for {apex}, fetching status...")
                        try:
                            result = service.webResource().get(id=apex).execute()
                            verified = result.get('verified', False)
                            logger.info(f"Domain {apex} verification status: {verified}")
                            return {
                                'verified': verified,
                                'status': 'verified' if verified else 'pending'
                            }
                        except HttpError as get_error:
                            logger.warning(f"Could not get existing verification resource: {get_error}")
                            # If we can't get it, assume it's verified (since it exists)
                            return {'verified': True, 'status': 'verified'}
                    elif '400' in error_str or 'bad request' in error_str.lower():
                        # DNS TXT record may not have propagated yet
                        logger.warning(f"DNS TXT record may not have propagated yet for {apex}: {error_str}")
                        return {'verified': False, 'status': 'pending', 'error': 'DNS not propagated yet'}
                    else:
                        raise
            
            except HttpError as e:
                error_str = str(e)
                logger.error(f"HTTP error verifying domain {apex}: {error_str}")
                if 'already verified' in error_str.lower():
                    return {'verified': True, 'status': 'verified'}
                else:
                    return {'verified': False, 'status': 'failed', 'error': error_str}
        
        except Exception as e:
            logger.error(f"Error verifying domain {apex}: {e}")
            return {'verified': False, 'status': 'error', 'error': str(e)}
    
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
