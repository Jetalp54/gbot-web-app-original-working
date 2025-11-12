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
from database import GoogleAccount, GoogleToken

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
        
        Args:
            apex: Apex domain to add
        
        Returns:
            Dict with 'created' (bool) and 'already_exists' (bool)
        """
        try:
            service = self._get_admin_service()
            
            # Check if domain already exists
            try:
                domains = service.domains().list(customer='my_customer').execute()
                existing_domains = [d.get('domainName', '') for d in domains.get('domains', [])]
                
                if apex in existing_domains:
                    logger.info(f"Domain {apex} already exists in Workspace")
                    return {'created': False, 'already_exists': True}
            
            except HttpError as e:
                logger.warning(f"Error checking existing domains: {e}")
            
            # Add domain
            domain_body = {'domainName': apex}
            try:
                result = service.domains().insert(customer='my_customer', body=domain_body).execute()
                logger.info(f"Successfully added domain {apex} to Workspace")
                return {'created': True, 'already_exists': False, 'domain': result}
            
            except HttpError as e:
                error_str = str(e)
                if 'already exists' in error_str.lower() or 'duplicate' in error_str.lower():
                    logger.info(f"Domain {apex} already exists (caught during insert)")
                    return {'created': False, 'already_exists': True}
                else:
                    raise
        
        except HttpError as e:
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
                token_response = service.webResource().getToken(body=verification_request).execute()
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
        
        Args:
            apex: Apex domain to verify
        
        Returns:
            Dict with 'verified' (bool) and 'status' (str)
        """
        try:
            service = self._get_site_verification_service()
            
            # Create verification resource
            verification_resource = {
                'site': {
                    'type': 'INET_DOMAIN',
                    'identifier': apex
                }
            }
            
            try:
                # Insert verification resource
                # Note: The insert method may require the token to be set first
                # We'll try to insert and then check status
                try:
                    result = service.webResource().insert(verificationMethod='DNS_TXT', body=verification_resource).execute()
                    logger.info(f"Verification resource created for {apex}")
                except HttpError as insert_error:
                    # If already exists, try to get it
                    if 'already exists' in str(insert_error).lower():
                        logger.info(f"Verification resource already exists for {apex}, fetching...")
                        result = service.webResource().get(id=apex).execute()
                    else:
                        raise
                
                # Check verification status
                verified = result.get('verified', False)
                return {
                    'verified': verified,
                    'status': 'verified' if verified else 'pending'
                }
            
            except HttpError as e:
                error_str = str(e)
                if 'already verified' in error_str.lower() or 'already exists' in error_str.lower():
                    logger.info(f"Domain {apex} already verified")
                    return {'verified': True, 'status': 'verified'}
                else:
                    logger.error(f"HTTP error verifying domain {apex}: {error_str}")
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
