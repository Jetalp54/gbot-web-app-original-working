"""
Namecheap DNS management service.
Handles DNS record retrieval and TXT record creation/updates.
"""
import logging
import requests
from typing import List, Dict, Optional
from database import NamecheapConfig

logger = logging.getLogger(__name__)

class HostRecord:
    """Represents a DNS host record."""
    def __init__(self, host: str, record_type: str, address: str, mx_pref: int = None, ttl: int = 300):
        self.host = host
        self.record_type = record_type
        self.address = address
        self.mx_pref = mx_pref
        self.ttl = ttl
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for Namecheap API."""
        result = {
            'HostName': self.host,
            'RecordType': self.record_type,
            'Address': self.address,
            'TTL': self.ttl
        }
        if self.mx_pref is not None:
            result['MXPref'] = self.mx_pref
        return result

class NamecheapDNSService:
    """Service for managing Namecheap DNS records."""
    
    BASE_URL = "https://api.namecheap.com/xml.response"
    
    def __init__(self):
        """Initialize service with credentials from database."""
        self._config = None
        self._load_config()
    
    def _load_config(self):
        """Load Namecheap configuration from database."""
        try:
            config = NamecheapConfig.query.filter_by(is_configured=True).first()
            if not config:
                raise Exception("Namecheap configuration not found. Please configure in Settings.")
            
            self._config = config
            logger.info("Namecheap configuration loaded")
        
        except Exception as e:
            logger.error(f"Error loading Namecheap config: {e}")
            raise
    
    def _make_request(self, command: str, extra_params: Dict = None) -> Dict:
        """
        Make API request to Namecheap.
        
        Args:
            command: API command name
            extra_params: Additional parameters
        
        Returns:
            Parsed XML response as dict (simplified - returns raw response for now)
        """
        if not self._config:
            raise Exception("Namecheap configuration not loaded")
        
        params = {
            'ApiUser': self._config.api_user,
            'ApiKey': self._config.api_key,
            'UserName': self._config.username,
            'Command': command,
            'ClientIp': self._config.client_ip
        }
        
        if extra_params:
            params.update(extra_params)
        
        try:
            response = requests.get(self.BASE_URL, params=params, timeout=30)
            response.raise_for_status()
            
            # Parse XML response (simplified - in production, use proper XML parser)
            # For now, we'll use a simple approach and parse the XML
            import xml.etree.ElementTree as ET
            root = ET.fromstring(response.text)
            
            # Check for errors
            errors = root.findall('.//Error')
            if errors:
                error_messages = [e.text for e in errors]
                raise Exception(f"Namecheap API error: {', '.join(error_messages)}")
            
            return {'success': True, 'xml': root, 'raw': response.text}
        
        except requests.RequestException as e:
            logger.error(f"Namecheap API request failed: {e}")
            raise Exception(f"Namecheap API request failed: {str(e)}")
    
    def get_hosts(self, apex: str) -> List[HostRecord]:
        """
        Get all DNS records for a domain.
        
        Args:
            apex: Apex domain (zone name)
        
        Returns:
            List of HostRecord objects
        """
        try:
            result = self._make_request('namecheap.domains.dns.getHosts', {
                'SLD': self._extract_sld(apex),
                'TLD': self._extract_tld(apex)
            })
            
            root = result['xml']
            hosts = []
            
            # Parse host records from XML
            # Namecheap API returns hosts in <host> elements with attributes
            # Format: <host Name="@" Type="A" Address="1.2.3.4" MXPref="10" TTL="300" />
            for host_elem in root.findall('.//host'):
                # Try both attribute access methods
                host = host_elem.get('Name') or host_elem.attrib.get('Name', '@')
                record_type = host_elem.get('Type') or host_elem.attrib.get('Type', '')
                address = host_elem.get('Address') or host_elem.attrib.get('Address', '')
                mx_pref = host_elem.get('MXPref') or host_elem.attrib.get('MXPref')
                ttl_str = host_elem.get('TTL') or host_elem.attrib.get('TTL', '300')
                
                # Skip empty records
                if not record_type or not address:
                    continue
                
                try:
                    ttl = int(ttl_str) if ttl_str else 300
                except (ValueError, TypeError):
                    ttl = 300
                
                hosts.append(HostRecord(
                    host=host or '@',
                    record_type=record_type,
                    address=address,
                    mx_pref=int(mx_pref) if mx_pref and str(mx_pref).isdigit() else None,
                    ttl=ttl
                ))
            
            logger.info(f"Retrieved {len(hosts)} DNS records for {apex}")
            return hosts
        
        except Exception as e:
            logger.error(f"Error getting hosts for {apex}: {e}")
            raise
    
    def upsert_txt_record(self, apex: str, host: str, value: str, ttl: int = 300) -> Dict:
        """
        Create or update TXT record, preserving all existing records.
        
        Args:
            apex: Apex domain (zone name)
            host: Host name ('@' for apex)
            value: TXT record value
            ttl: TTL in seconds (default 300)
        
        Returns:
            Dict with 'updated' (bool)
        """
        try:
            # Get all existing records
            existing_hosts = self.get_hosts(apex)
            
            # Check if TXT record with same host and value already exists
            for record in existing_hosts:
                if record.host == host and record.record_type == 'TXT' and record.address == value:
                    logger.info(f"TXT record already exists for {apex} @ {host} with value {value}")
                    return {'updated': True, 'action': 'no-op', 'message': 'Record already exists'}
            
            # Create updated host list
            updated_hosts = []
            txt_found = False
            
            # Preserve all existing records
            for record in existing_hosts:
                # If we find a TXT record with same host but different value, we'll add a new one
                # (Namecheap supports multiple TXT records)
                if record.host == host and record.record_type == 'TXT':
                    txt_found = True
                    # Keep existing, will add new one below
                updated_hosts.append(record)
            
            # Add new TXT record
            new_txt = HostRecord(host=host, record_type='TXT', address=value, ttl=ttl)
            updated_hosts.append(new_txt)
            
            # Convert to Namecheap API format
            sld = self._extract_sld(apex)
            tld = self._extract_tld(apex)
            
            # Build host list parameter (Namecheap expects specific format)
            host_list = []
            for i, record in enumerate(updated_hosts, start=1):
                host_list.append(f"{record.host},{record.record_type},{record.address},{record.ttl}")
                if record.mx_pref is not None:
                    host_list[-1] += f",{record.mx_pref}"
            
            # Set hosts via API
            params = {
                'SLD': sld,
                'TLD': tld
            }
            
            # Namecheap API expects hosts in specific numbered format
            # Format: HostName1, RecordType1, Address1, TTL1, MXPref1 (optional), ...
            for i, record in enumerate(updated_hosts, start=1):
                params[f'HostName{i}'] = record.host
                params[f'RecordType{i}'] = record.record_type
                params[f'Address{i}'] = record.address
                params[f'TTL{i}'] = str(record.ttl)
                if record.mx_pref is not None:
                    params[f'MXPref{i}'] = str(record.mx_pref)
            
            result = self._make_request('namecheap.domains.dns.setHosts', params)
            
            logger.info(f"Successfully updated DNS records for {apex}, added TXT record @ {host}")
            return {'updated': True, 'action': 'added', 'message': 'TXT record added'}
        
        except Exception as e:
            logger.error(f"Error upserting TXT record for {apex}: {e}")
            raise
    
    def _extract_sld(self, domain: str) -> str:
        """Extract second-level domain (e.g., 'example' from 'example.com')."""
        parts = domain.split('.')
        if len(parts) >= 2:
            return parts[-2]
        return parts[0]
    
    def _extract_tld(self, domain: str) -> str:
        """Extract top-level domain (e.g., 'com' from 'example.com')."""
        parts = domain.split('.')
        if len(parts) >= 2:
            return parts[-1]
        # For domains like 'co.uk', return the last two parts
        if len(parts) >= 3:
            return '.'.join(parts[-2:])
        return parts[-1] if parts else ''
