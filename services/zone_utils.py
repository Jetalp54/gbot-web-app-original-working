"""
Zone utilities for domain apex detection using Public Suffix List.
"""
import logging
import publicsuffix2

logger = logging.getLogger(__name__)

def to_apex(domain: str) -> str:
    """
    Convert any domain (including subdomains) to its registrable apex domain.
    
    Examples:
        mail.team.example.co.uk -> example.co.uk
        sub.example.com -> example.com
        example.com -> example.com
    
    Args:
        domain: Input domain (can be subdomain or apex)
    
    Returns:
        Apex domain string
    """
    try:
        domain = domain.strip().lower()
        if not domain:
            raise ValueError("Empty domain string")
        
        # Use publicsuffix2 to get the registrable domain
        psl = publicsuffix2.PublicSuffixList()
        apex = psl.get_public_suffix(domain)
        
        if not apex:
            # Fallback: if PSL doesn't work, try basic extraction
            parts = domain.split('.')
            if len(parts) >= 2:
                apex = '.'.join(parts[-2:])
            else:
                apex = domain
        
        logger.info(f"Converted {domain} to apex: {apex}")
        return apex
    
    except Exception as e:
        logger.error(f"Error converting {domain} to apex: {e}")
        # Fallback: basic domain extraction
        parts = domain.strip().lower().split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain.strip().lower()

def matching_zone_in_namecheap(apex: str) -> str:
    """
    For Namecheap, the apex domain is the zone.
    This function validates and returns the zone name.
    
    Args:
        apex: Apex domain name
    
    Returns:
        Zone name (same as apex for Namecheap)
    """
    apex = apex.strip().lower()
    if not apex:
        raise ValueError("Empty apex domain")
    
    # Namecheap uses the apex as the zone
    return apex
