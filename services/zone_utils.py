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
        
        # Use publicsuffix2 to get the public suffix (TLD)
        psl = publicsuffix2.PublicSuffixList()
        suffix = psl.get_public_suffix(domain)
        
        if not suffix:
            # Fallback: basic extraction (last 2 parts)
            parts = domain.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return domain
            
        # If domain IS the suffix (e.g. "co.uk"), return it (though invalid for registration)
        if domain == suffix:
            return domain
            
        # Extract the part before the suffix
        # domain = "sub.example.co.uk", suffix = "co.uk"
        # suffix_len = 5
        # prefix = "sub.example"
        prefix = domain[:-len(suffix)].rstrip('.')
        
        # Get the last part of the prefix (the SLD)
        prefix_parts = prefix.split('.')
        sld = prefix_parts[-1]
        
        apex = f"{sld}.{suffix}"
        logger.info(f"Converted {domain} to apex: {apex} (suffix: {suffix})")
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
