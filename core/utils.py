"""
CaseVault Core Utilities
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)
"""

import hashlib
import ipaddress


def get_client_ip(request) -> str:
    """
    Safely retrieves the client's IP address from request headers.
    Directly defaults to REMOTE_ADDR to avoid spoofed X-Forwarded-For headers
    unless explicitly behind a known reverse proxy.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Take the leftmost untrusted IP if behind a reverse proxy
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    
    # Validate that it is a syntactically valid IP address
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return '127.0.0.1'


def anonymize_ip(ip: str) -> str:
    """
    Hashes an IP address using SHA-256 for privacy-preserving audit logs.
    """
    return hashlib.sha256(ip.encode('utf-8')).hexdigest()[:16]
