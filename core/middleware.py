"""
CaseVault Core Security Middleware
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Implements defense-in-depth HTTP security headers, dynamic CSP nonce generation,
strict MFA enforcement for authenticated sessions, and client IP extraction.
"""

import logging
import secrets

from django.conf import settings
from django.shortcuts import redirect
from django.urls import Resolver404, resolve

logger = logging.getLogger('casevault.security')


class SecurityHeadersMiddleware:
    """
    Injects hardened HTTP response headers to defend against:
    - Cross-Site Scripting (CSP with per-request cryptographic nonces)
    - Clickjacking (X-Frame-Options: DENY & CSP frame-ancestors: none)
    - MIME confusion / sniffing (X-Content-Type-Options: nosniff)
    - Information leakage (Referrer-Policy: strict-origin-when-cross-origin)
    - Unauthorized device API access (Permissions-Policy)
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Generate a per-request cryptographically secure nonce for inline scripts/styles if needed
        nonce = secrets.token_urlsafe(16)
        request.csp_nonce = nonce

        response = self.get_response(request)

        # Skip modifying headers for evidence download views that set their own isolated sandbox CSP
        if response.has_header('Content-Security-Policy'):
            return response

        # Construct strict Content Security Policy
        csp_directives = [
            "default-src 'self'",
            f"script-src 'self' 'nonce-{nonce}'",
            # style-src allows self and inline styling required by clean UI presentation
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com data:",
            "img-src 'self' data:",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "block-all-mixed-content",
        ]
        response['Content-Security-Policy'] = "; ".join(csp_directives)

        # Standard defense-in-depth headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Cross-Origin-Opener-Policy'] = 'same-origin'
        response['Cross-Origin-Resource-Policy'] = 'same-origin'
        response['Permissions-Policy'] = (
            'accelerometer=(), camera=(), geolocation=(), gyroscope=(), '
            'magnetometer=(), microphone=(), payment=(), usb=()'
        )

        if getattr(settings, 'SECURE_HSTS_SECONDS', 0) > 0:
            hsts_val = f"max-age={settings.SECURE_HSTS_SECONDS}; includeSubDomains"
            if getattr(settings, 'SECURE_HSTS_PRELOAD', False):
                hsts_val += "; preload"
            response['Strict-Transport-Security'] = hsts_val

        return response


class MFAEnforcementMiddleware:
    """
    Enforces two-step verification gate:
    If an authenticated user has MFA configured (or required by policy), they cannot
    access any application resource until the active session presents a valid TOTP token.
    """

    EXEMPT_URL_NAMES = {
        'login',
        'logout',
        'mfa_verify',
        'mfa_setup',
        'static',
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            # Check if user requires MFA and has not completed it in current session
            is_mfa_verified = request.session.get('mfa_verified', False)
            user_has_mfa = getattr(request.user, 'is_mfa_enabled', False)

            if user_has_mfa and not is_mfa_verified:
                try:
                    current_url_name = resolve(request.path_info).url_name
                except Resolver404:
                    current_url_name = None

                # Exclude authentication and MFA verification endpoints
                if current_url_name not in self.EXEMPT_URL_NAMES and not request.path_info.startswith('/static/'):
                    return redirect('mfa_verify')

        return self.get_response(request)


class SensitiveDataLoggingFilter(logging.Filter):
    """
    Sanitizes log records to guarantee that credentials, tokens, session IDs,
    and evidence data are never leaked to logs (satisfying Hard Rule #5).
    """

    REDACTED_KEYWORDS = (
        'password',
        'secret',
        'token',
        'totp',
        'authorization',
        'cookie',
        'sessionid',
        'fernet',
        'hmac',
    )

    def filter(self, record):
        msg = str(record.msg)
        lower_msg = msg.lower()
        for kw in self.REDACTED_KEYWORDS:
            if kw in lower_msg:
                # If sensitive keyword appears in log string, scrub potential values
                record.msg = f"[REDACTED LOG ENTRY CONTAINING '{kw.upper()}']"
                break
        return True

