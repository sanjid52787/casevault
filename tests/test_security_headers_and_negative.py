"""
Integration Tests: Security Headers, CSRF, and Negative Access Scenarios
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)
"""

import pytest
from django.urls import reverse

from accounts.models import CustomUser, UserRole


@pytest.mark.django_db
def test_hardened_security_headers(client):
    """
    Verifies that the SecurityHeadersMiddleware injects required defensive headers.
    """
    response = client.get(reverse('login'))
    assert response.status_code == 200

    # Content Security Policy with nonce
    assert 'Content-Security-Policy' in response
    csp = response['Content-Security-Policy']
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp

    # Anti-sniffing & Clickjacking
    assert response['X-Content-Type-Options'] == 'nosniff'
    assert response['X-Frame-Options'] == 'DENY'
    assert response['Referrer-Policy'] == 'strict-origin-when-cross-origin'


@pytest.mark.django_db
def test_unauthenticated_access_redirects_to_login(client):
    """
    Ensures protected routes reject unauthenticated requests and redirect to login.
    """
    response = client.get(reverse('case_list'))
    assert response.status_code == 302
    assert reverse('login') in response.url


@pytest.mark.django_db
def test_unverified_mfa_middleware_interception(client):
    """
    Verifies that a user with MFA enabled cannot access case data
    if their session has not completed the second factor challenge (MFA gate).
    """
    user = CustomUser.objects.create_user(
        username='mfa_gated_user',
        password='ValidPassword123!',
        role=UserRole.INVESTIGATOR,
        is_mfa_enabled=True
    )
    user.generate_totp_secret()

    # Log in user with mfa_verified = False
    client.force_login(user)
    session = client.session
    session['mfa_verified'] = False
    session.save()

    # Attempt to access case list
    response = client.get(reverse('case_list'))
    assert response.status_code == 302
    assert response.url == reverse('mfa_verify'), "MFAEnforcementMiddleware must redirect unverified sessions"


@pytest.mark.django_db
def test_csrf_protection_enforcement(client):
    """
    Verifies that state-modifying requests without CSRF token are blocked with HTTP 403.
    """
    csrf_client = client.__class__(enforce_csrf_checks=True)
    response = csrf_client.post(reverse('login'), {'username': 'attacker', 'password': 'foo'})
    assert response.status_code == 403, "Requests lacking valid CSRF token must be rejected"

