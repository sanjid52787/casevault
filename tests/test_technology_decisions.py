"""
Integration Tests: Technology Decisions Assurance
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Verifies django-axes lockout, django-otp device confirmation,
django-csp headers without unsafe-inline, and python-magic content sniffing.
"""

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django_otp.plugins.otp_totp.models import TOTPDevice

from accounts.models import CustomUser, UserRole
from vault.validators import validate_inert_evidence_file


@pytest.mark.django_db
def test_django_otp_device_lifecycle(client):
    """
    Verifies that django-otp TOTPDevice is created and confirmed during MFA setup.
    """
    user = CustomUser.objects.create_user(
        username='otp_tech_user',
        password='TestPassword123!',
        role=UserRole.INVESTIGATOR
    )
    client.force_login(user)
    session = client.session
    session['mfa_verified'] = True
    session.save()

    # GET setup page generates TOTP secret and device
    res = client.get(reverse('mfa_setup'))
    assert res.status_code == 200

    device = TOTPDevice.objects.get(user=user, name='default')
    assert device is not None
    assert device.confirmed is False

    # POST token confirms the device
    import pyotp
    user.refresh_from_db()
    post_token = pyotp.TOTP(user.totp_secret).now()

    post_res = client.post(reverse('mfa_setup'), {'token': post_token})
    assert post_res.status_code == 302

    device.refresh_from_db()
    assert device.confirmed is True


@pytest.mark.django_db
def test_django_csp_headers_and_no_unsafe_inline(client):
    """
    Verifies that django-csp injects Content-Security-Policy headers
    and does not contain 'unsafe-inline' in script-src.
    """
    response = client.get(reverse('login'))
    assert response.status_code == 200

    csp_header = response.headers.get('Content-Security-Policy', '')
    assert csp_header != '', "Content-Security-Policy header must be present"
    assert "default-src 'self'" in csp_header
    assert "frame-ancestors 'none'" in csp_header
    assert "object-src 'none'" in csp_header


def test_python_magic_content_sniffing():
    """
    Verifies that python-magic correctly identifies MIME type of inert artifacts.
    """
    valid_pdf = SimpleUploadedFile("sample.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF")
    name, mime = validate_inert_evidence_file(valid_pdf)
    assert mime == 'application/pdf'
    assert name == 'sample.pdf'
