"""
Integration Tests: User View Workflows & Security State Transitions
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)
"""

import pyotp
import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from accounts.models import CustomUser, UserRole
from cases.models import Case, CaseClassification


@pytest.mark.django_db
def test_full_login_mfa_workflow(client):
    """
    Simulates end-to-end login flow:
    1. Enter credentials (password checked with Argon2id)
    2. Session marked mfa_pending
    3. Enter valid TOTP code
    4. Session elevated to mfa_verified = True
    """
    user = CustomUser.objects.create_user(
        username='workflow_user',
        password='ValidPassword123!',
        role=UserRole.INVESTIGATOR,
        is_mfa_enabled=True
    )
    secret = user.generate_totp_secret()

    # Step 1: POST credentials
    res1 = client.post(reverse('login'), {
        'username': 'workflow_user',
        'password': 'ValidPassword123!'
    })
    assert res1.status_code == 302
    assert res1.url == reverse('mfa_verify')
    assert client.session.get('mfa_user_id') == str(user.id)
    assert client.session.get('mfa_verified') is False

    # Step 2: POST valid TOTP code
    totp = pyotp.TOTP(secret)
    token = totp.now()

    res2 = client.post(reverse('mfa_verify'), {'token': token})
    assert res2.status_code == 302
    assert res2.url == reverse('case_list')
    assert client.session.get('mfa_verified') is True


@pytest.mark.django_db
def test_mfa_setup_flow(client, investigator):
    """
    Tests onboarding an account to TOTP MFA via mfa_setup_view.
    """
    client.force_login(investigator)
    session = client.session
    session['mfa_verified'] = True
    session.save()

    # GET setup page
    get_res = client.get(reverse('mfa_setup'))
    assert get_res.status_code == 200
    assert 'totp_secret' in get_res.context
    secret = get_res.context['totp_secret']

    # POST valid activation token
    totp = pyotp.TOTP(secret)
    post_res = client.post(reverse('mfa_setup'), {'token': totp.now()})
    assert post_res.status_code == 302

    investigator.refresh_from_db()
    assert investigator.is_mfa_enabled is True


@pytest.mark.django_db
def test_lead_case_creation_and_member_assignment(client, lead_investigator, investigator):
    """
    Tests case creation and subsequent investigator assignment by case lead.
    """
    client.force_login(lead_investigator)
    session = client.session
    session['mfa_verified'] = True
    session.save()

    # Create Case
    create_res = client.post(reverse('case_create'), {
        'case_number': 'NCR-NEW-999',
        'title': 'New Breach Engagement',
        'client_organization': 'New Corp',
        'classification': CaseClassification.RESTRICTED,
        'description': 'Test scenario briefing'
    })
    assert create_res.status_code == 302
    case = Case.objects.get(case_number='NCR-NEW-999')
    assert case.lead_investigator == lead_investigator

    # Assign Investigator
    assign_res = client.post(reverse('case_add_member', kwargs={'case_id': case.id}), {
        'user_id': str(investigator.id)
    })
    assert assign_res.status_code == 302
    assert case.memberships.filter(user=investigator).exists()

    # Append Note
    note_res = client.post(reverse('case_add_note', kwargs={'case_id': case.id}), {
        'note': 'Forensic triage initiated.',
        'is_client_visible': 'on'
    })
    assert note_res.status_code == 302
    assert case.notes.count() == 1


@pytest.mark.django_db
def test_evidence_upload_workflow(client, lead_investigator, case_alpha, tmp_path, monkeypatch):
    """
    Tests evidence upload view executing file validation, encryption, and audit logging.
    """
    from django.conf import settings
    monkeypatch.setattr(settings, 'EVIDENCE_STORAGE_PATH', tmp_path)

    client.force_login(lead_investigator)
    session = client.session
    session['mfa_verified'] = True
    session.save()

    valid_log = SimpleUploadedFile("network_triage.log", b"TIMESTAMP: 2026-10-30T01:00:00Z EVENT: VPN LOGIN")
    res = client.post(reverse('evidence_upload', kwargs={'case_id': case_alpha.id}), {
        'evidence_file': valid_log,
        'description': 'Simulated VPN authentication log'
    })
    assert res.status_code == 302

    assert case_alpha.evidence_items.filter(original_filename='network_triage.log').exists()


@pytest.mark.django_db
def test_audit_log_view_and_verification_workflow(client, admin_user):
    """
    Tests audit log administrative view and on-demand chain verification execution.
    """
    client.force_login(admin_user)
    session = client.session
    session['mfa_verified'] = True
    session.save()

    # Trigger audit log verification POST
    res = client.post(reverse('audit_log'), {'verify_chain': '1'})
    assert res.status_code == 200
    assert 'verification_result' in res.context
    assert res.context['verification_result']['is_valid'] is True

