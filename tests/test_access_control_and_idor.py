"""
Integration Tests: Access Control & Insecure Direct Object References (Anti-IDOR)
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)
"""

import pytest
from django.urls import reverse
from cases.models import Case, CaseNote


@pytest.mark.django_db
def test_case_queryset_tenancy_and_role_isolation(
    admin_user, lead_investigator, investigator, other_investigator,
    client_auditor_alpha, client_auditor_beta, case_alpha, case_beta
):
    """
    Verifies that Case.objects.for_user() enforces multi-tenancy and RBAC (ADR-0002).
    """
    # 1. Administrator sees all cases
    admin_cases = Case.objects.for_user(admin_user)
    assert admin_cases.count() == 2

    # 2. Lead Investigator (leads both cases in fixtures) sees both
    lead_cases = Case.objects.for_user(lead_investigator)
    assert lead_cases.count() == 2

    # 3. Assigned investigator sees only Case Alpha, NOT Case Beta
    inv_cases = Case.objects.for_user(investigator)
    assert case_alpha in inv_cases
    assert case_beta not in inv_cases

    # 4. Other investigator (not assigned to either) sees 0 cases
    other_cases = Case.objects.for_user(other_investigator)
    assert other_cases.count() == 0

    # 5. Client Auditor Alpha sees Alpha Corp cases only
    alpha_cases = Case.objects.for_user(client_auditor_alpha)
    assert case_alpha in alpha_cases
    assert case_beta not in alpha_cases

    # 6. Client Auditor Beta sees Beta Corp cases only
    beta_cases = Case.objects.for_user(client_auditor_beta)
    assert case_beta in beta_cases
    assert case_alpha not in beta_cases


@pytest.mark.django_db
def test_anti_idor_case_detail_view(client, other_investigator, client_auditor_beta, case_alpha):
    """
    Verifies that direct object access (IDOR / BOLA) returns HTTP 404
    when an unauthorized user requests a valid case UUID directly.
    """
    # 1. Unassigned investigator tries to access Case Alpha
    client.force_login(other_investigator)
    session = client.session
    session['mfa_verified'] = True
    session.save()

    response = client.get(reverse('case_detail', kwargs={'case_id': case_alpha.id}))
    assert response.status_code == 404, "Expected HTTP 404 to prevent IDOR enumeration"

    # 2. Client Auditor Beta tries to access Case Alpha
    client.force_login(client_auditor_beta)
    session = client.session
    session['mfa_verified'] = True
    session.save()

    response = client.get(reverse('case_detail', kwargs={'case_id': case_alpha.id}))
    assert response.status_code == 404, "Expected HTTP 404 to isolate tenant boundary"


@pytest.mark.django_db
def test_client_auditor_cannot_create_case(client, client_auditor_alpha):
    """
    Verifies that external client auditors cannot initiate new cases (RBAC).
    """
    client.force_login(client_auditor_alpha)
    session = client.session
    session['mfa_verified'] = True
    session.save()

    response = client.get(reverse('case_create'))
    # Expect redirect or permission denied
    assert response.status_code == 302
    assert response.url == reverse('case_list')


@pytest.mark.django_db
def test_case_notes_client_visibility_filtering(client, investigator, client_auditor_alpha, case_alpha):
    """
    Verifies that internal investigative notes marked is_client_visible=False
    are never exposed to external Client Auditors.
    """
    # Create internal note
    CaseNote.objects.create(
        case=case_alpha,
        author=investigator,
        note="Internal: suspected zero-day vulnerability in gateway.",
        is_client_visible=False
    )
    # Create client-visible note
    CaseNote.objects.create(
        case=case_alpha,
        author=investigator,
        note="Client briefing: gateway port isolated at 14:00 UTC.",
        is_client_visible=True
    )

    # Client auditor accesses case detail
    client.force_login(client_auditor_alpha)
    session = client.session
    session['mfa_verified'] = True
    session.save()

    response = client.get(reverse('case_detail', kwargs={'case_id': case_alpha.id}))
    assert response.status_code == 200
    content = response.content.decode('utf-8')

    # Must contain client-visible note
    assert "Client briefing: gateway port isolated" in content
    # MUST NOT contain internal confidential note
    assert "Internal: suspected zero-day vulnerability" not in content
