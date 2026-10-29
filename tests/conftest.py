"""
CaseVault Test Suite Configuration & Fixtures
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)
"""

import pytest
from accounts.models import CustomUser, UserRole
from cases.models import Case, CaseMembership, CaseClassification, CaseStatus


@pytest.fixture
def admin_user(db):
    user = CustomUser.objects.create_user(
        username='test_admin',
        password='TestPassword123!',
        role=UserRole.ADMIN,
        organization='Northbridge Cyber Response',
        is_staff=True,
        is_superuser=True
    )
    return user


@pytest.fixture
def lead_investigator(db):
    user = CustomUser.objects.create_user(
        username='test_lead',
        password='TestPassword123!',
        role=UserRole.LEAD_INVESTIGATOR,
        organization='Northbridge Cyber Response',
        is_staff=True
    )
    return user


@pytest.fixture
def investigator(db):
    user = CustomUser.objects.create_user(
        username='test_investigator',
        password='TestPassword123!',
        role=UserRole.INVESTIGATOR,
        organization='Northbridge Cyber Response'
    )
    return user


@pytest.fixture
def other_investigator(db):
    user = CustomUser.objects.create_user(
        username='other_investigator',
        password='TestPassword123!',
        role=UserRole.INVESTIGATOR,
        organization='Northbridge Cyber Response'
    )
    return user


@pytest.fixture
def client_auditor_alpha(db):
    user = CustomUser.objects.create_user(
        username='client_alpha',
        password='TestPassword123!',
        role=UserRole.CLIENT_AUDITOR,
        organization='Alpha Corp'
    )
    return user


@pytest.fixture
def client_auditor_beta(db):
    user = CustomUser.objects.create_user(
        username='client_beta',
        password='TestPassword123!',
        role=UserRole.CLIENT_AUDITOR,
        organization='Beta Corp'
    )
    return user


@pytest.fixture
def case_alpha(db, lead_investigator, investigator):
    case = Case.objects.create(
        case_number='NCR-TEST-001',
        title='Alpha Infiltration Test',
        client_organization='Alpha Corp',
        classification=CaseClassification.RESTRICTED,
        status=CaseStatus.ACTIVE,
        lead_investigator=lead_investigator
    )
    CaseMembership.objects.create(case=case, user=investigator, role_in_case='INVESTIGATOR')
    return case


@pytest.fixture
def case_beta(db, lead_investigator):
    case = Case.objects.create(
        case_number='NCR-TEST-002',
        title='Beta Database Exfiltration',
        client_organization='Beta Corp',
        classification=CaseClassification.CRITICAL_INFRASTRUCTURE,
        status=CaseStatus.ACTIVE,
        lead_investigator=lead_investigator
    )
    return case
