"""
CaseVault Case Management & Tenancy Models
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Implements Case, CaseMembership, and CaseNote models with dual-layer
RBAC and ABAC (Object-Level Access Control) to eliminate IDOR vulnerabilities (ADR-0002).
"""

import uuid
from django.db import models
from django.conf import settings
from accounts.models import UserRole


class CaseClassification(models.TextChoices):
    COMMERCIAL = 'COMMERCIAL', 'Commercial Confidential'
    RESTRICTED = 'RESTRICTED', 'Client Restricted'
    CRITICAL_INFRASTRUCTURE = 'CRITICAL_INFRASTRUCTURE', 'Critical Infrastructure (Strict Isolation)'


class CaseStatus(models.TextChoices):
    ACTIVE = 'ACTIVE', 'Active Investigation'
    CONTAINED = 'CONTAINED', 'Incident Contained'
    ERADICATED = 'ERADICATED', 'Threat Eradicated'
    CLOSED = 'CLOSED', 'Investigation Closed'


class CaseQuerySet(models.QuerySet):
    """
    Custom QuerySet enforcing server-side object-level tenancy and RBAC.
    Guarantees that investigators and client auditors can only query cases
    they are explicitly authorized to access (neutralizing IDOR / BOLA).
    """

    def for_user(self, user):
        if not user or not user.is_authenticated:
            return self.none()

        # Firm Administrators have system-wide oversight
        if user.is_firm_admin:
            return self.all()

        # External Client Auditors: Strictly confined to their client organization tenancy
        if user.is_client_auditor:
            if not user.organization:
                return self.none()
            return self.filter(client_organization__iexact=user.organization)

        # Internal Investigators and Leads: Assigned cases or cases they lead
        return self.filter(
            models.Q(lead_investigator=user) |
            models.Q(memberships__user=user)
        ).distinct()


class Case(models.Model):
    """
    Forensic incident response case file.
    Identified by UUID4 to prevent sequential ID enumeration.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case_number = models.CharField(
        max_length=32,
        unique=True,
        help_text="Standard Northbridge case identifier (e.g. NCR-2026-001)"
    )
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    client_organization = models.CharField(
        max_length=128,
        db_index=True,
        help_text="Name of client organization under investigation"
    )
    classification = models.CharField(
        max_length=32,
        choices=CaseClassification.choices,
        default=CaseClassification.RESTRICTED
    )
    status = models.CharField(
        max_length=32,
        choices=CaseStatus.choices,
        default=CaseStatus.ACTIVE
    )
    lead_investigator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='led_cases',
        help_text="Lead forensic investigator responsible for case governance"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CaseQuerySet.as_manager()

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Incident Case'
        verbose_name_plural = 'Incident Cases'

    def __str__(self):
        return f"[{self.case_number}] {self.title} ({self.client_organization})"

    def can_user_view(self, user) -> bool:
        """Evaluates whether the specified user has object-level read permissions."""
        if not user or not user.is_authenticated:
            return False
        if user.is_firm_admin:
            return True
        if user.is_client_auditor:
            return self.client_organization.lower() == user.organization.lower()
        if self.lead_investigator == user:
            return True
        return self.memberships.filter(user=user).exists()

    def can_user_edit(self, user) -> bool:
        """Evaluates whether the specified user can alter case metadata or close the case."""
        if not user or not user.is_authenticated:
            return False
        if user.is_firm_admin:
            return True
        if user.is_client_auditor:
            return False
        return self.lead_investigator == user

    def can_user_upload_evidence(self, user) -> bool:
        """Only assigned investigators, the lead, or an admin may upload evidence."""
        return self.can_user_view(user) and not user.is_client_auditor


class CaseMembership(models.Model):
    """
    Explicit assignment mapping investigators to cases (ABAC membership).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='case_memberships')
    role_in_case = models.CharField(max_length=32, default='INVESTIGATOR')
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('case', 'user')
        verbose_name = 'Case Membership'
        verbose_name_plural = 'Case Memberships'

    def __str__(self):
        return f"{self.user.username} -> {self.case.case_number} ({self.role_in_case})"


class CaseNote(models.Model):
    """
    Chronological investigative notebook entries for forensic documentation.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='notes')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='case_notes')
    note = models.TextField()
    is_client_visible = models.BooleanField(
        default=False,
        help_text="If True, external client auditors assigned to this organization can view this note"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']
        verbose_name = 'Case Note'
        verbose_name_plural = 'Case Notes'

    def __str__(self):
        return f"Note by {self.author.username} on {self.case.case_number} at {self.created_at.isoformat()}"
