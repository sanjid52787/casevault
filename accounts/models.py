"""
CaseVault Accounts & Identity Models
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Implements CustomUser with UUID primary key, RBAC roles, tenancy organization scoping,
brute-force account lockout tracking, and RFC 6238 TOTP Multi-Factor Authentication.
"""

import uuid
from datetime import timedelta

import pyotp
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class UserRole(models.TextChoices):
    ADMIN = 'ADMIN', 'Firm Administrator'
    LEAD_INVESTIGATOR = 'LEAD_INVESTIGATOR', 'Lead Investigator'
    INVESTIGATOR = 'INVESTIGATOR', 'Forensic Investigator'
    CLIENT_AUDITOR = 'CLIENT_AUDITOR', 'Client Auditor'


class CustomUser(AbstractUser):
    """
    Hardened User model replacing Django's default User.
    Enforces UUID primary keys, role-based access control (RBAC),
    tenancy scoping for client auditors, account lockout tracking,
    and TOTP MFA state.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.CharField(
        max_length=24,
        choices=UserRole.choices,
        default=UserRole.INVESTIGATOR,
        help_text="Role determining access level within Northbridge Cyber Response"
    )
    organization = models.CharField(
        max_length=128,
        blank=True,
        default='Northbridge Cyber Response',
        help_text="Organization name used for multi-tenant isolation of client auditors"
    )

    # Multi-Factor Authentication fields (RFC 6238)
    is_mfa_enabled = models.BooleanField(
        default=False,
        help_text="Designates whether this user has enrolled and verified a TOTP second factor"
    )
    totp_secret = models.CharField(
        max_length=64,
        blank=True,
        help_text="Base32 TOTP secret key"
    )

    # Brute-force defence & account lockout tracking
    failed_login_attempts = models.PositiveIntegerField(
        default=0,
        help_text="Consecutive failed login counter for rate limiting"
    )
    locked_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp until which the account is temporarily locked out"
    )

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['username']

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"

    @property
    def is_firm_admin(self) -> bool:
        return self.role == UserRole.ADMIN or self.is_superuser

    @property
    def is_lead_investigator(self) -> bool:
        return self.role in (UserRole.ADMIN, UserRole.LEAD_INVESTIGATOR) or self.is_superuser

    @property
    def is_client_auditor(self) -> bool:
        return self.role == UserRole.CLIENT_AUDITOR

    def is_account_locked(self) -> bool:
        """Checks if the account is currently locked due to excessive failed attempts."""
        if self.locked_until and self.locked_until > timezone.now():
            return True
        return False

    def record_failed_login(self, max_attempts: int = 5, lockout_minutes: int = 15):
        """
        Increments failed attempt counter; triggers temporary lockout when threshold is reached.
        """
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_attempts:
            self.locked_until = timezone.now() + timedelta(minutes=lockout_minutes)
        self.save(update_fields=['failed_login_attempts', 'locked_until'])

    def reset_failed_logins(self):
        """Clears lockout state upon successful authentication."""
        if self.failed_login_attempts > 0 or self.locked_until is not None:
            self.failed_login_attempts = 0
            self.locked_until = None
            self.save(update_fields=['failed_login_attempts', 'locked_until'])

    def generate_totp_secret(self) -> str:
        """Generates a new RFC 6238 base32 secret."""
        secret = pyotp.random_base32()
        self.totp_secret = secret
        self.save(update_fields=['totp_secret'])
        return secret

    def get_totp_uri(self) -> str:
        """Generates an otpauth:// provisioning URI for authenticator applications."""
        if not self.totp_secret:
            self.generate_totp_secret()
        totp = pyotp.TOTP(self.totp_secret)
        return totp.provisioning_uri(
            name=self.username,
            issuer_name="Northbridge CaseVault"
        )

    def verify_totp(self, token: str) -> bool:
        """
        Validates a user-supplied 6-digit TOTP token against the stored secret.
        Allows valid_window=1 (30s clock skew forward/backward).
        """
        if not self.totp_secret or not token:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        # valid_window=1 allows for +/- 30 seconds drift
        return bool(totp.verify(str(token).strip(), valid_window=1))
