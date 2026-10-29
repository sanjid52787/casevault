"""
CaseVault Tamper-Evident Audit Subsystem
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Implements cryptographically chained audit logging (ADR-0003).
Each entry computes an HMAC-SHA256 bound to the previous entry,
guaranteeing forensic non-repudiation and immediate detection of
log manipulation, record deletion, or unauthorized insertion.
"""

import hashlib
import hmac

from django.conf import settings
from django.db import models
from django.utils import timezone

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


class AuditAction(models.TextChoices):
    # Authentication events
    LOGIN_SUCCESS = 'LOGIN_SUCCESS', 'Successful Login'
    LOGIN_FAILED = 'LOGIN_FAILED', 'Failed Login Attempt'
    ACCOUNT_LOCKED = 'ACCOUNT_LOCKED', 'Account Locked Out'
    LOGOUT = 'LOGOUT', 'User Logout'
    MFA_SETUP = 'MFA_SETUP', 'MFA Enrolled'
    MFA_VERIFIED = 'MFA_VERIFIED', 'MFA Challenge Verified'
    MFA_FAILED = 'MFA_FAILED', 'MFA Challenge Failed'

    # Case management events
    CASE_CREATED = 'CASE_CREATED', 'Incident Case Created'
    CASE_VIEWED = 'CASE_VIEWED', 'Incident Case Accessed'
    CASE_UPDATED = 'CASE_UPDATED', 'Incident Case Updated'
    CASE_MEMBER_ADDED = 'CASE_MEMBER_ADDED', 'Investigator Assigned to Case'
    CASE_MEMBER_REMOVED = 'CASE_MEMBER_REMOVED', 'Investigator Removed from Case'
    NOTE_ADDED = 'NOTE_ADDED', 'Investigative Note Added'

    # Evidence vault events
    EVIDENCE_UPLOADED = 'EVIDENCE_UPLOADED', 'Evidence Ingested and Encrypted'
    EVIDENCE_DOWNLOADED = 'EVIDENCE_DOWNLOADED', 'Evidence Decrypted and Downloaded'
    EVIDENCE_UPLOAD_REJECTED = 'EVIDENCE_UPLOAD_REJECTED', 'Evidence File Upload Rejected'
    EVIDENCE_TAMPER_DETECTED = 'EVIDENCE_TAMPER_DETECTED', 'Evidence Integrity Check Failed'

    # Security & access control events
    ACCESS_DENIED = 'ACCESS_DENIED', 'Unauthorized Access Blocked (RBAC/ABAC)'
    TAMPER_CHECK_EXECUTED = 'TAMPER_CHECK_EXECUTED', 'Audit Chain Integrity Audit Executed'


class AuditLog(models.Model):
    """
    Sequential, tamper-evident audit record.
    Uses sequential integer IDs and HMAC hash-chaining to detect
    any post-hoc database tampering or record deletion.
    """
    id = models.BigAutoField(primary_key=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_events'
    )
    actor_username = models.CharField(max_length=150, blank=True)
    ip_address = models.CharField(max_length=45, blank=True)
    action = models.CharField(max_length=48, choices=AuditAction.choices, db_index=True)
    target_model = models.CharField(max_length=64, blank=True)
    target_id = models.CharField(max_length=64, blank=True)
    details = models.JSONField(default=dict, blank=True)

    # Cryptographic Chain Hashes
    previous_hash = models.CharField(max_length=64, help_text="HMAC digest of the preceding audit record")
    current_hash = models.CharField(max_length=64, help_text="HMAC digest of this record binding to previous_hash")

    class Meta:
        ordering = ['id']
        verbose_name = 'Audit Log Entry'
        verbose_name_plural = 'Audit Log Entries'

    def __str__(self):
        return f"[{self.timestamp.isoformat()}] {self.action} by {self.actor_username or 'System'} (ID: {self.id})"

    @staticmethod
    def calculate_entry_hmac(key: str, previous_hash: str, timestamp_iso: str,
                             actor_id: str, action: str, target_model: str,
                             target_id: str, details_json: str) -> str:
        """
        Pure function computing the HMAC-SHA256 digest over the canonical string representation.
        """
        message = f"{previous_hash}|{timestamp_iso}|{actor_id}|{action}|{target_model}|{target_id}|{details_json}"
        return hmac.new(
            key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
