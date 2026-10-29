"""
CaseVault Forensic Evidence Models
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Implements EvidenceItem with cryptographic dual-hashing (SHA-256, SHA-512),
isolated storage filenames, and association to Incident Cases (ADR-0003, ADR-0004).
"""

import uuid
from pathlib import Path

from django.conf import settings
from django.db import models

from cases.models import Case


class EvidenceItem(models.Model):
    """
    Forensic evidence artifact stored with authenticated encryption at rest.
    The raw file is stored in an isolated filesystem location under a random UUID.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        related_name='evidence_items',
        help_text="Incident case to which this forensic evidence belongs"
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='uploaded_evidence'
    )
    original_filename = models.CharField(
        max_length=255,
        help_text="Sanitized original filename"
    )
    storage_filename = models.CharField(
        max_length=255,
        unique=True,
        help_text="Randomized UUID identifier on disk (outside web server document root)"
    )
    file_size_bytes = models.BigIntegerField(
        help_text="Size of the unencrypted evidence artifact in bytes"
    )
    mime_type = models.CharField(
        max_length=128,
        help_text="Validated MIME media type"
    )

    # Pre-encryption cryptographic hashes for forensic integrity verification
    sha256_hash = models.CharField(
        max_length=64,
        db_index=True,
        help_text="SHA-256 cryptographic hash of the plaintext evidence"
    )
    sha512_hash = models.CharField(
        max_length=128,
        help_text="SHA-512 cryptographic hash for dual-algorithm collision resistance"
    )

    description = models.CharField(
        max_length=255,
        blank=True,
        help_text="Brief description of the evidence artifact"
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-uploaded_at']
        verbose_name = 'Evidence Artifact'
        verbose_name_plural = 'Evidence Artifacts'

    def __str__(self):
        return f"{self.original_filename} ({self.case.case_number}) - SHA-256: {self.sha256_hash[:12]}..."

    @property
    def storage_path(self) -> Path:
        """Resolves the absolute path of the encrypted artifact on disk."""
        return settings.EVIDENCE_STORAGE_PATH / self.storage_filename
