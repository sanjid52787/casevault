"""
CaseVault Audit Service
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Handles atomic insertion into the tamper-evident HMAC audit chain
and verification of full audit trail integrity.
"""

import json
import logging

from django.conf import settings
from django.db import transaction

from audit.models import GENESIS_HASH, AuditLog
from core.utils import get_client_ip

logger = logging.getLogger('casevault.audit')


def get_audit_hmac_key() -> str:
    key = getattr(settings, 'CASEVAULT_AUDIT_HMAC_KEY', None)
    if not key:
        # Fallback to SECRET_KEY if audit-specific key not configured
        key = settings.SECRET_KEY
    return str(key)


def log_security_event(
    action: str,
    actor=None,
    request=None,
    target_model: str = '',
    target_id: str = '',
    details: dict | None = None
) -> AuditLog:
    """
    Atomically appends a new audit record to the cryptographic chain.
    Locks the latest audit record to ensure correct sequential chaining.
    """
    if details is None:
        details = {}

    # Extract actor & IP safely
    actor_obj = None
    actor_username = 'SYSTEM'
    ip_address = '127.0.0.1'

    if request:
        ip_address = get_client_ip(request)
        if hasattr(request, 'user') and request.user.is_authenticated:
            actor_obj = request.user
            actor_username = request.user.username
    elif actor:
        actor_obj = actor
        actor_username = getattr(actor, 'username', str(actor))

    hmac_key = get_audit_hmac_key()
    details_clean = {k: v for k, v in details.items() if not any(
        s in k.lower() for s in ('password', 'token', 'secret', 'key')
    )}
    details_json = json.dumps(details_clean, sort_keys=True)

    with transaction.atomic():
        # Select the last record with row locking to ensure deterministic sequential chaining
        last_entry = AuditLog.objects.select_for_update().order_by('-id').first()
        previous_hash = last_entry.current_hash if last_entry else GENESIS_HASH

        entry = AuditLog(
            actor=actor_obj,
            actor_username=actor_username,
            ip_address=ip_address,
            action=action,
            target_model=target_model,
            target_id=str(target_id),
            details=details_clean,
            previous_hash=previous_hash,
        )

        # Calculate current hash over canonical fields
        entry.current_hash = AuditLog.calculate_entry_hmac(
            key=hmac_key,
            previous_hash=previous_hash,
            timestamp_iso=entry.timestamp.isoformat(),
            actor_id=str(actor_obj.id) if actor_obj else '',
            action=action,
            target_model=target_model,
            target_id=str(target_id),
            details_json=details_json,
        )
        entry.save()

    return entry


def verify_audit_chain() -> tuple[bool, int, str]:
    """
    Traverses the entire audit log from genesis to head, recalculating
    and verifying each HMAC digest.

    Returns:
        (is_valid: bool, total_or_failed_id: int, message: str)
    """
    entries = list(AuditLog.objects.order_by('id'))
    if not entries:
        return True, 0, "Audit ledger is empty (genesis state)."

    hmac_key = get_audit_hmac_key()
    expected_previous_hash = GENESIS_HASH

    for _index, entry in enumerate(entries):
        # 1. Verify link to previous entry
        if entry.previous_hash != expected_previous_hash:
            msg = (
                f"Tampering detected at record ID {entry.id}: previous_hash mismatch! "
                f"Expected '{expected_previous_hash}', got '{entry.previous_hash}'."
            )
            logger.error(msg)
            return False, entry.id, msg

        # 2. Recalculate and verify current hash
        details_json = json.dumps(entry.details, sort_keys=True)
        actor_id_str = str(entry.actor.id) if entry.actor else ''
        expected_current = AuditLog.calculate_entry_hmac(
            key=hmac_key,
            previous_hash=expected_previous_hash,
            timestamp_iso=entry.timestamp.isoformat(),
            actor_id=actor_id_str,
            action=entry.action,
            target_model=entry.target_model,
            target_id=entry.target_id,
            details_json=details_json,
        )

        if entry.current_hash != expected_current:
            msg = (
                f"Tampering detected at record ID {entry.id}: payload modified! "
                f"Computed hash '{expected_current}', stored hash '{entry.current_hash}'."
            )
            logger.error(msg)
            return False, entry.id, msg

        expected_previous_hash = entry.current_hash

    return True, len(entries), f"Cryptographic audit chain verified: {len(entries)} records intact."

