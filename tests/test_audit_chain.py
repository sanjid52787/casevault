"""
Unit Tests: Tamper-Evident HMAC Hash Chained Audit Subsystem
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)
"""

import pytest
from audit.models import AuditLog, AuditAction, GENESIS_HASH
from audit.service import log_security_event, verify_audit_chain


@pytest.mark.django_db
def test_audit_hash_chaining_and_tamper_detection(lead_investigator):
    """
    Verifies that:
    1. Events are chained via HMAC-SHA256 digests.
    2. An intact chain validates successfully.
    3. Row modification (tampering) is mathematically detected.
    4. Row deletion is mathematically detected.
    """
    AuditLog.objects.all().delete()  # Start from fresh state

    # Step 1: Log three distinct events
    e1 = log_security_event(
        action=AuditAction.LOGIN_SUCCESS,
        actor=lead_investigator,
        details={'session': 'test1'}
    )
    assert e1.previous_hash == GENESIS_HASH
    assert len(e1.current_hash) == 64

    e2 = log_security_event(
        action=AuditAction.CASE_CREATED,
        actor=lead_investigator,
        target_model='Case',
        target_id='uuid-test-123',
        details={'case_number': 'NCR-TEST-001'}
    )
    assert e2.previous_hash == e1.current_hash

    e3 = log_security_event(
        action=AuditAction.EVIDENCE_UPLOADED,
        actor=lead_investigator,
        target_model='EvidenceItem',
        target_id='uuid-test-456',
        details={'filename': 'log.txt'}
    )
    assert e3.previous_hash == e2.current_hash

    # Step 2: Verify intact chain
    is_valid, count, msg = verify_audit_chain()
    assert is_valid is True
    assert count == 3
    assert "verified" in msg.lower()

    # Step 3: TAMPER TEST 1 - Modify an existing entry
    # Rogue actor modifies details of e2 to conceal their actions
    e2.details = {'case_number': 'TAMPERED_CONTENT'}
    e2.save(update_fields=['details'])

    is_valid, failed_id, msg = verify_audit_chain()
    assert is_valid is False
    assert failed_id == e2.id
    assert "tampering detected" in msg.lower()

    # Revert modification for deletion test
    e2.details = {'case_number': 'NCR-TEST-001'}
    e2.save(update_fields=['details'])
    assert verify_audit_chain()[0] is True

    # Step 4: TAMPER TEST 2 - Delete an intermediate row
    # Rogue actor deletes e2 entirely
    e2.delete()

    is_valid, failed_id, msg = verify_audit_chain()
    assert is_valid is False
    assert failed_id == e3.id
    assert "previous_hash mismatch" in msg.lower()
