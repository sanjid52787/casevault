"""
Unit & Integration Tests: Evidence Vault Cryptography & Safe File Handling
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)
"""

import uuid
import pytest
from pathlib import Path
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ValidationError
from django.conf import settings
from cryptography.fernet import InvalidToken
from vault.models import EvidenceItem
from vault.validators import validate_inert_evidence_file, sanitize_filename
from vault.crypto import (
    encrypt_and_store_evidence,
    decrypt_and_verify_evidence,
    get_fernet_cipher
)


@pytest.mark.django_db
def test_filename_sanitization_and_path_traversal():
    """
    Verifies that filenames are strictly sanitized and path traversal attacks are stripped.
    """
    # Path traversal attempts
    assert sanitize_filename('../../etc/passwd.log') == 'passwd.log'
    assert sanitize_filename('..\\..\\windows\\system32\\cmd.log') == 'cmd.log'
    
    # Dangerous special characters (without directory slashes)
    assert sanitize_filename('evidence;rm -rf;.txt') == 'evidence_rm_-rf.txt'
    assert sanitize_filename('safe_artifact.log') == 'safe_artifact.log'


def test_file_validation_rejections():
    """
    Tests strict rejection of executable files, scripts, SVGs, and disguised payloads.
    """
    # 1. Reject prohibited extensions (.exe, .php, .sh, .py, .svg)
    with pytest.raises(ValidationError) as exc1:
        f = SimpleUploadedFile("malware.exe", b"MZ\x90\x00\x03\x00")
        validate_inert_evidence_file(f)
    assert "Prohibited file extension '.exe'" in str(exc1.value)

    with pytest.raises(ValidationError) as exc2:
        f = SimpleUploadedFile("shell.php", b"<?php echo 'pwned'; ?>")
        validate_inert_evidence_file(f)
    assert "Prohibited file extension '.php'" in str(exc2.value)

    with pytest.raises(ValidationError) as exc3:
        f = SimpleUploadedFile("vector.svg", b"<svg onload=alert(1)>")
        validate_inert_evidence_file(f)
    assert "Prohibited file extension '.svg'" in str(exc3.value)

    # 2. Reject disguised HTML payload pretending to be a PDF
    with pytest.raises(ValidationError) as exc4:
        disguised_pdf = SimpleUploadedFile("report.pdf", b"<html><body><script>alert(1)</script></body></html>")
        validate_inert_evidence_file(disguised_pdf)
    assert "does not contain valid application/pdf magic bytes" in str(exc4.value) or "dangerous executable signature" in str(exc4.value)


@pytest.mark.django_db
def test_evidence_authenticated_encryption_and_tamper_detection(tmp_path):
    """
    Tests authenticated symmetric encryption (Fernet) and bit-level tamper detection (ADR-0003).
    """
    plaintext = b"FORENSIC_MEMORY_DUMP_SAMPLE_INERT_CONTENT_123456789"
    upload = SimpleUploadedFile("memory_strings.txt", plaintext)
    storage_path = tmp_path / "test_evidence.enc"

    # Step 1: Encrypt and store
    sha256, sha512, byte_size = encrypt_and_store_evidence(upload, storage_path)
    assert byte_size == len(plaintext)
    assert len(sha256) == 64
    assert len(sha512) == 128

    # Step 2: Ensure file on disk is NOT plaintext (encrypted at rest)
    with open(storage_path, 'rb') as f:
        stored_bytes = f.read()
    assert stored_bytes != plaintext, "Evidence must never be stored in plaintext"

    # Step 3: Decrypt and verify hash
    decrypted = decrypt_and_verify_evidence(storage_path, sha256)
    assert decrypted == plaintext

    # Step 4: TAMPER DETECTION TEST
    # Modify a single byte of ciphertext to simulate disk tampering
    tampered_bytes = bytearray(stored_bytes)
    tampered_bytes[20] ^= 0xFF  # Flip bits
    with open(storage_path, 'wb') as f:
        f.write(tampered_bytes)

    # Decryption must raise InvalidToken due to HMAC mismatch
    with pytest.raises(InvalidToken):
        decrypt_and_verify_evidence(storage_path, sha256)


@pytest.mark.django_db
def test_evidence_sandboxed_download_headers(client, investigator, case_alpha, tmp_path, monkeypatch):
    """
    Verifies that evidence downloads enforce sandbox CSP and attachment headers (ADR-0004).
    """
    monkeypatch.setattr(settings, 'EVIDENCE_STORAGE_PATH', tmp_path)

    plaintext = b"LOG_LINE: SYN scan detected from 10.0.0.1"
    upload = SimpleUploadedFile("firewall.log", plaintext)
    dest_path = tmp_path / "test_fw.enc"
    sha256, sha512, size = encrypt_and_store_evidence(upload, dest_path)

    item = EvidenceItem.objects.create(
        case=case_alpha,
        uploaded_by=investigator,
        original_filename="firewall.log",
        storage_filename="test_fw.enc",
        file_size_bytes=size,
        mime_type="text/plain",
        sha256_hash=sha256,
        sha512_hash=sha512
    )

    client.force_login(investigator)
    session = client.session
    session['mfa_verified'] = True
    session.save()

    url = reverse('evidence_download', kwargs={'case_id': case_alpha.id, 'evidence_id': item.id})
    response = client.get(url)

    assert response.status_code == 200
    assert response['Content-Disposition'] == 'attachment; filename="firewall.log"'
    assert response['Content-Security-Policy'] == "sandbox; default-src 'none';"
    assert response['X-Content-Type-Options'] == 'nosniff'
    assert response.content == plaintext
