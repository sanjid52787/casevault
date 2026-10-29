"""
CaseVault Forensic Cryptography Subsystem
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Implements authenticated symmetric encryption at rest using Python's
cryptography library (Fernet: AES-128-CBC with HMAC-SHA256 authenticated envelope)
and pre-encryption cryptographic dual-hashing (SHA-256 and SHA-512) (ADR-0003).
"""

import hashlib
import logging
from pathlib import Path

from cryptography.fernet import Fernet
from django.conf import settings

logger = logging.getLogger('casevault.crypto')


def get_fernet_cipher() -> Fernet:
    """
    Initializes a Fernet cipher instance using the configured master key.
    """
    key = getattr(settings, 'CASEVAULT_EVIDENCE_KEY', None)
    if not key:
        raise ValueError(
            "CRITICAL SECURITY CONFIGURATION ERROR: CASEVAULT_EVIDENCE_KEY is not defined in environment!"
        )
    if isinstance(key, str):
        key = key.encode('utf-8')
    return Fernet(key)


def encrypt_and_store_evidence(uploaded_file, destination_path: Path) -> tuple[str, str, int]:
    """
    Processes an uploaded evidence file:
    1. Computes pre-encryption SHA-256 and SHA-512 hashes.
    2. Encrypts the payload using authenticated Fernet encryption.
    3. Writes the ciphertext to the destination path on disk.

    Returns:
        (sha256_hex: str, sha512_hex: str, original_byte_size: int)
    """
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    cipher = get_fernet_cipher()

    # Read uploaded file contents in memory (bounded to 25 MB max by settings)
    uploaded_file.seek(0)
    raw_bytes = uploaded_file.read()
    byte_count = len(raw_bytes)

    # Compute cryptographic digests on plaintext stream
    sha256.update(raw_bytes)
    sha512.update(raw_bytes)

    # Perform authenticated symmetric encryption
    encrypted_bytes = cipher.encrypt(raw_bytes)

    # Ensure parent directory exists and write ciphertext
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    with open(destination_path, 'wb') as f:
        f.write(encrypted_bytes)

    return sha256.hexdigest(), sha512.hexdigest(), byte_count


def decrypt_and_verify_evidence(storage_path: Path, expected_sha256: str) -> bytes:
    """
    Reads an encrypted evidence file from disk, decrypts with authenticated integrity checks,
    and re-verifies the SHA-256 hash against the stored database record.

    Returns:
        plaintext_bytes: bytes

    Raises:
        InvalidToken: if the encrypted ciphertext was modified on disk (HMAC mismatch).
        ValueError: if the decrypted plaintext does not match the original SHA-256 record.
    """
    if not storage_path.exists():
        raise FileNotFoundError(f"Evidence file missing from disk: {storage_path.name}")

    cipher = get_fernet_cipher()

    with open(storage_path, 'rb') as f:
        ciphertext = f.read()

    # Fernet.decrypt verifies the embedded HMAC-SHA256 signature; raises InvalidToken on tamper
    plaintext = cipher.decrypt(ciphertext)

    # Re-verify cryptographic integrity against stored metadata
    computed_sha256 = hashlib.sha256(plaintext).hexdigest()
    if computed_sha256.lower() != expected_sha256.lower():
        msg = (
            f"EVIDENCE TAMPER DETECTED: Computed plaintext hash '{computed_sha256}' "
            f"does not match registered hash '{expected_sha256}'!"
        )
        logger.critical(msg)
        raise ValueError(msg)

    return plaintext

