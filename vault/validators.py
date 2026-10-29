"""
CaseVault Safe File Handling & MIME Magic Byte Inspection
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Implements strict extension whitelisting, filename sanitization,
magic byte signature verification, and executable rejection (ADR-0004).
"""

import re
import os
from typing import Tuple
from django.core.exceptions import ValidationError

# Strict extension whitelist for forensic artifacts (executable extensions prohibited)
ALLOWED_EXTENSIONS = {
    '.txt': 'text/plain',
    '.log': 'text/plain',
    '.pdf': 'application/pdf',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.json': 'application/json',
    '.csv': 'text/csv',
    '.pcap': 'application/vnd.tcpdump.pcap',
}

# Signatures for dangerous executable formats that must be rejected unconditionally
DISALLOWED_SIGNATURES = [
    (b'MZ', 'Windows PE / EXE / DLL executable'),
    (b'\x7fELF', 'Linux ELF executable'),
    (b'<?php', 'PHP server-side script'),
    (b'<script', 'HTML / JavaScript script payload'),
    (b'#!/bin/', 'Unix shell script'),
    (b'#!/usr/', 'Unix shell script'),
    (b'<svg', 'Scalable Vector Graphics (SVG XSS risk)'),
]

# Magic byte signatures for verified formats
MAGIC_BYTE_SIGNATURES = {
    'application/pdf': [b'%PDF-'],
    'image/png': [b'\x89PNG\r\n\x1a\n'],
    'image/jpeg': [b'\xff\xd8\xff'],
    'application/vnd.tcpdump.pcap': [
        b'\xa1\xb2\xc3\xd4',  # standard pcap microsecond
        b'\xd4\xc3\xb2\xa1',  # swapped pcap
        b'\xa1\xb2\x3c\x4d',  # nanosecond pcap
        b'\x0a\x0d\x0d\x0a',  # pcapng
    ],
}


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes user-provided filenames to prevent directory traversal and injection.
    Strips directory separators, removes non-alphanumeric characters except safe symbols.
    """
    # 1. Take only the basename, discarding any path traversal prefixes
    basename = os.path.basename(filename).strip()
    
    # 2. Split extension and root
    root, ext = os.path.splitext(basename)
    
    # 3. Sanitize root to safe characters
    sanitized_root = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', root)
    if not sanitized_root:
        sanitized_root = "evidence_artifact"

    # Truncate to maximum 100 characters to prevent filesystem errors
    sanitized_root = sanitized_root[:100]
    clean_ext = ext.lower()
    
    return f"{sanitized_root}{clean_ext}"


def validate_inert_evidence_file(uploaded_file) -> Tuple[str, str]:
    """
    Validates uploaded evidence file:
    1. Checks file size against maximum limit.
    2. Validates filename and whitelisted extension.
    3. Reads header bytes to inspect magic signatures.
    4. Prohibits executable markers, scripts, and SVG vectors.

    Returns:
        (sanitized_filename: str, validated_mime: str)
    
    Raises:
        ValidationError: if the file violates any security rule.
    """
    raw_filename = uploaded_file.name
    if not raw_filename:
        raise ValidationError("Missing filename.")

    sanitized = sanitize_filename(raw_filename)
    _, ext = os.path.splitext(sanitized)
    ext_lower = ext.lower()

    if ext_lower not in ALLOWED_EXTENSIONS:
        allowed_list = ", ".join(sorted(ALLOWED_EXTENSIONS.keys()))
        raise ValidationError(
            f"Prohibited file extension '{ext_lower}'. "
            f"CaseVault accepts only inert forensic artifact formats: {allowed_list}"
        )

    expected_mime = ALLOWED_EXTENSIONS[ext_lower]

    # Read header bytes for magic inspection (first 512 bytes)
    header = uploaded_file.read(512)
    uploaded_file.seek(0)

    if not header:
        raise ValidationError("Uploaded file is empty (0 bytes).")

    # Reject dangerous executable signatures
    for sig, desc in DISALLOWED_SIGNATURES:
        if header.startswith(sig) or (sig in header[:128] and sig in (b'<?php', b'<script', b'<svg')):
            raise ValidationError(
                f"File content rejected: detected dangerous executable signature ({desc})."
            )

    # Validate magic bytes for binary formats with known signatures
    if expected_mime in MAGIC_BYTE_SIGNATURES:
        signatures = MAGIC_BYTE_SIGNATURES[expected_mime]
        if not any(header.startswith(sig) for sig in signatures):
            raise ValidationError(
                f"File content mismatch: the uploaded file does not contain valid {expected_mime} magic bytes."
            )

    # For text-based formats (.txt, .log, .json, .csv), ensure valid UTF-8/ASCII without null bytes
    if expected_mime in ('text/plain', 'application/json', 'text/csv'):
        if b'\x00' in header:
            raise ValidationError("Text evidence format contains null bytes or binary characters.")
        try:
            header.decode('utf-8')
        except UnicodeDecodeError:
            raise ValidationError("Text evidence must be valid UTF-8 encoded text.")

    return sanitized, expected_mime
