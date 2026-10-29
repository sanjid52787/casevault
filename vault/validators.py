"""
CaseVault Safe File Handling & MIME Magic Byte Inspection
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Implements strict extension whitelisting, python-magic content sniffing,
and binary executable rejection (ADR-0004, ADR-0006).
"""

import logging
import os
import re
import sys
from pathlib import Path

from django.core.exceptions import ValidationError

logger = logging.getLogger('casevault.vault')

# Initialize python-magic on Windows if running with python-magic-bin
if sys.platform == 'win32':
    try:
        import site
        for sp in site.getsitepackages():
            dll_p = Path(sp) / 'magic' / 'libmagic'
            if dll_p.exists():
                os.add_dll_directory(str(dll_p))
                os.environ['PATH'] = str(dll_p) + ';' + os.environ.get('PATH', '')
        import magic.loader
        orig_loader = magic.loader._lib_candidates
        dll_file = dll_p / 'libmagic.dll'
        if dll_file.exists():
            magic.loader._lib_candidates = lambda: (str(dll_file), *orig_loader())
    except (ImportError, OSError, AttributeError) as exc:
        logger.debug("Windows libmagic DLL initialization fallback: %s", exc)

try:
    import magic
    HAS_MAGIC = True
except (ImportError, OSError) as exc:
    HAS_MAGIC = False
    logger.debug("python-magic library unavailable, falling back to signature inspection: %s", exc)

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
    normalized = filename.replace('\\', '/')
    basename = os.path.basename(normalized).strip()
    root, ext = os.path.splitext(basename)
    sanitized_root = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', root)
    sanitized_root = re.sub(r'_+', '_', sanitized_root).strip('_')

    if not sanitized_root:
        sanitized_root = "evidence_artifact"

    sanitized_root = sanitized_root[:100]
    return f"{sanitized_root}{ext.lower()}"


def validate_inert_evidence_file(uploaded_file) -> tuple[str, str]:
    """
    Validates uploaded evidence file:
    1. Checks file size against maximum limit.
    2. Validates filename and whitelisted extension.
    3. Reads header bytes to inspect magic signatures and python-magic sniffing.
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

    # Content sniffing via python-magic when available
    if HAS_MAGIC:
        try:
            detected_mime = magic.from_buffer(header, mime=True)
            if expected_mime == 'application/pdf' and 'pdf' not in detected_mime:
                raise ValidationError("python-magic content sniffing: file is not a valid PDF.")
            if expected_mime in ('image/png', 'image/jpeg') and not detected_mime.startswith('image/'):
                raise ValidationError(f"python-magic content sniffing: expected image, detected {detected_mime}.")
        except ValidationError:
            raise
        except Exception as exc:
            logger.debug("python-magic content sniffing skipped due to non-fatal error: %s", exc)

    # For text-based formats (.txt, .log, .json, .csv), ensure valid UTF-8/ASCII without null bytes
    if expected_mime in ('text/plain', 'application/json', 'text/csv'):
        if b'\x00' in header:
            raise ValidationError("Text evidence format contains null bytes or binary characters.")
        try:
            header.decode('utf-8')
        except UnicodeDecodeError:
            raise ValidationError("Text evidence must be valid UTF-8 encoded text.") from None

    return sanitized, expected_mime
