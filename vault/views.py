"""
CaseVault Evidence Vault Views
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Handles authenticated evidence ingestion with streaming encryption,
pre-storage dual hashing, safe file inspection, and sandboxed downloads (ADR-0003, ADR-0004).
"""

import uuid
from pathlib import Path
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, Http404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.core.exceptions import ValidationError
from cases.models import Case
from vault.models import EvidenceItem
from vault.validators import validate_inert_evidence_file
from vault.crypto import encrypt_and_store_evidence, decrypt_and_verify_evidence
from audit.service import log_security_event
from audit.models import AuditAction


@login_required
@require_http_methods(["GET", "POST"])
def evidence_upload_view(request, case_id):
    """
    Ingests an inert evidence artifact:
    1. Enforces object-level tenancy checks on the parent case.
    2. Prohibits external client auditors from uploading files.
    3. Validates file extension against whitelist and inspects magic bytes.
    4. Computes pre-encryption SHA-256 and SHA-512 hashes.
    5. Performs authenticated symmetric encryption at rest.
    6. Appends chained audit record.
    """
    case = get_object_or_404(Case.objects.for_user(request.user), id=case_id)

    if not case.can_user_upload_evidence(request.user):
        log_security_event(
            action=AuditAction.ACCESS_DENIED,
            actor=request.user,
            request=request,
            details={'reason': 'evidence_upload_unauthorized_role'}
        )
        messages.error(request, "Permission Denied: You do not possess evidence upload permissions for this case.")
        return redirect('case_detail', case_id=case.id)

    if request.method == 'POST':
        uploaded_file = request.FILES.get('evidence_file')
        description = request.POST.get('description', '').strip()

        if not uploaded_file:
            messages.error(request, "Please select a file to upload.")
            return render(request, 'vault/evidence_upload.html', {'case': case})

        # Step 1: Validate file safety, extension whitelist, and magic bytes
        try:
            sanitized_name, mime_type = validate_inert_evidence_file(uploaded_file)
        except ValidationError as err:
            log_security_event(
                action=AuditAction.EVIDENCE_UPLOAD_REJECTED,
                actor=request.user,
                request=request,
                target_model='Case',
                target_id=str(case.id),
                details={'filename': uploaded_file.name, 'error': str(err)}
            )
            messages.error(request, f"File Rejected: {err.message if hasattr(err, 'message') else str(err)}")
            return render(request, 'vault/evidence_upload.html', {'case': case})

        # Step 2: Generate random storage filename outside document root
        storage_filename = f"{uuid.uuid4().hex}.enc"
        dest_path = settings.EVIDENCE_STORAGE_PATH / storage_filename

        # Step 3: Compute pre-encryption hashes and stream authenticated ciphertext to disk
        try:
            sha256_hash, sha512_hash, byte_size = encrypt_and_store_evidence(uploaded_file, dest_path)
        except Exception as exc:
            messages.error(request, f"Cryptographic storage failed: {str(exc)}")
            return render(request, 'vault/evidence_upload.html', {'case': case})

        # Step 4: Record metadata in database
        evidence = EvidenceItem.objects.create(
            case=case,
            uploaded_by=request.user,
            original_filename=sanitized_name,
            storage_filename=storage_filename,
            file_size_bytes=byte_size,
            mime_type=mime_type,
            sha256_hash=sha256_hash,
            sha512_hash=sha512_hash,
            description=description,
        )

        log_security_event(
            action=AuditAction.EVIDENCE_UPLOADED,
            actor=request.user,
            request=request,
            target_model='EvidenceItem',
            target_id=str(evidence.id),
            details={
                'case_number': case.case_number,
                'filename': evidence.original_filename,
                'sha256': evidence.sha256_hash,
                'size_bytes': evidence.file_size_bytes,
            }
        )

        messages.success(request, f"Evidence artifact '{evidence.original_filename}' safely encrypted and ingested.")
        return redirect('case_detail', case_id=case.id)

    return render(request, 'vault/evidence_upload.html', {'case': case})


@login_required
@require_http_methods(["GET"])
def evidence_download_view(request, case_id, evidence_id):
    """
    Retrieves and decrypts an evidence artifact:
    1. Validates user case access (ABAC check).
    2. Decrypts ciphertext with authenticated HMAC verification.
    3. Re-verifies decrypted plaintext SHA-256 against stored database hash.
    4. Delivers file with forced attachment disposition and sandboxed CSP headers.
    """
    case = get_object_or_404(Case.objects.for_user(request.user), id=case_id)
    evidence = get_object_or_404(case.evidence_items, id=evidence_id)

    try:
        plaintext_bytes = decrypt_and_verify_evidence(
            storage_path=evidence.storage_path,
            expected_sha256=evidence.sha256_hash
        )
    except ValueError as val_err:
        # Cryptographic hash verification failed (evidence tampering)
        log_security_event(
            action=AuditAction.EVIDENCE_TAMPER_DETECTED,
            actor=request.user,
            request=request,
            target_model='EvidenceItem',
            target_id=str(evidence.id),
            details={'error': str(val_err), 'filename': evidence.original_filename}
        )
        messages.error(request, "CRITICAL SECURITY ALERT: Evidence integrity verification failed. Download blocked.")
        return redirect('case_detail', case_id=case.id)
    except Exception as exc:
        messages.error(request, f"Unable to decrypt evidence: {str(exc)}")
        return redirect('case_detail', case_id=case.id)

    # Log successful evidence retrieval
    log_security_event(
        action=AuditAction.EVIDENCE_DOWNLOADED,
        actor=request.user,
        request=request,
        target_model='EvidenceItem',
        target_id=str(evidence.id),
        details={'filename': evidence.original_filename, 'case_number': case.case_number}
    )

    # Formulate sandboxed HTTP response
    response = HttpResponse(plaintext_bytes, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{evidence.original_filename}"'
    response['Content-Length'] = len(plaintext_bytes)
    
    # Sandboxed CSP prevents browser from executing payload even if user opens in tab
    response['Content-Security-Policy'] = "sandbox; default-src 'none';"
    response['X-Content-Type-Options'] = 'nosniff'
    response['X-Frame-Options'] = 'DENY'

    return response
