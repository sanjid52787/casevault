"""
CaseVault Audit Trail Views
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Provides administrative inspection and live cryptographic verification
of the tamper-evident HMAC hash chain (ADR-0003).
"""

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from audit.models import AuditLog, AuditAction
from audit.service import verify_audit_chain, log_security_event


@login_required
@require_http_methods(["GET", "POST"])
def audit_log_view(request):
    """
    Displays the chronological audit trail.
    Supports on-demand mathematical verification of the HMAC hash chain.
    Restricted to Firm Administrators and Lead Investigators.
    """
    if not (request.user.is_firm_admin or request.user.is_lead_investigator):
        log_security_event(
            action=AuditAction.ACCESS_DENIED,
            actor=request.user,
            request=request,
            details={'attempted_action': 'audit_log_view'}
        )
        messages.error(request, "Permission Denied: Audit log review is restricted to Firm Leadership.")
        return redirect('case_list')

    verification_result = None

    if request.method == 'POST' and 'verify_chain' in request.POST:
        is_valid, record_count_or_failed_id, msg = verify_audit_chain()
        log_security_event(
            action=AuditAction.TAMPER_CHECK_EXECUTED,
            actor=request.user,
            request=request,
            details={'is_valid': is_valid, 'inspected_records': record_count_or_failed_id}
        )
        verification_result = {
            'is_valid': is_valid,
            'count': record_count_or_failed_id,
            'message': msg,
        }
        if is_valid:
            messages.success(request, f"Audit Chain Integrity Verified: {msg}")
        else:
            messages.error(request, f"AUDIT CHAIN TAMPER ALERT: {msg}")

    # Paginate / slice latest 100 entries for readability
    entries = AuditLog.objects.order_by('-id')[:100]

    return render(request, 'audit/audit_log.html', {
        'entries': entries,
        'verification_result': verification_result,
    })
