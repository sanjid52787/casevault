"""
CaseVault Case Management Views
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Implements case listing, creation, detail inspection, investigator assignment,
and note appending with strict server-side RBAC and ABAC authorization (ADR-0002).
"""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit

from accounts.models import CustomUser, UserRole
from audit.models import AuditAction
from audit.service import log_security_event
from cases.models import Case, CaseClassification, CaseMembership, CaseNote, CaseStatus


@login_required
@ratelimit(key='ip', rate='30/m', block=True)
@require_http_methods(["GET"])
def case_list_view(request):
    """
    Displays the list of incident cases accessible to the authenticated user.
    Enforces object-level filtering via Case.objects.for_user().
    """
    cases = Case.objects.for_user(request.user).select_related('lead_investigator')
    return render(request, 'cases/case_list.html', {
        'cases': cases,
        'user': request.user,
    })


@login_required
@require_http_methods(["GET", "POST"])
def case_create_view(request):
    """
    Creates a new incident response case.
    Restricted to Lead Investigators and Firm Administrators.
    """
    if not request.user.is_lead_investigator:
        log_security_event(
            action=AuditAction.ACCESS_DENIED,
            actor=request.user,
            request=request,
            details={'attempted_action': 'case_create', 'role': request.user.role}
        )
        messages.error(request, "Permission Denied: Only Lead Investigators or Administrators may initiate new cases.")
        return redirect('case_list')

    if request.method == 'POST':
        case_number = request.POST.get('case_number', '').strip().upper()
        title = request.POST.get('title', '').strip()
        client_organization = request.POST.get('client_organization', '').strip()
        classification = request.POST.get('classification', CaseClassification.RESTRICTED)
        description = request.POST.get('description', '').strip()

        if not case_number or not title or not client_organization:
            messages.error(request, "Please fill in all mandatory case fields.")
            return render(request, 'cases/case_form.html', {
                'classifications': CaseClassification.choices,
            })

        if Case.objects.filter(case_number=case_number).exists():
            messages.error(request, f"Case number '{case_number}' is already registered.")
            return render(request, 'cases/case_form.html', {
                'classifications': CaseClassification.choices,
            })

        case = Case.objects.create(
            case_number=case_number,
            title=title,
            client_organization=client_organization,
            classification=classification,
            description=description,
            lead_investigator=request.user,
            status=CaseStatus.ACTIVE
        )

        log_security_event(
            action=AuditAction.CASE_CREATED,
            actor=request.user,
            request=request,
            target_model='Case',
            target_id=str(case.id),
            details={'case_number': case.case_number, 'classification': case.classification}
        )
        messages.success(request, f"Incident Case '{case.case_number}' successfully created.")
        return redirect('case_detail', case_id=case.id)

    return render(request, 'cases/case_form.html', {
        'classifications': CaseClassification.choices,
    })


@login_required
@require_http_methods(["GET"])
def case_detail_view(request, case_id):
    """
    Displays case metadata, investigative notes, evidence items, and assigned members.
    Enforces object-level ABAC checks: returns 404 if the user is unauthorized,
    preventing IDOR enumeration attacks.
    """
    case = get_object_or_404(Case.objects.for_user(request.user), id=case_id)

    # Scoped notes: client auditors only see client-visible notes
    if request.user.is_client_auditor:
        notes = case.notes.filter(is_client_visible=True).select_related('author')
    else:
        notes = case.notes.all().select_related('author')

    evidence_items = case.evidence_items.all().select_related('uploaded_by')
    memberships = case.memberships.all().select_related('user')
    available_investigators = CustomUser.objects.filter(
        role__in=[UserRole.LEAD_INVESTIGATOR, UserRole.INVESTIGATOR],
        is_active=True
    ).exclude(case_memberships__case=case).exclude(id=case.lead_investigator_id)

    log_security_event(
        action=AuditAction.CASE_VIEWED,
        actor=request.user,
        request=request,
        target_model='Case',
        target_id=str(case.id),
        details={'case_number': case.case_number}
    )

    return render(request, 'cases/case_detail.html', {
        'case': case,
        'notes': notes,
        'evidence_items': evidence_items,
        'memberships': memberships,
        'available_investigators': available_investigators,
        'can_edit': case.can_user_edit(request.user),
        'can_upload': case.can_user_upload_evidence(request.user),
    })


@login_required
@require_http_methods(["POST"])
def case_add_note_view(request, case_id):
    """
    Appends an investigative note to the case.
    External client auditors cannot create internal forensic notes.
    """
    case = get_object_or_404(Case.objects.for_user(request.user), id=case_id)

    if request.user.is_client_auditor:
        log_security_event(
            action=AuditAction.ACCESS_DENIED,
            actor=request.user,
            request=request,
            details={'reason': 'client_auditor_note_creation_blocked'}
        )
        messages.error(request, "Client Auditors hold read-only permissions.")
        return redirect('case_detail', case_id=case.id)

    note_text = request.POST.get('note', '').strip()
    is_client_visible = request.POST.get('is_client_visible') == 'on'

    if note_text:
        note = CaseNote.objects.create(
            case=case,
            author=request.user,
            note=note_text,
            is_client_visible=is_client_visible
        )
        log_security_event(
            action=AuditAction.NOTE_ADDED,
            actor=request.user,
            request=request,
            target_model='CaseNote',
            target_id=str(note.id),
            details={'case_number': case.case_number, 'is_client_visible': is_client_visible}
        )
        messages.success(request, "Investigative note added.")
    else:
        messages.error(request, "Note content cannot be empty.")

    return redirect('case_detail', case_id=case.id)


@login_required
@require_http_methods(["POST"])
def case_add_member_view(request, case_id):
    """
    Assigns an investigator to a case.
    Restricted to Lead Investigators and Firm Administrators.
    """
    case = get_object_or_404(Case.objects.for_user(request.user), id=case_id)

    if not case.can_user_edit(request.user):
        log_security_event(
            action=AuditAction.ACCESS_DENIED,
            actor=request.user,
            request=request,
            details={'reason': 'unauthorized_member_assignment'}
        )
        messages.error(request, "Only the case lead or administrator can assign investigators.")
        return redirect('case_detail', case_id=case.id)

    user_id = request.POST.get('user_id')
    user_to_assign = get_object_or_404(CustomUser, id=user_id)

    membership, created = CaseMembership.objects.get_or_create(
        case=case,
        user=user_to_assign,
        defaults={'role_in_case': 'INVESTIGATOR'}
    )

    if created:
        log_security_event(
            action=AuditAction.CASE_MEMBER_ADDED,
            actor=request.user,
            request=request,
            target_model='CaseMembership',
            target_id=str(membership.id),
            details={'assigned_user': user_to_assign.username, 'case_number': case.case_number}
        )
        messages.success(request, f"Investigator '{user_to_assign.username}' assigned to case.")
    else:
        messages.info(request, f"Investigator '{user_to_assign.username}' is already a member.")

    return redirect('case_detail', case_id=case.id)
