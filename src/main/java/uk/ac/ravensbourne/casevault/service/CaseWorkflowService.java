package uk.ac.ravensbourne.casevault.service;

import jakarta.persistence.OptimisticLockException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.domain.CaseNote;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.CaseStatus;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.RemediationAction;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.repository.CaseNoteRepository;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.RemediationActionRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.RequiresCaseAccess;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.web.dto.CaseMutationRequests.Action;
import uk.ac.ravensbourne.casevault.web.dto.CaseMutationRequests.Assign;
import uk.ac.ravensbourne.casevault.web.dto.CaseMutationRequests.Note;
import uk.ac.ravensbourne.casevault.web.dto.CaseMutationRequests.Status;

/** Mutations obtain the case through CaseAccessService before changing it (CWE-639). */
@Service
public class CaseWorkflowService {
    private final CaseAccessService access;
    private final AccessPolicy policy;
    private final CaseRepository cases;
    private final UserAccountRepository users;
    private final CaseNoteRepository notes;
    private final RemediationActionRepository actions;
    private final InputNormalizer normalizer;
    private final AuditService audit;

    public CaseWorkflowService(CaseAccessService access, AccessPolicy policy, CaseRepository cases,
                               UserAccountRepository users, CaseNoteRepository notes,
                               RemediationActionRepository actions, InputNormalizer normalizer, AuditService audit) {
        this.access = access;
        this.policy = policy;
        this.cases = cases;
        this.users = users;
        this.notes = notes;
        this.actions = actions;
        this.normalizer = normalizer;
        this.audit = audit;
    }

    @Transactional @RequiresCaseAccess
    public void assign(UserPrincipal principal, UUID caseId, Assign request) {
        CaseRecord caseRecord = access.requireView(principal, caseId);
        if (!policy.canAssign(principal, caseRecord)) throw new CaseNotFoundException();
        caseRecord.assign(users.findById(request.analystId()).orElseThrow(CaseNotFoundException::new));
        audit.record(principal, "CASE_ASSIGNED", "CASE", caseId, "case-assigned");
    }

    @Transactional @RequiresCaseAccess
    public void status(UserPrincipal principal, UUID caseId, Status request) {
        CaseRecord caseRecord = access.requireView(principal, caseId);
        if (!policy.canChangeStatus(principal, caseRecord)) throw new CaseNotFoundException();
        if (request.version() != null && request.version() != caseRecord.getVersion()) {
            throw new OptimisticLockException("Case changed by another request");
        }
        CaseStatusMachine.requirePermitted(caseRecord.getStatus(), request.status());
        caseRecord.transitionTo(request.status());
        audit.record(principal, "STATUS_CHANGED", "CASE", caseId, "status-changed");
    }

    @Transactional @RequiresCaseAccess
    public void note(UserPrincipal principal, UUID caseId, Note request) {
        CaseRecord caseRecord = access.requireView(principal, caseId);
        if (!policy.canAddNote(principal, caseRecord, cases.existsAssignment(caseId, principal.id()))) {
            throw new CaseNotFoundException();
        }
        notes.save(new CaseNote(UUID.randomUUID(), caseRecord, users.findById(principal.id()).orElseThrow(),
                normalizer.text(request.body()), request.clientVisible()));
        audit.record(principal, "NOTE_ADDED", "CASE", caseId, "note-added");
    }

    @Transactional @RequiresCaseAccess
    public void action(UserPrincipal principal, UUID caseId, Action request) {
        CaseRecord caseRecord = access.requireView(principal, caseId);
        if (!policy.canAddRemediation(principal, caseRecord, cases.existsAssignment(caseId, principal.id()))) {
            throw new CaseNotFoundException();
        }
        RemediationAction action = new RemediationAction(UUID.randomUUID(), caseRecord,
                users.findById(principal.id()).orElseThrow(), normalizer.text(request.description()));
        action.update(request.status());
        actions.save(action);
        audit.record(principal, "ACTION_ADDED", "CASE", caseId, "action-added");
    }

    public Page<CaseRecord> search(UserPrincipal principal, String text, Category category, Severity severity,
                                   CaseStatus status, UUID owner, LocalDate fromDate, LocalDate toDate,
                                   int page, int size, String sort) {
        if (fromDate != null && toDate != null && fromDate.isAfter(toDate)) {
            throw new IllegalArgumentException("Invalid date range");
        }
        int safeSize = Math.min(Math.max(size, 1), 50);
        String field = Set.of("createdAt", "title", "severity", "status").contains(sort) ? sort : "createdAt";
        String query = text == null || text.isBlank() ? null
                : "%" + text.toLowerCase(Locale.ROOT).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%";
        var from = fromDate == null ? null : fromDate.atStartOfDay().toInstant(ZoneOffset.UTC);
        var toExclusive = toDate == null ? null : toDate.plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC);
        var pageable = PageRequest.of(Math.max(page, 0), safeSize, Sort.by(Sort.Direction.DESC, field));
        Page<CaseRecord> result = switch (Role.valueOf(principal.role())) {
            case CLIENT_USER -> cases.searchClient(principal.organisationId(), query, category, severity, status, owner,
                    from, toExclusive, pageable);
            case SECURITY_ANALYST -> cases.searchAssigned(principal.id(), query, category, severity, status, owner,
                    from, toExclusive, pageable);
            case CASE_MANAGER -> cases.searchManaged(query, category, severity, status, owner, from, toExclusive, pageable);
            case AUDITOR_ADMIN -> Page.empty(pageable);
        };
        audit.record(principal, "SEARCH_PERFORMED", "CASE", null, "search-performed");
        return result;
    }

    /** Compatibility overload for existing internal callers without a date filter. */
    public Page<CaseRecord> search(UserPrincipal principal, String text, Category category, Severity severity,
                                   CaseStatus status, UUID owner, int page, int size, String sort) {
        return search(principal, text, category, severity, status, owner, null, null, page, size, sort);
    }
}
