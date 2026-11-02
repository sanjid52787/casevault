package uk.ac.ravensbourne.casevault.service;

import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.domain.CaseNote;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.CaseStatus;
import uk.ac.ravensbourne.casevault.domain.RemediationAction;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseNoteRepository;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.RemediationActionRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.domain.EvidenceFile;
import uk.ac.ravensbourne.casevault.domain.ReportRecord;
import uk.ac.ravensbourne.casevault.report.ReportService;
import uk.ac.ravensbourne.casevault.security.RequiresCaseAccess;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/** Loads a case and only the notes that the authenticated role may view (CWE-639). */
@Service
public class CaseViewService {
    private final CaseAccessService access;
    private final AccessPolicy policy;
    private final CaseRepository cases;
    private final CaseNoteRepository notes;
    private final RemediationActionRepository actions;
    private final UserAccountRepository users;
    private final AuditService audit;
    private final EvidenceService evidence;
    private final ReportService reports;

    public CaseViewService(CaseAccessService access, AccessPolicy policy, CaseRepository cases, CaseNoteRepository notes,
                           RemediationActionRepository actions, UserAccountRepository users, AuditService audit,
                           EvidenceService evidence, ReportService reports) {
        this.access = access;
        this.policy = policy;
        this.cases = cases;
        this.notes = notes;
        this.actions = actions;
        this.users = users;
        this.audit = audit;
        this.evidence = evidence;
        this.reports = reports;
    }

    @RequiresCaseAccess
    public CaseDetail view(UserPrincipal principal, UUID caseId) {
        CaseRecord caseRecord = access.requireView(principal, caseId);
        boolean assigned = cases.existsAssignment(caseId, principal.id());
        List<CaseNote> visibleNotes = (Role.CLIENT_USER.name().equals(principal.role())
                || Role.CASE_MANAGER.name().equals(principal.role()))
                ? notes.findByCaseRecordIdAndClientVisibleTrue(caseId) : notes.findByCaseRecordId(caseId);
        CasePermissions permissions = new CasePermissions(
                policy.canAssign(principal, caseRecord),
                policy.canEditCaseMetadata(principal, caseRecord),
                policy.canChangeStatus(principal, caseRecord),
                policy.canAddNote(principal, caseRecord, assigned),
                policy.canAddRemediation(principal, caseRecord, assigned),
                policy.canUploadEvidence(principal, caseRecord, assigned),
                policy.canDownloadEvidence(principal, caseRecord, assigned),
                policy.canGenerateReport(principal, caseRecord, assigned),
                Role.CASE_MANAGER.name().equals(principal.role()));
        List<UserAccount> analysts = permissions.canAssign()
                ? users.findByRoleAndEnabledTrue(Role.SECURITY_ANALYST) : List.of();
        audit.record(principal, "CASE_VIEWED", "CASE", caseId, "case-viewed");
        List<EvidenceFile> evidenceFiles = permissions.canDownloadEvidence() ? evidence.visibleFor(principal, caseId) : List.of();
        List<ReportRecord> visibleReports = reports.visibleFor(principal, caseId);
        return new CaseDetail(caseRecord, visibleNotes, actions.findByCaseRecordId(caseId), evidenceFiles, visibleReports, analysts,
                CaseStatusMachine.nextStates(caseRecord.getStatus()), permissions);
    }

    public record CaseDetail(CaseRecord caseRecord, List<CaseNote> notes, List<RemediationAction> actions,
                             List<EvidenceFile> evidenceFiles, List<ReportRecord> reports,
                             List<UserAccount> analysts, java.util.Set<CaseStatus> nextStatuses,
                             CasePermissions permissions) { }

    /** Presentation permissions mirror service checks; endpoints still repeat authorisation. */
    public record CasePermissions(boolean canAssign, boolean canEditMetadata, boolean canChangeStatus,
                                  boolean canAddNote, boolean canAddRemediation, boolean canUploadEvidence,
                                  boolean canDownloadEvidence, boolean canGenerateReport, boolean canApproveReports) { }
}
