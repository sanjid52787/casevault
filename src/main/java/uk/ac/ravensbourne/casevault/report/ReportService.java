package uk.ac.ravensbourne.casevault.report;

import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.HtmlUtils;
import uk.ac.ravensbourne.casevault.audit.AuditEventType;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.ReportRecord;
import uk.ac.ravensbourne.casevault.domain.ReportStatus;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.repository.CaseNoteRepository;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.RemediationActionRepository;
import uk.ac.ravensbourne.casevault.repository.ReportRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.AccessPolicy;
import uk.ac.ravensbourne.casevault.service.CaseAccessService;
import uk.ac.ravensbourne.casevault.service.CaseNotFoundException;

/**
 * Produces text-only, client-safe report snapshots. It enforces report workflow and object access in the
 * service layer (CWE-639/CWE-863), and deliberately excludes internal notes, evidence and user identities.
 */
@Service
public class ReportService {
    private final CaseAccessService access;
    private final AccessPolicy policy;
    private final CaseRepository cases;
    private final CaseNoteRepository notes;
    private final RemediationActionRepository actions;
    private final ReportRepository reports;
    private final UserAccountRepository users;
    private final Redactor redactor;
    private final AuditService audit;

    public ReportService(CaseAccessService access, AccessPolicy policy, CaseRepository cases,
                         CaseNoteRepository notes, RemediationActionRepository actions,
                         ReportRepository reports, UserAccountRepository users, Redactor redactor,
                         AuditService audit) {
        this.access = access;
        this.policy = policy;
        this.cases = cases;
        this.notes = notes;
        this.actions = actions;
        this.reports = reports;
        this.users = users;
        this.redactor = redactor;
        this.audit = audit;
    }

    /** Creates a versioned DRAFT. Submission is a separate, auditable workflow action. */
    @Transactional
    public ReportRecord generate(UserPrincipal principal, UUID caseId) {
        CaseRecord caseRecord = access.requireView(principal, caseId);
        requireGenerator(principal, caseRecord);
        int version = reports.findFirstByCaseRecordIdOrderByVersionDesc(caseId)
                .map(report -> report.getVersion() + 1).orElse(1);
        ReportRecord report = reports.save(new ReportRecord(UUID.randomUUID(), caseRecord,
                caseRecord.getOrganisation(), users.findById(principal.id()).orElseThrow(CaseNotFoundException::new),
                version, content(caseRecord)));
        audit.record(principal, AuditEventType.REPORT_GENERATED, "REPORT", report.getId(), "report-generated");
        return report;
    }

    /** Submits a generator's own DRAFT for independent manager approval. */
    @Transactional
    public void submit(UserPrincipal principal, UUID caseId, UUID reportId) {
        CaseRecord caseRecord = access.requireView(principal, caseId);
        requireGenerator(principal, caseRecord);
        ReportRecord report = reportForCase(caseId, reportId);
        if (!report.getGeneratedBy().getId().equals(principal.id())) throw new CaseNotFoundException();
        report.submit();
        audit.record(principal, AuditEventType.REPORT_SUBMITTED, "REPORT", reportId, "report-submitted");
    }

    /** Returns only content the caller may download; unauthorised reports are indistinguishable from absent ones. */
    @Transactional
    public ReportRecord downloadable(UserPrincipal principal, UUID caseId, UUID reportId) {
        CaseRecord caseRecord = access.requireView(principal, caseId);
        ReportRecord report = reportForCase(caseId, reportId);
        if (!mayDownload(principal, report)) throw new CaseNotFoundException();
        audit.record(principal, AuditEventType.REPORT_DOWNLOADED, "REPORT", reportId, "report-downloaded");
        return report;
    }

    private void requireGenerator(UserPrincipal principal, CaseRecord caseRecord) {
        if (!policy.canGenerateReport(principal, caseRecord, cases.existsAssignment(caseRecord.getId(), principal.id()))) {
            throw new CaseNotFoundException();
        }
    }

    private ReportRecord reportForCase(UUID caseId, UUID reportId) {
        return reports.findByIdAndCaseRecordId(reportId, caseId).orElseThrow(CaseNotFoundException::new);
    }

    private boolean mayDownload(UserPrincipal principal, ReportRecord report) {
        return switch (Role.valueOf(principal.role())) {
            case CLIENT_USER -> report.getStatus() == ReportStatus.APPROVED;
            case SECURITY_ANALYST -> report.getGeneratedBy().getId().equals(principal.id());
            case CASE_MANAGER -> report.getStatus() != ReportStatus.DRAFT;
            case AUDITOR_ADMIN -> false;
        };
    }

    private String content(CaseRecord caseRecord) {
        StringBuilder report = new StringBuilder("Case summary\n")
                .append("Title: ").append(safe(caseRecord.getTitle())).append('\n')
                .append("Description: ").append(safe(caseRecord.getDescription())).append('\n')
                .append("Category: ").append(caseRecord.getCategory()).append('\n')
                .append("Severity: ").append(caseRecord.getSeverity()).append("\n\n")
                .append("Status timeline\n")
                .append("- Case created: NEW\n")
                .append("- Current status: ").append(caseRecord.getStatus()).append("\n\n")
                .append("Client-visible findings\n");
        notes.findByCaseRecordIdAndClientVisibleTrue(caseRecord.getId())
                .forEach(note -> report.append("- ").append(safe(note.getBody())).append('\n'));
        report.append("\nRemediation actions\n");
        actions.findByCaseRecordId(caseRecord.getId())
                .forEach(action -> report.append("- ").append(safe(action.getDescription()))
                        .append(" [").append(action.getStatus()).append("]\n"));
        return report.toString();
    }

    private String safe(String value) {
        return HtmlUtils.htmlEscape(redactor.redact(value));
    }
}
