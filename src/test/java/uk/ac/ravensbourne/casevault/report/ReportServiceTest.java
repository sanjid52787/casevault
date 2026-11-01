package uk.ac.ravensbourne.casevault.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.ac.ravensbourne.casevault.audit.AuditEventType;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.domain.CaseNote;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.RemediationAction;
import uk.ac.ravensbourne.casevault.domain.ReportRecord;
import uk.ac.ravensbourne.casevault.domain.ReportStatus;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseNoteRepository;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.RemediationActionRepository;
import uk.ac.ravensbourne.casevault.repository.ReportRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.AccessPolicy;
import uk.ac.ravensbourne.casevault.service.CaseAccessService;
import uk.ac.ravensbourne.casevault.service.CaseNotFoundException;
import uk.ac.ravensbourne.casevault.service.ReportApprovalService;

/** Unit coverage for the confidential report workflow and content boundary. */
class ReportServiceTest {
    private final CaseAccessService access = mock(CaseAccessService.class);
    private final CaseRepository cases = mock(CaseRepository.class);
    private final CaseNoteRepository notes = mock(CaseNoteRepository.class);
    private final RemediationActionRepository actions = mock(RemediationActionRepository.class);
    private final ReportRepository reports = mock(ReportRepository.class);
    private final UserAccountRepository users = mock(UserAccountRepository.class);
    private final AuditService audit = mock(AuditService.class);
    private ReportService service;
    private Organisation clientOrganisation;
    private UserAccount analyst;
    private UserAccount manager;
    private UserAccount client;
    private CaseRecord caseRecord;
    private UserPrincipal analystPrincipal;

    @BeforeEach
    void setUp() {
        clientOrganisation = new Organisation(UUID.randomUUID(), "Report Client");
        Organisation internal = new Organisation(UUID.randomUUID(), "Northbridge Internal");
        client = new UserAccount(UUID.randomUUID(), clientOrganisation, "client@example.test", "hash", Role.CLIENT_USER);
        analyst = new UserAccount(UUID.randomUUID(), internal, "analyst@northbridge.test", "hash", Role.SECURITY_ANALYST);
        manager = new UserAccount(UUID.randomUUID(), internal, "manager@northbridge.test", "hash", Role.CASE_MANAGER);
        caseRecord = new CaseRecord(UUID.randomUUID(), clientOrganisation, "<script>Title</script>",
                "Contact client@example.test from 203.0.113.12 using api_key=supersecretvalue",
                Category.DATA_EXPOSURE, Severity.HIGH, client);
        analystPrincipal = UserPrincipal.from(analyst);
        service = new ReportService(access, new AccessPolicy(), cases, notes, actions, reports, users,
                new Redactor(), audit);
        when(access.requireView(analystPrincipal, caseRecord.getId())).thenReturn(caseRecord);
        when(cases.existsAssignment(caseRecord.getId(), analyst.getId())).thenReturn(true);
        when(users.findById(analyst.getId())).thenReturn(Optional.of(analyst));
        when(reports.findFirstByCaseRecordIdOrderByVersionDesc(caseRecord.getId())).thenReturn(Optional.empty());
        when(reports.save(any(ReportRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(notes.findByCaseRecordIdAndClientVisibleTrue(caseRecord.getId())).thenReturn(List.of(
                new CaseNote(UUID.randomUUID(), caseRecord, analyst, "Visible <b>finding</b>", true)));
        when(actions.findByCaseRecordId(caseRecord.getId())).thenReturn(List.of(
                new RemediationAction(UUID.randomUUID(), caseRecord, analyst, "Rotate api-key=abcdefghijk")));
    }

    @Test
    void tReport001CreatesVersionedDraftWithOnlySafeClientContent() {
        ReportRecord previous = new ReportRecord(UUID.randomUUID(), caseRecord, clientOrganisation, analyst, 3, "old");
        when(reports.findFirstByCaseRecordIdOrderByVersionDesc(caseRecord.getId())).thenReturn(Optional.of(previous));

        ReportRecord report = service.generate(analystPrincipal, caseRecord.getId());

        assertEquals(ReportStatus.DRAFT, report.getStatus());
        assertEquals(4, report.getVersion());
        assertTrue(report.getContent().contains("&lt;script&gt;Title&lt;/script&gt;"));
        assertTrue(report.getContent().contains("[redacted-email]"));
        assertTrue(report.getContent().contains("[redacted-ip]"));
        assertTrue(report.getContent().contains("[redacted-secret]"));
        assertTrue(report.getContent().contains("Client-visible findings"));
        assertTrue(report.getContent().contains("Remediation actions"));
        verify(audit).record(eq(analystPrincipal), eq(AuditEventType.REPORT_GENERATED), eq("REPORT"),
                eq(report.getId()), eq("report-generated"));
    }

    @Test
    void tReport002SubmissionAndIndependentApprovalAreEnforcedAndAudited() {
        ReportRecord report = service.generate(analystPrincipal, caseRecord.getId());
        when(reports.findByIdAndCaseRecordId(report.getId(), caseRecord.getId())).thenReturn(Optional.of(report));

        service.submit(analystPrincipal, caseRecord.getId(), report.getId());
        assertEquals(ReportStatus.SUBMITTED, report.getStatus());
        verify(audit).record(analystPrincipal, AuditEventType.REPORT_SUBMITTED, "REPORT", report.getId(), "report-submitted");

        ReportApprovalService approval = new ReportApprovalService(reports, users, access, audit);
        UserPrincipal managerPrincipal = UserPrincipal.from(manager);
        when(access.requireReportApproval(managerPrincipal, caseRecord.getId(), analyst.getId())).thenReturn(caseRecord);
        when(users.findById(manager.getId())).thenReturn(Optional.of(manager));
        approval.approve(managerPrincipal, caseRecord.getId(), report.getId());
        assertEquals(ReportStatus.APPROVED, report.getStatus());
        verify(audit).record(managerPrincipal, AuditEventType.REPORT_APPROVED, "REPORT", report.getId(), "report-approved");

        ReportRecord selfApprovalAttempt = new ReportRecord(UUID.randomUUID(), caseRecord, clientOrganisation,
                analyst, 99, "synthetic");
        selfApprovalAttempt.submit();
        assertThrows(IllegalArgumentException.class, () -> selfApprovalAttempt.approve(analyst));
    }

    @Test
    void tReport003ClientsOnlyDownloadApprovedAndAuditorsOrOtherTenantsSeeNotFound() {
        ReportRecord report = service.generate(analystPrincipal, caseRecord.getId());
        when(reports.findByIdAndCaseRecordId(report.getId(), caseRecord.getId())).thenReturn(Optional.of(report));
        UserPrincipal clientPrincipal = UserPrincipal.from(client);
        when(access.requireView(clientPrincipal, caseRecord.getId())).thenReturn(caseRecord);
        assertThrows(CaseNotFoundException.class, () -> service.downloadable(clientPrincipal, caseRecord.getId(), report.getId()));

        report.submit();
        report.approve(manager);
        assertEquals(report, service.downloadable(clientPrincipal, caseRecord.getId(), report.getId()));
        verify(audit).record(clientPrincipal, AuditEventType.REPORT_DOWNLOADED, "REPORT", report.getId(), "report-downloaded");

        UserPrincipal otherTenant = new UserPrincipal(UUID.randomUUID(), UUID.randomUUID(), "other@example.test", "",
                Role.CLIENT_USER.name(), true, false);
        UserPrincipal auditor = new UserPrincipal(UUID.randomUUID(), UUID.randomUUID(), "audit@example.test", "",
                Role.AUDITOR_ADMIN.name(), true, false);
        when(access.requireView(otherTenant, caseRecord.getId())).thenThrow(new CaseNotFoundException());
        when(access.requireView(auditor, caseRecord.getId())).thenThrow(new CaseNotFoundException());
        assertThrows(CaseNotFoundException.class, () -> service.downloadable(otherTenant, caseRecord.getId(), report.getId()));
        assertThrows(CaseNotFoundException.class, () -> service.downloadable(auditor, caseRecord.getId(), report.getId()));
    }
}
