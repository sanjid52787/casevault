package uk.ac.ravensbourne.casevault.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import uk.ac.ravensbourne.casevault.domain.CaseNote;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.RemediationAction;
import uk.ac.ravensbourne.casevault.domain.ReportRecord;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseNoteRepository;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.RemediationActionRepository;
import uk.ac.ravensbourne.casevault.repository.ReportRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.CaseNotFoundException;
import uk.ac.ravensbourne.casevault.service.ReportApprovalService;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/** Security regression suite for client-safe report generation and retrieval. */
@SpringBootTest
@ActiveProfiles("test")
class ReportSecurityTest {
    @Autowired ReportService reportService;
    @Autowired ReportApprovalService approvalService;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;
    @Autowired CaseNoteRepository notes;
    @Autowired RemediationActionRepository actions;
    @Autowired ReportRepository reports;

    private Organisation clientOrganisation;
    private UserAccount client;
    private UserAccount otherClient;
    private UserAccount analyst;
    private UserAccount manager;
    private UserAccount auditor;
    private CaseRecord caseRecord;

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        TestDataCleaner.clean(jdbc);

        clientOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Report Client"));
        Organisation otherOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Other Client"));
        Organisation internal = organisations.save(new Organisation(UUID.randomUUID(), "Northbridge Internal"));
        client = user(clientOrganisation, "client@example.test", Role.CLIENT_USER);
        otherClient = user(otherOrganisation, "other@example.test", Role.CLIENT_USER);
        analyst = user(internal, "analyst@northbridge.test", Role.SECURITY_ANALYST);
        manager = user(internal, "manager@northbridge.test", Role.CASE_MANAGER);
        auditor = user(internal, "auditor@northbridge.test", Role.AUDITOR_ADMIN);
        caseRecord = cases.save(new CaseRecord(UUID.randomUUID(), clientOrganisation,
                "<script>alert('title')</script>",
                "Synthetic description: client@example.test, 203.0.113.23, api_key=supersecretvalue",
                Category.DATA_EXPOSURE, Severity.HIGH, client));
        jdbc.update("INSERT INTO case_assignments(id,case_id,organisation_id,analyst_id,assigned_by) VALUES(?,?,?,?,?)",
                UUID.randomUUID(), caseRecord.getId(), clientOrganisation.getId(), analyst.getId(), manager.getId());
        notes.save(new CaseNote(UUID.randomUUID(), caseRecord, analyst, "Visible <img src=x>", true));
        notes.save(new CaseNote(UUID.randomUUID(), caseRecord, analyst, "INTERNAL-ONLY-FINDING", false));
        actions.save(new RemediationAction(UUID.randomUUID(), caseRecord, analyst, "Rotate token=abcdefghijklmnop"));
    }

    @AfterEach
    void cleanFixtures() { TestDataCleaner.clean(jdbc); }

    @Test
    void tReport001RedactionRemovesEmailsIpsAndApiKeys() {
        String content = generate().getContent();
        assertTrue(content.contains("[redacted-email]"));
        assertTrue(content.contains("[redacted-ip]"));
        assertTrue(content.contains("[redacted-secret]"));
        assertFalse(content.contains("client@example.test"));
        assertFalse(content.contains("203.0.113.23"));
        assertFalse(content.contains("supersecretvalue"));
    }

    @Test
    void tReport002InjectionPayloadsAreEscaped() {
        String content = generate().getContent();
        assertTrue(content.contains("&lt;script&gt;alert(&#39;title&#39;)&lt;/script&gt;"));
        assertTrue(content.contains("&lt;img src=x&gt;"));
        assertFalse(content.contains("<script>"));
        assertFalse(content.contains("<img src=x>"));
    }

    @Test
    void tReport003InternalNotesAreExcluded() {
        String content = generate().getContent();
        assertTrue(content.contains("Visible"));
        assertFalse(content.contains("INTERNAL-ONLY-FINDING"));
        assertFalse(content.contains("analyst@northbridge.test"));
        assertFalse(content.contains(analyst.getId().toString()));
    }

    @Test
    void tReport004ManagerCannotApproveOwnReport() {
        ReportRecord report = new ReportRecord(UUID.randomUUID(), caseRecord, clientOrganisation, manager, 1, "synthetic");
        report.submit();
        reports.save(report);
        assertThrows(CaseNotFoundException.class,
                () -> approvalService.approve(principal(manager), caseRecord.getId(), report.getId()));
    }

    @Test
    void tReport005ClientSeesApprovedReportsOnly() {
        ReportRecord draft = generate();
        assertThrows(CaseNotFoundException.class,
                () -> reportService.downloadable(principal(client), caseRecord.getId(), draft.getId()));
        approve(draft);
        assertEquals(draft.getId(), reportService.downloadable(principal(client), caseRecord.getId(), draft.getId()).getId());
    }

    @Test
    void tReport006CrossTenantAccessIsNotFound() {
        ReportRecord approved = generate();
        approve(approved);
        assertThrows(CaseNotFoundException.class,
                () -> reportService.downloadable(principal(otherClient), caseRecord.getId(), approved.getId()));
    }

    @Test
    void tReport007AuditorIsDeniedReportContent() {
        ReportRecord approved = generate();
        approve(approved);
        assertThrows(CaseNotFoundException.class,
                () -> reportService.downloadable(principal(auditor), caseRecord.getId(), approved.getId()));
    }

    @Test
    void tReport008LifecycleActionsAreAudited() {
        ReportRecord report = generate();
        reportService.submit(principal(analyst), caseRecord.getId(), report.getId());
        approvalService.approve(principal(manager), caseRecord.getId(), report.getId());
        reportService.downloadable(principal(client), caseRecord.getId(), report.getId());
        List<String> recorded = jdbc.queryForList(
                "SELECT action FROM audit_events WHERE target_id=? ORDER BY id", String.class, report.getId());
        assertEquals(List.of("REPORT_GENERATED", "REPORT_SUBMITTED", "REPORT_APPROVED", "REPORT_DOWNLOADED"), recorded);
    }

    private ReportRecord generate() {
        return reportService.generate(principal(analyst), caseRecord.getId());
    }

    private void approve(ReportRecord report) {
        reportService.submit(principal(analyst), caseRecord.getId(), report.getId());
        approvalService.approve(principal(manager), caseRecord.getId(), report.getId());
    }

    private UserAccount user(Organisation organisation, String email, Role role) {
        return users.save(new UserAccount(UUID.randomUUID(), organisation, email, "hash", role));
    }

    private UserPrincipal principal(UserAccount user) {
        return UserPrincipal.from(user);
    }
}
