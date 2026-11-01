package uk.ac.ravensbourne.casevault.web;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.ReportRecord;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.ReportRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/** HTTP regression tests for report object authorisation and CSRF (CWE-639/CWE-352). */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ReportEndpointSecurityTest {
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;
    @Autowired ReportRepository reports;
    @Autowired TestDataCleaner cleaner;

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
        cleaner.clean();
        clientOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Report HTTP Client"));
        Organisation otherOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Report HTTP Other"));
        Organisation internalOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Report HTTP Internal"));
        client = user(clientOrganisation, "report-client@example.test", Role.CLIENT_USER);
        otherClient = user(otherOrganisation, "report-other@example.test", Role.CLIENT_USER);
        analyst = user(internalOrganisation, "report-analyst@example.test", Role.SECURITY_ANALYST);
        manager = user(internalOrganisation, "report-manager@example.test", Role.CASE_MANAGER);
        auditor = user(internalOrganisation, "report-auditor@example.test", Role.AUDITOR_ADMIN);
        caseRecord = cases.save(new CaseRecord(UUID.randomUUID(), clientOrganisation, "Report HTTP case",
                "Synthetic content", Category.OTHER, Severity.LOW, client));
        jdbc.update("INSERT INTO case_assignments(id,case_id,organisation_id,analyst_id,assigned_by) VALUES(?,?,?,?,?)",
                UUID.randomUUID(), caseRecord.getId(), clientOrganisation.getId(), analyst.getId(), manager.getId());
    }

    @AfterEach
    void cleanUp() {
        cleaner.clean();
    }

    @Test
    void tReport009OtherOrganisationClientGetsNotFoundOverHttp() throws Exception {
        ReportRecord report = draft(analyst, 1);
        mvc.perform(get("/cases/{caseId}/reports/{reportId}", caseRecord.getId(), report.getId())
                        .with(authentication(auth(otherClient))))
                .andExpect(status().isNotFound());
    }

    @Test
    void tReport010ClientCannotGetDraftOrSubmittedReportOverHttp() throws Exception {
        ReportRecord draft = draft(analyst, 1);
        ReportRecord submitted = draft(analyst, 2);
        submitted.submit();
        reports.save(submitted);

        mvc.perform(get("/cases/{caseId}/reports/{reportId}", caseRecord.getId(), draft.getId())
                        .with(authentication(auth(client))))
                .andExpect(status().isNotFound());
        mvc.perform(get("/cases/{caseId}/reports/{reportId}", caseRecord.getId(), submitted.getId())
                        .with(authentication(auth(client))))
                .andExpect(status().isNotFound());
    }

    @Test
    void tReport011ManagerCannotApproveOwnGeneratedReportOverHttp() throws Exception {
        ReportRecord report = draft(manager, 1);
        report.submit();
        reports.save(report);

        mvc.perform(post("/cases/{caseId}/reports/{reportId}/approve", caseRecord.getId(), report.getId())
                        .with(authentication(auth(manager))).with(csrf()))
                .andExpect(status().isNotFound());
    }

    @Test
    void tReport012AuditorCannotGetReportContentOverHttp() throws Exception {
        ReportRecord report = draft(analyst, 1);
        mvc.perform(get("/cases/{caseId}/reports/{reportId}", caseRecord.getId(), report.getId())
                        .with(authentication(auth(auditor))))
                .andExpect(status().isNotFound());
    }

    @Test
    void tReport013ReportGenerationPostWithoutCsrfIsRejected() throws Exception {
        mvc.perform(post("/cases/{caseId}/reports", caseRecord.getId()).with(authentication(auth(analyst))))
                .andExpect(status().isForbidden());
    }

    private ReportRecord draft(UserAccount generatedBy, int version) {
        return reports.save(new ReportRecord(UUID.randomUUID(), caseRecord, clientOrganisation, generatedBy,
                version, "Synthetic report"));
    }

    private UserAccount user(Organisation organisation, String email, Role role) {
        return users.save(new UserAccount(UUID.randomUUID(), organisation, email, "hash", role));
    }

    private UsernamePasswordAuthenticationToken auth(UserAccount account) {
        UserPrincipal principal = UserPrincipal.from(account);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }
}
