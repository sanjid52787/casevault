package uk.ac.ravensbourne.casevault.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
import uk.ac.ravensbourne.casevault.domain.RemediationAction;
import uk.ac.ravensbourne.casevault.domain.RemediationStatus;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.RemediationActionRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.CaseWorkflowService;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;
import uk.ac.ravensbourne.casevault.web.dto.CaseMutationRequests;

/** HTTP regressions for the remaining Phase 5 case-detail workflow controls. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class CaseDetailWorkflowTest {
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;
    @Autowired RemediationActionRepository actions;
    @Autowired CaseWorkflowService workflow;
    @Autowired TestDataCleaner cleaner;

    private UserAccount client;
    private UserAccount analyst;
    private UserAccount manager;
    private UserAccount auditor;
    private CaseRecord caseRecord;
    private RemediationAction action;
    private Organisation otherOrganisation;

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        cleaner.clean();
        Organisation clientOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Workflow client"));
        otherOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Other workflow client"));
        Organisation internalOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Workflow internal"));
        client = user(clientOrganisation, "workflow-client@test", Role.CLIENT_USER);
        analyst = user(internalOrganisation, "workflow-analyst@test", Role.SECURITY_ANALYST);
        manager = user(internalOrganisation, "workflow-manager@test", Role.CASE_MANAGER);
        auditor = user(internalOrganisation, "workflow-auditor@test", Role.AUDITOR_ADMIN);
        caseRecord = cases.save(new CaseRecord(UUID.randomUUID(), clientOrganisation, "Workflow case", "Synthetic case",
                Category.OTHER, Severity.LOW, client));
        jdbc.update("INSERT INTO case_assignments(id,case_id,organisation_id,analyst_id,assigned_by) VALUES(?,?,?,?,?)",
                UUID.randomUUID(), caseRecord.getId(), clientOrganisation.getId(), analyst.getId(), manager.getId());
        action = actions.save(new RemediationAction(UUID.randomUUID(), caseRecord, analyst, "Initial remediation action"));
    }

    @AfterEach
    void tearDown() {
        cleaner.clean();
    }

    @Test
    void tCase008ManagerEditsCategoryAndSeverity() throws Exception {
        mvc.perform(post("/cases/{id}/metadata", caseRecord.getId()).with(authentication(auth(manager))).with(csrf())
                        .param("category", "PHISHING").param("severity", "HIGH")
                        .param("version", Long.toString(caseRecord.getVersion())))
                .andExpect(status().is3xxRedirection());

        CaseRecord updated = cases.findById(caseRecord.getId()).orElseThrow();
        assertEquals(Category.PHISHING, updated.getCategory());
        assertEquals(Severity.HIGH, updated.getSeverity());
    }

    @Test
    void tCase009ClientAndAnalystCannotEditMetadata() throws Exception {
        mvc.perform(post("/cases/{id}/metadata", caseRecord.getId()).with(authentication(auth(client))).with(csrf())
                        .param("category", "PHISHING").param("severity", "HIGH"))
                .andExpect(status().isForbidden());
        mvc.perform(post("/cases/{id}/metadata", caseRecord.getId()).with(authentication(auth(analyst))).with(csrf())
                        .param("category", "PHISHING").param("severity", "HIGH"))
                .andExpect(status().isForbidden());
    }

    @Test
    void tCase010RemediationStatusUpdateAndCrossTenantDenial() throws Exception {
        mvc.perform(post("/cases/{caseId}/actions/{actionId}/status", caseRecord.getId(), action.getId())
                        .with(authentication(auth(analyst))).with(csrf()).param("status", "COMPLETE"))
                .andExpect(status().is3xxRedirection());
        assertEquals(RemediationStatus.COMPLETE, actions.findById(action.getId()).orElseThrow().getStatus());

        UserAccount otherClient = user(otherOrganisation, "workflow-other-client@test", Role.CLIENT_USER);
        CaseRecord otherCase = cases.save(new CaseRecord(UUID.randomUUID(), otherOrganisation, "Other workflow case",
                "Synthetic case", Category.OTHER, Severity.LOW, otherClient));
        RemediationAction otherAction = actions.save(new RemediationAction(UUID.randomUUID(), otherCase, otherClient, "Other action"));
        mvc.perform(post("/cases/{caseId}/actions/{actionId}/status", otherCase.getId(), otherAction.getId())
                        .with(authentication(auth(analyst))).with(csrf()).param("status", "COMPLETE"))
                .andExpect(status().isNotFound());
    }

    @Test
    void tCase011FormsRenderOnlyForAllowedRoles() throws Exception {
        mvc.perform(get("/cases/{id}", caseRecord.getId()).with(authentication(auth(client))))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("Assign analyst and owner"))))
                .andExpect(content().string(not(containsString("Add investigation note"))));
        mvc.perform(get("/cases/{id}", caseRecord.getId()).with(authentication(auth(analyst))))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Add investigation note")))
                .andExpect(content().string(containsString("Add remediation action")))
                .andExpect(content().string(not(containsString("Edit classification"))));
        mvc.perform(get("/cases/{id}", caseRecord.getId()).with(authentication(auth(manager))))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Assign analyst and owner")))
                .andExpect(content().string(containsString("Edit classification")))
                .andExpect(content().string(containsString("Change case status")));
        mvc.perform(get("/cases/{id}", caseRecord.getId()).with(authentication(auth(auditor))))
                .andExpect(status().isNotFound());

        mvc.perform(get("/").with(authentication(auth(client))))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Your cases")))
                .andExpect(content().string(not(containsString("Audit</a>"))));
        mvc.perform(get("/").with(authentication(auth(analyst))))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Assigned cases")));
        mvc.perform(get("/").with(authentication(auth(manager))))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Unassigned cases")))
                .andExpect(content().string(containsString("Open cases")));
        mvc.perform(get("/").with(authentication(auth(auditor))))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Review audit events and account activity")))
                .andExpect(content().string(containsString("Audit</a>")))
                .andExpect(content().string(containsString("Accounts</a>")))
                .andExpect(content().string(not(containsString(">Cases</a>"))));
    }

    @Test
    void tXss002NoteAndActionTextAreEscaped() throws Exception {
        workflow.note(UserPrincipal.from(analyst), caseRecord.getId(),
                new CaseMutationRequests.Note("<script>notePayload()</script>", false));
        workflow.action(UserPrincipal.from(analyst), caseRecord.getId(),
                new CaseMutationRequests.Action("<script>actionPayload()</script>", RemediationStatus.OPEN));

        mvc.perform(get("/cases/{id}", caseRecord.getId()).with(authentication(auth(analyst))))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("&lt;script&gt;notePayload()&lt;/script&gt;")))
                .andExpect(content().string(containsString("&lt;script&gt;actionPayload()&lt;/script&gt;")))
                .andExpect(content().string(not(containsString("<script>notePayload()</script>"))))
                .andExpect(content().string(not(containsString("<script>actionPayload()</script>"))));
    }

    private UserAccount user(Organisation organisation, String email, Role role) {
        return users.save(new UserAccount(UUID.randomUUID(), organisation, email, "hash", role));
    }

    private UsernamePasswordAuthenticationToken auth(UserAccount account) {
        UserPrincipal principal = UserPrincipal.from(account);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }
}
