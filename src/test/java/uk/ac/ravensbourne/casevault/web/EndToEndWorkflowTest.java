package uk.ac.ravensbourne.casevault.web;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import uk.ac.ravensbourne.casevault.audit.PersistentAuditService;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/** T-E2E-001: complete synthetic multi-role workflow, including access revocation. */
@SpringBootTest(properties = "casevault.evidence.directory=target/e2e-evidence")
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EndToEndWorkflowTest {
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;
    @Autowired PersistentAuditService audit;
    @Autowired FindByIndexNameSessionRepository<?> sessionRepository;
    @Autowired TestDataCleaner cleaner;

    private UserAccount client;
    private UserAccount analyst;
    private UserAccount manager;
    private UserAccount auditor;

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        cleaner.clean();
        Organisation clientOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "E2E Client"));
        Organisation internalOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "E2E Internal"));
        client = user(clientOrganisation, "e2e-client@example.test", Role.CLIENT_USER);
        analyst = user(internalOrganisation, "e2e-analyst@example.test", Role.SECURITY_ANALYST);
        manager = user(internalOrganisation, "e2e-manager@example.test", Role.CASE_MANAGER);
        auditor = user(internalOrganisation, "e2e-auditor@example.test", Role.AUDITOR_ADMIN);
    }

    @AfterEach
    void cleanUp() {
        cleaner.clean();
    }

    @Test
    void tE2e001ClientToApprovedReportToAdministrativeRevocation() throws Exception {
        var create = mvc.perform(post("/cases").with(authentication(auth(client))).with(csrf())
                        .param("title", "Synthetic end-to-end case")
                        .param("description", "Synthetic incident description")
                        .param("category", "PHISHING").param("severity", "HIGH"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        UUID caseId = UUID.fromString(create.getResponse().getRedirectedUrl().replace("/cases/", ""));

        mvc.perform(post("/cases/{id}/assign", caseId).with(authentication(auth(manager))).with(csrf())
                        .param("analystId", analyst.getId().toString()))
                .andExpect(status().is3xxRedirection());

        mvc.perform(post("/cases/{id}/notes", caseId).with(authentication(auth(analyst))).with(csrf())
                        .param("body", "Client-visible synthetic finding").param("clientVisible", "true"))
                .andExpect(status().is3xxRedirection());
        mvc.perform(post("/cases/{id}/actions", caseId).with(authentication(auth(analyst))).with(csrf())
                        .param("description", "Synthetic remediation action").param("status", "OPEN"))
                .andExpect(status().is3xxRedirection());
        mvc.perform(multipart("/cases/{id}/evidence", caseId)
                        .file(new MockMultipartFile("file", "e2e.txt", "text/plain",
                                "inert synthetic evidence".getBytes(StandardCharsets.UTF_8)))
                        .with(authentication(auth(analyst))).with(csrf()))
                .andExpect(status().isCreated());

        var generated = mvc.perform(post("/cases/{id}/reports", caseId)
                        .with(authentication(auth(analyst))).with(csrf()))
                .andExpect(status().isCreated()).andExpect(header().string("Location", containsString("/reports/")))
                .andReturn();
        UUID reportId = UUID.fromString(generated.getResponse().getHeader("Location").replace("/cases/" + caseId + "/reports/", ""));
        mvc.perform(post("/cases/{caseId}/reports/{reportId}/submit", caseId, reportId)
                        .with(authentication(auth(analyst))).with(csrf()))
                .andExpect(status().isNoContent());
        mvc.perform(post("/cases/{caseId}/reports/{reportId}/approve", caseId, reportId)
                        .with(authentication(auth(manager))).with(csrf()))
                .andExpect(status().isOk());

        mvc.perform(get("/cases/{caseId}/reports/{reportId}", caseId, reportId)
                        .with(authentication(auth(client))))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", containsString("attachment")))
                .andExpect(content().string(containsString("Client-visible synthetic finding")));
        mvc.perform(get("/admin/audit").with(authentication(auth(auditor))))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Audit")));

        Session analystSession = sessions().createSession();
        analystSession.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, analyst.getEmail());
        sessions().save(analystSession);
        mvc.perform(post("/admin/accounts/{id}/disable", analyst.getId()).with(authentication(auth(auditor))).with(csrf())
                        .param("reason", "Synthetic end-to-end access revocation"))
                .andExpect(status().is3xxRedirection());
        assertFalse(users.findById(analyst.getId()).orElseThrow().isEnabled());
        assertNull(sessions().findById(analystSession.getId()));
        assertNotNull(cases.findById(caseId).orElseThrow());
        assertEquals(true, audit.verifyChain().valid());
    }

    private UserAccount user(Organisation organisation, String email, Role role) {
        return users.save(new UserAccount(UUID.randomUUID(), organisation, email, "not-used-in-this-mockmvc-test", role));
    }

    private UsernamePasswordAuthenticationToken auth(UserAccount account) {
        UserPrincipal principal = UserPrincipal.from(account);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private FindByIndexNameSessionRepository<Session> sessions() {
        return (FindByIndexNameSessionRepository) sessionRepository;
    }
}
