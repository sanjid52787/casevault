package uk.ac.ravensbourne.casevault.web;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
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
import uk.ac.ravensbourne.casevault.domain.CaseStatus;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.CaseWorkflowService;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;
import uk.ac.ravensbourne.casevault.web.dto.CaseMutationRequests;

/** Verifies XSS encoding, binding isolation, deterministic stale writes, and scoped dates. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class CaseSecurityHardeningTest {
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;
    @Autowired CaseWorkflowService workflow;
    @Autowired TestDataCleaner cleaner;

    private Organisation clientOrganisation;
    private UserAccount client;
    private UserAccount analyst;
    private UserAccount manager;
    private CaseRecord caseRecord;

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        cleaner.clean();
        clientOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Client Organisation"));
        Organisation otherOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Other Organisation"));
        Organisation internal = organisations.save(new Organisation(UUID.randomUUID(), "Internal Organisation"));
        client = save(clientOrganisation, "case-client@test", Role.CLIENT_USER);
        analyst = save(internal, "case-analyst@test", Role.SECURITY_ANALYST);
        manager = save(internal, "case-manager@test", Role.CASE_MANAGER);
        caseRecord = cases.save(new CaseRecord(UUID.randomUUID(), clientOrganisation, "Safe case title", "Synthetic",
                Category.OTHER, Severity.LOW, client));
        jdbc.update("INSERT INTO case_assignments(id,case_id,organisation_id,analyst_id,assigned_by) VALUES(?,?,?,?,?)",
                UUID.randomUUID(), caseRecord.getId(), clientOrganisation.getId(), analyst.getId(), manager.getId());
        // Keep an unrelated tenant for search-scope assertions.
        UserAccount otherClient = save(otherOrganisation, "other-client@test", Role.CLIENT_USER);
        cases.save(new CaseRecord(UUID.randomUUID(), otherOrganisation, "Other tenant case", "Synthetic",
                Category.OTHER, Severity.LOW, otherClient));
    }

    @AfterEach
    void cleanFixtures() { cleaner.clean(); }

    @Test
    void tXss001StoredTitleNoteAndSearchTermAreEscapedInResponses() throws Exception {
        CaseRecord xssCase = cases.save(new CaseRecord(UUID.randomUUID(), clientOrganisation, "<script>title</script>", "Synthetic",
                Category.OTHER, Severity.LOW, client));
        jdbc.update("INSERT INTO case_assignments(id,case_id,organisation_id,analyst_id,assigned_by) VALUES(?,?,?,?,?)",
                UUID.randomUUID(), xssCase.getId(), clientOrganisation.getId(), analyst.getId(), manager.getId());
        workflow.note(UserPrincipal.from(analyst), xssCase.getId(), new CaseMutationRequests.Note("<img src=x>", false));

        mvc.perform(get("/cases").with(authentication(auth(client))))
                .andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("&lt;script&gt;title&lt;/script&gt;")))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("<script>title</script>"))));
        mvc.perform(get("/cases/{id}", xssCase.getId()).with(authentication(auth(analyst))))
                .andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("&lt;img src=x&gt;")))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("<img src=x>"))));
        mvc.perform(get("/cases").param("q", "<script>search</script>").with(authentication(auth(client))))
                .andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("&lt;script&gt;search&lt;/script&gt;")))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("<script>search</script>"))));
    }

    @Test
    void tCase003ClientMassAssignmentFieldsAreIgnored() throws Exception {
        UUID attemptedOrganisation = UUID.randomUUID();
        mvc.perform(post("/cases").with(authentication(auth(client))).with(csrf())
                        .param("title", "Mass assignment case").param("description", "Synthetic description")
                        .param("category", "OTHER").param("severity", "LOW")
                        .param("organisationId", attemptedOrganisation.toString()).param("role", "CASE_MANAGER")
                        .param("ownerId", UUID.randomUUID().toString()).param("status", "CLOSED"))
                .andExpect(status().is3xxRedirection());
        CaseRecord created = cases.findAll().stream().filter(value -> value.getTitle().equals("Mass assignment case"))
                .findFirst().orElseThrow();
        assertEquals(clientOrganisation.getId(), created.getOrganisation().getId());
        assertEquals(CaseStatus.NEW, created.getStatus());
        assertNull(created.getOwnerAnalyst());
        assertEquals(Role.CLIENT_USER, users.findById(client.getId()).orElseThrow().getRole());
    }

    @Test
    void tCase004DateRangeFilteringIsScopedInTheDatabaseQuery() {
        jdbc.update("UPDATE cases SET created_at=? WHERE id=?", Timestamp.from(Instant.parse("2026-01-10T12:00:00Z")), caseRecord.getId());
        CaseRecord february = cases.save(new CaseRecord(UUID.randomUUID(), clientOrganisation, "February case", "Synthetic",
                Category.OTHER, Severity.LOW, client));
        jdbc.update("UPDATE cases SET created_at=? WHERE id=?", Timestamp.from(Instant.parse("2026-02-10T12:00:00Z")), february.getId());
        var result = workflow.search(UserPrincipal.from(client), "", null, null, null, null,
                LocalDate.of(2026, 1, 1), LocalDate.of(2026, 1, 31), 0, 50, "createdAt");
        assertEquals(1, result.getTotalElements());
        assertEquals(caseRecord.getId(), result.getContent().getFirst().getId());
    }

    @Test
    void tCase005StaleVersionReturnsFriendlyConflictPage() throws Exception {
        mvc.perform(post("/cases/{id}/status", caseRecord.getId()).with(authentication(auth(manager))).with(csrf())
                        .param("status", "TRIAGED").param("version", "999"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("The case changed while you were editing it.")))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("OptimisticLockException"))));
        assertEquals(CaseStatus.NEW, cases.findById(caseRecord.getId()).orElseThrow().getStatus());
    }

    private UserAccount save(Organisation organisation, String email, Role role) {
        return users.save(new UserAccount(UUID.randomUUID(), organisation, email, "hash", role));
    }

    private UsernamePasswordAuthenticationToken auth(UserAccount user) {
        UserPrincipal principal = UserPrincipal.from(user);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }
}
