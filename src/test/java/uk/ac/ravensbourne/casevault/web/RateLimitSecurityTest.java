package uk.ac.ravensbourne.casevault.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import org.hamcrest.Matchers;
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
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/** HTTP regression coverage for per-user/per-IP case-operation quotas (CWE-770). */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RateLimitSecurityTest {
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;
    private UserAccount clientA;
    private UserAccount clientB;
    private UserAccount analyst;
    private UserAccount manager;
    private CaseRecord caseRecord;

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        TestDataCleaner.clean(jdbc);
        Organisation clientOrgA = organisations.save(new Organisation(UUID.randomUUID(), "Rate Client A"));
        Organisation clientOrgB = organisations.save(new Organisation(UUID.randomUUID(), "Rate Client B"));
        Organisation internal = organisations.save(new Organisation(UUID.randomUUID(), "Rate Internal"));
        clientA = user(clientOrgA, "rate-a-" + UUID.randomUUID() + "@test", Role.CLIENT_USER);
        clientB = user(clientOrgB, "rate-b-" + UUID.randomUUID() + "@test", Role.CLIENT_USER);
        analyst = user(internal, "rate-analyst-" + UUID.randomUUID() + "@test", Role.SECURITY_ANALYST);
        manager = user(internal, "rate-manager-" + UUID.randomUUID() + "@test", Role.CASE_MANAGER);
        caseRecord = cases.save(new CaseRecord(UUID.randomUUID(), clientOrgA, "Rate test incident", "Synthetic",
                Category.OTHER, Severity.LOW, clientA));
        jdbc.update("INSERT INTO case_assignments(id,case_id,organisation_id,analyst_id,assigned_by) VALUES(?,?,?,?,?)",
                UUID.randomUUID(), caseRecord.getId(), clientOrgA.getId(), analyst.getId(), manager.getId());
    }

    @AfterEach
    void cleanFixtures() { TestDataCleaner.clean(jdbc); }

    @Test
    void tRate001SearchLimitReturns429WithRetryAfter() throws Exception {
        for (int count = 0; count < 3; count++) {
            mvc.perform(get("/cases").with(authentication(auth(clientA))))
                    .andExpect(status().isOk());
        }
        mvc.perform(get("/cases").with(authentication(auth(clientA))))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(header().exists("X-Correlation-ID"))
                .andExpect(content().string(Matchers.containsString("Request could not be completed")));
    }

    @Test
    void tRate002ReportGenerationLimitReturns429() throws Exception {
        for (int count = 0; count < 2; count++) {
            mvc.perform(post("/cases/{caseId}/reports", caseRecord.getId()).with(authentication(auth(analyst))).with(csrf()))
                    .andExpect(status().isCreated());
        }
        mvc.perform(post("/cases/{caseId}/reports", caseRecord.getId()).with(authentication(auth(analyst))).with(csrf()))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(header().exists("X-Correlation-ID"))
                .andExpect(content().string(Matchers.containsString("Request could not be completed")));
    }

    @Test
    void tRate003LimitsArePerUser() throws Exception {
        for (int count = 0; count < 3; count++) {
            mvc.perform(get("/cases").with(authentication(auth(clientA)))).andExpect(status().isOk());
        }
        mvc.perform(get("/cases").with(authentication(auth(clientA)))).andExpect(status().isTooManyRequests());
        mvc.perform(get("/cases").with(authentication(auth(clientB)))).andExpect(status().isOk());
    }

    @Test
    void tRate004DenialAuditIsAggregatedPerWindow() throws Exception {
        for (int count = 0; count < 6; count++) {
            mvc.perform(get("/cases").with(authentication(auth(clientA))));
        }
        assertEquals(1, jdbc.queryForObject(
                "SELECT COUNT(*) FROM audit_events WHERE action='RATE_LIMITED' AND target_type='SEARCH'", Integer.class));
    }

    private UserAccount user(Organisation organisation, String email, Role role) {
        return users.save(new UserAccount(UUID.randomUUID(), organisation, email, "hash", role));
    }

    private UsernamePasswordAuthenticationToken auth(UserAccount user) {
        UserPrincipal principal = UserPrincipal.from(user);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }
}
