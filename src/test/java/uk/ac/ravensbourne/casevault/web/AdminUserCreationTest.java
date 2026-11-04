package uk.ac.ravensbourne.casevault.web;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import uk.ac.ravensbourne.casevault.domain.*;
import uk.ac.ravensbourne.casevault.repository.*;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/**
 * Security tests for admin user and organisation creation (CWE-269, CWE-862).
 *
 * <ul>
 *   <li>T-ADMIN-CREATE-001 — Non-admins cannot access user creation endpoints</li>
 *   <li>T-ADMIN-CREATE-002 — AUDITOR_ADMIN role cannot be assigned via the creation form</li>
 *   <li>T-ADMIN-CREATE-003 — Duplicate email is rejected</li>
 *   <li>T-ADMIN-CREATE-004 — Successful creation sets force_password_reset and audit</li>
 *   <li>T-ADMIN-CREATE-005 — Password never appears in audit events</li>
 *   <li>T-ADMIN-CREATE-006 — Organisation creation is audited</li>
 *   <li>T-ADMIN-CREATE-007 — Non-admins cannot create organisations</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AdminUserCreationTest {

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository orgs;
    @Autowired UserAccountRepository users;
    @Autowired TestDataCleaner cleaner;

    UserAccount admin, client;
    Organisation org;

    @BeforeEach
    void data() {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL, last_hash=NULL WHERE singleton=TRUE");
        cleaner.clean();
        org = orgs.save(new Organisation(UUID.randomUUID(), "TestOrg"));
        Organisation extOrg = orgs.save(new Organisation(UUID.randomUUID(), "External"));
        admin = users.save(new UserAccount(UUID.randomUUID(), org, "admin@test", "hash", Role.AUDITOR_ADMIN));
        client = users.save(new UserAccount(UUID.randomUUID(), extOrg, "client@test", "hash", Role.CLIENT_USER));
    }

    @AfterEach
    void cleanFixtures() { cleaner.clean(); }

    UsernamePasswordAuthenticationToken auth(UserAccount u) {
        var p = UserPrincipal.from(u);
        return UsernamePasswordAuthenticationToken.authenticated(p, null, p.getAuthorities());
    }

    /** T-ADMIN-CREATE-001: Non-admin users get 403 on GET and POST create-user endpoints. */
    @Test
    void tAdminCreate001NonAdminCannotAccessCreateUser() throws Exception {
        mvc.perform(get("/admin/accounts/create")
                        .with(authentication(auth(client))))
                .andExpect(status().isForbidden());

        mvc.perform(post("/admin/accounts/create")
                        .param("email", "new@test")
                        .param("role", "CLIENT_USER")
                        .param("organisationId", org.getId().toString())
                        .with(authentication(auth(client)))
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    /** T-ADMIN-CREATE-002: AUDITOR_ADMIN role cannot be assigned via user creation. */
    @Test
    void tAdminCreate002AuditorAdminRoleIsBlocked() throws Exception {
        mvc.perform(post("/admin/accounts/create")
                        .param("email", "hacker@test")
                        .param("role", "AUDITOR_ADMIN")
                        .param("organisationId", org.getId().toString())
                        .with(authentication(auth(admin)))
                        .with(csrf()))
                .andExpect(status().isOk()) // re-renders form with errors
                .andExpect(content().string(containsString("Create User Account")));

        // Verify no account was created
        assertTrue(users.findByEmail("hacker@test").isEmpty());
    }

    /** T-ADMIN-CREATE-003: Duplicate email is rejected. */
    @Test
    void tAdminCreate003DuplicateEmailRejected() throws Exception {
        mvc.perform(post("/admin/accounts/create")
                        .param("email", "client@test")
                        .param("role", "CLIENT_USER")
                        .param("organisationId", org.getId().toString())
                        .with(authentication(auth(admin)))
                        .with(csrf()))
                .andExpect(status().isOk()) // re-renders form with error
                .andExpect(content().string(containsString("already exists")));
    }

    /** T-ADMIN-CREATE-004: Successful creation sets force_password_reset and is audited. */
    @Test
    void tAdminCreate004SuccessfulCreationSetsForceResetAndAudits() throws Exception {
        mvc.perform(post("/admin/accounts/create")
                        .param("email", "newuser@test")
                        .param("role", "SECURITY_ANALYST")
                        .param("organisationId", org.getId().toString())
                        .param("displayName", "New User")
                        .with(authentication(auth(admin)))
                        .with(csrf()))
                .andExpect(status().isOk()) // renders the one-time password page
                .andExpect(content().string(containsString("One-time password")));

        // Verify user was created with force_password_reset
        UserAccount created = users.findByEmail("newuser@test").orElseThrow();
        assertTrue(created.isForcePasswordReset());
        assertEquals(Role.SECURITY_ANALYST, created.getRole());
        assertEquals("New User", created.getDisplayName());

        // Verify audit event
        assertEquals(1, jdbc.queryForObject(
                "SELECT COUNT(*) FROM audit_events WHERE action='ACCOUNT_CREATED'", Integer.class));
    }

    /** T-ADMIN-CREATE-005: The generated password never appears in audit events. */
    @Test
    void tAdminCreate005PasswordNeverInAuditEvents() throws Exception {
        var result = mvc.perform(post("/admin/accounts/create")
                        .param("email", "audit-check@test")
                        .param("role", "CLIENT_USER")
                        .param("organisationId", org.getId().toString())
                        .with(authentication(auth(admin)))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andReturn();

        // Extract the generated password from the response
        String responseBody = result.getResponse().getContentAsString();
        // The password is in the <pre> tag
        int start = responseBody.indexOf("<pre class=\"one-time-password\">");
        int end = responseBody.indexOf("</pre>", start);
        assertTrue(start > 0 && end > start, "Password should appear in response page");
        String password = responseBody.substring(start + "<pre class=\"one-time-password\">".length(), end).trim();
        assertFalse(password.isEmpty(), "Generated password should not be empty");

        // Verify password does NOT appear in any audit event details
        List<String> allDetails = jdbc.queryForList(
                "SELECT details_json FROM audit_events", String.class);
        for (String detail : allDetails) {
            assertFalse(detail.contains(password),
                    "Generated password must never appear in audit events");
        }
    }

    /** T-ADMIN-CREATE-006: Organisation creation is audited. */
    @Test
    void tAdminCreate006OrgCreationAudited() throws Exception {
        mvc.perform(post("/admin/organisations/create")
                        .param("name", "Globex Corp")
                        .with(authentication(auth(admin)))
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());

        assertEquals(1, jdbc.queryForObject(
                "SELECT COUNT(*) FROM audit_events WHERE action='ORGANISATION_CREATED'", Integer.class));
    }

    /** T-ADMIN-CREATE-007: Non-admins cannot create organisations. */
    @Test
    void tAdminCreate007NonAdminCannotCreateOrg() throws Exception {
        mvc.perform(post("/admin/organisations/create")
                        .param("name", "Hacker Corp")
                        .with(authentication(auth(client)))
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }
}

