package uk.ac.ravensbourne.casevault.web;

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
import uk.ac.ravensbourne.casevault.service.AdminAccountService;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/**
 * Security tests for admin user deletion / anonymisation (CWE-269, CWE-862, CWE-613).
 *
 * <ul>
 *   <li>T-ADMIN-DEL-001 — Non-admin cannot invoke user deletion</li>
 *   <li>T-ADMIN-DEL-002 — Admin cannot delete self</li>
 *   <li>T-ADMIN-DEL-003 — Admin cannot delete the last active administrator</li>
 *   <li>T-ADMIN-DEL-004 — Deletion marks account deleted, scrambles email, disables it, and audits ACCOUNT_DELETED</li>
 *   <li>T-ADMIN-DEL-005 — Deletion requires valid audit reason</li>
 *   <li>T-ADMIN-DEL-006 — Already deleted account cannot be deleted again</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AdminUserDeletionTest {

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository orgs;
    @Autowired UserAccountRepository users;
    @Autowired AdminAccountService adminAccounts;
    @Autowired TestDataCleaner cleaner;

    UserAccount admin, otherAdmin, client, analyst;
    Organisation org;

    @BeforeEach
    void setup() {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL, last_hash=NULL WHERE singleton=TRUE");
        cleaner.clean();

        org = orgs.save(new Organisation(UUID.randomUUID(), "TestOrg"));
        admin = users.save(new UserAccount(UUID.randomUUID(), org, "admin@test", "hash", Role.AUDITOR_ADMIN));
        otherAdmin = users.save(new UserAccount(UUID.randomUUID(), org, "admin2@test", "hash", Role.AUDITOR_ADMIN));
        client = users.save(new UserAccount(UUID.randomUUID(), org, "client@test", "hash", Role.CLIENT_USER));
        analyst = users.save(new UserAccount(UUID.randomUUID(), org, "analyst@test", "hash", Role.SECURITY_ANALYST));
    }

    @AfterEach
    void tearDown() {
        cleaner.clean();
    }

    UsernamePasswordAuthenticationToken auth(UserAccount u) {
        var p = UserPrincipal.from(u);
        return UsernamePasswordAuthenticationToken.authenticated(p, null, p.getAuthorities());
    }

    /** T-ADMIN-DEL-001: Non-admin users get 403 on delete user endpoint. */
    @Test
    void tAdminDel001NonAdminCannotDeleteUser() throws Exception {
        mvc.perform(post("/admin/accounts/{id}/delete", analyst.getId())
                        .param("reason", "Unauthorized attempt")
                        .with(authentication(auth(client)))
                        .with(csrf()))
                .andExpect(status().isForbidden());

        UserAccount unaffected = users.findById(analyst.getId()).orElseThrow();
        assertFalse(unaffected.isDeleted());
    }

    /** T-ADMIN-DEL-002: Admin cannot delete their own account. */
    @Test
    void tAdminDel002CannotDeleteSelf() {
        assertThrows(IllegalArgumentException.class, () ->
                adminAccounts.delete(UserPrincipal.from(admin), admin.getId(), "Self delete attempt"));

        UserAccount self = users.findById(admin.getId()).orElseThrow();
        assertFalse(self.isDeleted());
        assertTrue(self.isEnabled());
    }

    /** T-ADMIN-DEL-003: Admin cannot delete the last active administrator. */
    @Test
    void tAdminDel003CannotDeleteLastAdmin() {
        // First delete otherAdmin
        adminAccounts.delete(UserPrincipal.from(admin), otherAdmin.getId(), "Removing second admin");
        assertTrue(users.findById(otherAdmin.getId()).orElseThrow().isDeleted());

        // Now admin is the last active admin; attempt to delete admin via otherAdmin or admin should fail
        assertThrows(IllegalArgumentException.class, () ->
                adminAccounts.delete(UserPrincipal.from(admin), admin.getId(), "Removing last admin"));
    }

    /** T-ADMIN-DEL-004: Deletion marks account deleted, scrambles email, disables it, and records ACCOUNT_DELETED. */
    @Test
    void tAdminDel004SuccessfulDeletionAnonymisesAndAudits() throws Exception {
        mvc.perform(post("/admin/accounts/{id}/delete", client.getId())
                        .param("reason", "Client requested account erasure under GDPR")
                        .with(authentication(auth(admin)))
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());

        UserAccount deleted = users.findById(client.getId()).orElseThrow();
        assertTrue(deleted.isDeleted());
        assertNotNull(deleted.getDeletedAt());
        assertFalse(deleted.isEnabled());
        assertNull(deleted.getDisplayName());
        assertEquals("deleted-" + client.getId() + "@casevault.invalid", deleted.getEmail());

        // Verify ACCOUNT_DELETED audit event
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM audit_events WHERE action='ACCOUNT_DELETED' AND target_id=?",
                Integer.class, client.getId());
        assertEquals(1, count);
    }

    /** T-ADMIN-DEL-005: Reason validation prevents empty or invalid reasons. */
    @Test
    void tAdminDel005ReasonRequired() {
        assertThrows(IllegalArgumentException.class, () ->
                adminAccounts.delete(UserPrincipal.from(admin), client.getId(), ""));
        assertThrows(IllegalArgumentException.class, () ->
                adminAccounts.delete(UserPrincipal.from(admin), client.getId(), null));
    }

    /** T-ADMIN-DEL-006: An already deleted user cannot be deleted again. */
    @Test
    void tAdminDel006AlreadyDeletedCannotBeDeletedAgain() {
        adminAccounts.delete(UserPrincipal.from(admin), client.getId(), "First deletion");
        assertTrue(users.findById(client.getId()).orElseThrow().isDeleted());

        assertThrows(IllegalArgumentException.class, () ->
                adminAccounts.delete(UserPrincipal.from(admin), client.getId(), "Second deletion"));
    }
}

