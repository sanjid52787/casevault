package uk.ac.ravensbourne.casevault.audit;

import static org.junit.jupiter.api.Assertions.*;

import java.util.UUID;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.CaseVaultAuthenticationProvider;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/**
 * Regression integration test proving that audit append, hash chain verification,
 * and user authentication (LOGIN_SUCCESS audit) succeed on real PostgreSQL (PostgreSQL 16)
 * without java.time.Instant JDBC binding errors (CWE-1188, CWE-345).
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
@ActiveProfiles("test")
class PostgresAuditAndLoginIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16.6-alpine")
            .withDatabaseName("casevault")
            .withUsername("casevault_admin")
            .withPassword("adminpass");

    @DynamicPropertySource
    static void dynamicProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.flyway.url", postgres::getJdbcUrl);
        registry.add("spring.flyway.user", postgres::getUsername);
        registry.add("spring.flyway.password", postgres::getPassword);
    }

    @Autowired
    private PersistentAuditService auditService;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private CaseVaultAuthenticationProvider authProvider;

    @Autowired
    private UserAccountRepository users;

    @Autowired
    private OrganisationRepository organisations;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void tPostgres001AuditAppendAndVerifyChainOnRealPostgres() {
        UserPrincipal actor = new UserPrincipal(UUID.randomUUID(), UUID.randomUUID(), "auditor@example.test", "", Role.AUDITOR_ADMIN.name(), true, false);

        // Appending must bind timestamp properly as java.sql.Timestamp (never raw Instant)
        assertDoesNotThrow(() -> auditService.record(actor, "CASE_VIEWED", "CASE", UUID.randomUUID(), "case-viewed"));
        assertDoesNotThrow(() -> auditService.record(actor, "SEARCH_PERFORMED", "CASE", null, "search-performed"));

        AuditChainVerification verification = auditService.verifyChain();
        assertTrue(verification.valid(), "HMAC audit chain must be valid when verified on real PostgreSQL");

        Integer count = jdbc.queryForObject("SELECT count(*) FROM audit_events WHERE action IN ('CASE_VIEWED', 'SEARCH_PERFORMED')", Integer.class);
        assertNotNull(count);
        assertTrue(count >= 2, "Audit events must be persisted in PostgreSQL");
    }

    @Test
    void tPostgres002LoginWritesLoginSuccessAuditOnRealPostgres() {
        Organisation org = organisations.save(new Organisation(UUID.randomUUID(), "Postgres Test Org " + UUID.randomUUID()));
        String email = "pgadmin-" + UUID.randomUUID() + "@example.test";
        String rawPassword = "SecurePass123!@#";

        users.save(new UserAccount(
                UUID.randomUUID(),
                org,
                email,
                passwordEncoder.encode(rawPassword),
                Role.AUDITOR_ADMIN
        ));

        // Authenticate - this internally invokes audit.record(principal, "LOGIN_SUCCESS", "ACCOUNT", user.getId(), "login-success")
        Authentication auth = assertDoesNotThrow(() ->
                authProvider.authenticate(new UsernamePasswordAuthenticationToken(email, rawPassword))
        );

        assertNotNull(auth);
        assertTrue(auth.isAuthenticated());
        assertEquals(email, auth.getName());

        // Verify LOGIN_SUCCESS audit record exists in real PostgreSQL
        Integer loginSuccessCount = jdbc.queryForObject(
                "SELECT count(*) FROM audit_events WHERE action = 'LOGIN_SUCCESS' AND details_json LIKE '%login-success%'",
                Integer.class
        );
        assertNotNull(loginSuccessCount);
        assertTrue(loginSuccessCount >= 1, "LOGIN_SUCCESS event must be recorded into PostgreSQL audit_events table");

        // Verify audit chain remains cryptographically intact after login
        AuditChainVerification chainCheck = auditService.verifyChain();
        assertTrue(chainCheck.valid(), "Audit chain must remain valid after LOGIN_SUCCESS recording on PostgreSQL");
    }
}
