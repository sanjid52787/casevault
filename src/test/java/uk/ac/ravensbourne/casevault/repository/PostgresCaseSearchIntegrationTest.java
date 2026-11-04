package uk.ac.ravensbourne.casevault.repository;

import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDate;
import java.util.UUID;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;
import uk.ac.ravensbourne.casevault.domain.*;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.CaseWorkflowService;

/**
 * Regression test against real PostgreSQL 16 proving that dynamic Specification
 * queries for case search (GET /cases) succeed without the "ERROR: could not determine data type
 * of parameter $N" (SQLState 42P18) error when optional filter parameters are null (CWE-1188).
 *
 * Covers:
 * 1. Case list with no filters (all null parameters)
 * 2. Each filter alone
 * 3. Combined filters
 * 4. Search with wildcard characters (%, _, ')
 * 5. Tenant isolation across two organisations
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class PostgresCaseSearchIntegrationTest {

    private static PostgreSQLContainer<?> postgres;
    private static boolean dockerAvailable;

    static {
        try {
            dockerAvailable = DockerClientFactory.instance().isDockerAvailable();
            if (dockerAvailable) {
                postgres = new PostgreSQLContainer<>("postgres:16.6-alpine")
                        .withDatabaseName("casevault")
                        .withUsername("casevault_admin")
                        .withPassword("adminpass");
                postgres.start();
            }
        } catch (Throwable t) {
            dockerAvailable = false;
        }
    }

    @DynamicPropertySource
    static void dynamicProperties(DynamicPropertyRegistry registry) {
        if (dockerAvailable && postgres != null && postgres.isRunning()) {
            registry.add("spring.datasource.url", postgres::getJdbcUrl);
            registry.add("spring.datasource.username", postgres::getUsername);
            registry.add("spring.datasource.password", postgres::getPassword);
            registry.add("spring.flyway.url", postgres::getJdbcUrl);
            registry.add("spring.flyway.user", postgres::getUsername);
            registry.add("spring.flyway.password", postgres::getPassword);
        }
    }

    @BeforeEach
    void checkEnvironment() {
        Assumptions.assumeTrue(dockerAvailable && postgres != null && postgres.isRunning(),
                "Docker is unavailable in this environment; skipping PostgreSQL Testcontainers integration test");
    }

    @AfterAll
    static void cleanup() {
        if (postgres != null && postgres.isRunning()) {
            postgres.stop();
        }
    }

    @Autowired CaseWorkflowService workflow;
    @Autowired CaseRepository cases;
    @Autowired OrganisationRepository orgs;
    @Autowired UserAccountRepository users;
    @Autowired CaseAssignmentRepository assignments;

    Organisation orgA;
    Organisation orgB;
    UserAccount clientA;
    UserAccount clientB;
    UserAccount analyst;
    UserAccount manager;
    CaseRecord caseA1;
    CaseRecord caseA2;
    CaseRecord caseB1;

    @BeforeEach
    void setupFixtures() {
        if (!dockerAvailable || postgres == null || !postgres.isRunning()) return;

        orgA = orgs.save(new Organisation(UUID.randomUUID(), "PG Org Alpha " + UUID.randomUUID()));
        orgB = orgs.save(new Organisation(UUID.randomUUID(), "PG Org Beta " + UUID.randomUUID()));

        clientA = users.save(new UserAccount(UUID.randomUUID(), orgA, "pgclienta-" + UUID.randomUUID() + "@alpha.test", "hash", Role.CLIENT_USER));
        clientB = users.save(new UserAccount(UUID.randomUUID(), orgB, "pgclientb-" + UUID.randomUUID() + "@beta.test", "hash", Role.CLIENT_USER));
        analyst = users.save(new UserAccount(UUID.randomUUID(), orgA, "pganalyst-" + UUID.randomUUID() + "@alpha.test", "hash", Role.SECURITY_ANALYST));
        manager = users.save(new UserAccount(UUID.randomUUID(), orgA, "pgmanager-" + UUID.randomUUID() + "@alpha.test", "hash", Role.CASE_MANAGER));

        caseA1 = cases.save(new CaseRecord(UUID.randomUUID(), orgA, "Phishing Attack 100% genuine",
                "Special_case with 10% risk and O'Reilly report", Category.PHISHING, Severity.HIGH, clientA));
        caseA1.assign(analyst);
        cases.save(caseA1);
        assignments.save(new CaseAssignment(UUID.randomUUID(), caseA1, analyst, manager));

        caseA2 = cases.save(new CaseRecord(UUID.randomUUID(), orgA, "Data Exposure incident",
                "Internal exposure details", Category.DATA_EXPOSURE, Severity.LOW, clientA));

        caseB1 = cases.save(new CaseRecord(UUID.randomUUID(), orgB, "Ransomware simulation",
                "Ransomware details for Beta", Category.RANSOMWARE_SIMULATION, Severity.CRITICAL, clientB));
    }

    @Test
    void tPgSearch001NoFiltersOnPostgres() {
        UserPrincipal principalA = UserPrincipal.from(clientA);
        Page<CaseRecord> resultA = assertDoesNotThrow(() ->
                workflow.search(principalA, null, null, null, null, null, null, null, 0, 20, "createdAt"));
        assertEquals(2, resultA.getTotalElements(), "Client A must see both organisation A cases without SQL error");

        UserPrincipal principalB = UserPrincipal.from(clientB);
        Page<CaseRecord> resultB = assertDoesNotThrow(() ->
                workflow.search(principalB, null, null, null, null, null, null, null, 0, 20, "createdAt"));
        assertEquals(1, resultB.getTotalElements());
        assertEquals("Ransomware simulation", resultB.getContent().get(0).getTitle());
    }

    @Test
    void tPgSearch002IndividualFiltersAloneOnPostgres() {
        UserPrincipal principal = UserPrincipal.from(clientA);

        // Category filter alone
        Page<CaseRecord> cat = assertDoesNotThrow(() ->
                workflow.search(principal, null, Category.PHISHING, null, null, null, null, null, 0, 20, "createdAt"));
        assertEquals(1, cat.getTotalElements());

        // Severity filter alone
        Page<CaseRecord> sev = assertDoesNotThrow(() ->
                workflow.search(principal, null, null, Severity.LOW, null, null, null, null, 0, 20, "createdAt"));
        assertEquals(1, sev.getTotalElements());

        // Status filter alone
        Page<CaseRecord> st = assertDoesNotThrow(() ->
                workflow.search(principal, null, null, null, CaseStatus.NEW, null, null, null, 0, 20, "createdAt"));
        assertEquals(2, st.getTotalElements());

        // Owner filter alone
        Page<CaseRecord> own = assertDoesNotThrow(() ->
                workflow.search(principal, null, null, null, null, analyst.getId(), null, null, 0, 20, "createdAt"));
        assertEquals(1, own.getTotalElements());

        // Date range filter alone
        LocalDate today = LocalDate.now();
        Page<CaseRecord> dt = assertDoesNotThrow(() ->
                workflow.search(principal, null, null, null, null, null, today.minusDays(1), today.plusDays(1), 0, 20, "createdAt"));
        assertEquals(2, dt.getTotalElements());
    }

    @Test
    void tPgSearch003CombinedFiltersOnPostgres() {
        UserPrincipal principal = UserPrincipal.from(clientA);
        Page<CaseRecord> matched = assertDoesNotThrow(() ->
                workflow.search(principal, "Phishing", Category.PHISHING, Severity.HIGH,
                        CaseStatus.NEW, analyst.getId(), null, null, 0, 20, "createdAt"));
        assertEquals(1, matched.getTotalElements());
    }

    @Test
    void tPgSearch004WildcardEscapingOnPostgres() {
        UserPrincipal principal = UserPrincipal.from(clientA);

        // Literal %
        Page<CaseRecord> resPct = assertDoesNotThrow(() ->
                workflow.search(principal, "100%", null, null, null, null, null, null, 0, 20, "createdAt"));
        assertEquals(1, resPct.getTotalElements());

        // Literal _
        Page<CaseRecord> resUnderscore = assertDoesNotThrow(() ->
                workflow.search(principal, "Special_", null, null, null, null, null, null, 0, 20, "createdAt"));
        assertEquals(1, resUnderscore.getTotalElements());

        // Literal '
        Page<CaseRecord> resQuote = assertDoesNotThrow(() ->
                workflow.search(principal, "O'Reilly", null, null, null, null, null, null, 0, 20, "createdAt"));
        assertEquals(1, resQuote.getTotalElements());
    }

    @Test
    void tPgSearch005TenantIsolationOnPostgres() {
        UserPrincipal principalA = UserPrincipal.from(clientA);
        Page<CaseRecord> resA = workflow.search(principalA, null, null, null, null, null, null, null, 0, 20, "createdAt");
        assertTrue(resA.getContent().stream().noneMatch(c -> c.getOrganisation().getId().equals(orgB.getId())));

        UserPrincipal principalB = UserPrincipal.from(clientB);
        Page<CaseRecord> resB = workflow.search(principalB, null, null, null, null, null, null, null, 0, 20, "createdAt");
        assertTrue(resB.getContent().stream().allMatch(c -> c.getOrganisation().getId().equals(orgB.getId())));
    }
}

