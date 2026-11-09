package uk.ac.ravensbourne.casevault.web;

import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDate;
import java.util.UUID;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;
import uk.ac.ravensbourne.casevault.domain.*;
import uk.ac.ravensbourne.casevault.repository.*;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.CaseWorkflowService;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/**
 * H2-independent regression tests for case search and filtering (CWE-1188, CWE-639).
 * Verifies that the dynamic {@link uk.ac.ravensbourne.casevault.repository.CaseSpecifications}
 * queries correctly handle:
 * <ul>
 *   <li>No filters (null parameters)</li>
 *   <li>Each filter alone (category, severity, status, owner, date range)</li>
 *   <li>Combined filters</li>
 *   <li>Wildcard search characters (%, _, ')</li>
 *   <li>Tenant isolation across organisations</li>
 *   <li>Role assignment scoping for security analysts</li>
 * </ul>
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class CaseSearchSpecificationTest {

    @Autowired CaseWorkflowService workflow;
    @Autowired CaseRepository cases;
    @Autowired OrganisationRepository orgs;
    @Autowired UserAccountRepository users;
    @Autowired CaseAssignmentRepository assignments;
    @Autowired TestDataCleaner cleaner;

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
    void setup() {
        cleaner.clean();

        orgA = orgs.save(new Organisation(UUID.randomUUID(), "Org Alpha"));
        orgB = orgs.save(new Organisation(UUID.randomUUID(), "Org Beta"));

        clientA = users.save(new UserAccount(UUID.randomUUID(), orgA, "clienta@alpha.test", "hash", Role.CLIENT_USER));
        clientB = users.save(new UserAccount(UUID.randomUUID(), orgB, "clientb@beta.test", "hash", Role.CLIENT_USER));
        analyst = users.save(new UserAccount(UUID.randomUUID(), orgA, "analyst@alpha.test", "hash", Role.SECURITY_ANALYST));
        manager = users.save(new UserAccount(UUID.randomUUID(), orgA, "manager@alpha.test", "hash", Role.CASE_MANAGER));

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
    void tSearch001NoFiltersReturnsAllTenantCasesForClient() {
        UserPrincipal principalA = UserPrincipal.from(clientA);
        Page<CaseRecord> resultA = workflow.search(principalA, null, null, null, null, null, null, null, 0, 20, "createdAt");
        assertEquals(2, resultA.getTotalElements());

        UserPrincipal principalB = UserPrincipal.from(clientB);
        Page<CaseRecord> resultB = workflow.search(principalB, null, null, null, null, null, null, null, 0, 20, "createdAt");
        assertEquals(1, resultB.getTotalElements());
        assertEquals("Ransomware simulation", resultB.getContent().get(0).getTitle());
    }

    @Test
    void tSearch002IndividualFiltersAlone() {
        UserPrincipal principal = UserPrincipal.from(clientA);

        // Category filter
        Page<CaseRecord> catResult = workflow.search(principal, null, Category.PHISHING, null, null, null, null, null, 0, 20, "createdAt");
        assertEquals(1, catResult.getTotalElements());
        assertEquals(caseA1.getId(), catResult.getContent().get(0).getId());

        // Severity filter
        Page<CaseRecord> sevResult = workflow.search(principal, null, null, Severity.LOW, null, null, null, null, 0, 20, "createdAt");
        assertEquals(1, sevResult.getTotalElements());
        assertEquals(caseA2.getId(), sevResult.getContent().get(0).getId());

        // Status filter
        Page<CaseRecord> statusResult = workflow.search(principal, null, null, null, CaseStatus.NEW, null, null, null, 0, 20, "createdAt");
        assertEquals(2, statusResult.getTotalElements());

        // Owner filter
        Page<CaseRecord> ownerResult = workflow.search(principal, null, null, null, null, analyst.getId(), null, null, 0, 20, "createdAt");
        assertEquals(1, ownerResult.getTotalElements());
        assertEquals(caseA1.getId(), ownerResult.getContent().get(0).getId());

        // Date range
        LocalDate today = LocalDate.now();
        Page<CaseRecord> dateResult = workflow.search(principal, null, null, null, null, null, today.minusDays(1), today.plusDays(1), 0, 20, "createdAt");
        assertEquals(2, dateResult.getTotalElements());
    }

    @Test
    void tSearch003CombinedFilters() {
        UserPrincipal principal = UserPrincipal.from(clientA);

        // Matching combination
        Page<CaseRecord> matched = workflow.search(principal, "Phishing", Category.PHISHING, Severity.HIGH,
                CaseStatus.NEW, analyst.getId(), null, null, 0, 20, "createdAt");
        assertEquals(1, matched.getTotalElements());

        // Non-matching combination (wrong severity)
        Page<CaseRecord> unmatched = workflow.search(principal, "Phishing", Category.PHISHING, Severity.LOW,
                CaseStatus.NEW, analyst.getId(), null, null, 0, 20, "createdAt");
        assertEquals(0, unmatched.getTotalElements());
    }

    @Test
    void tSearch004WildcardSearchCharacters() {
        UserPrincipal principal = UserPrincipal.from(clientA);

        // Search literal "%"
        Page<CaseRecord> pctResult = workflow.search(principal, "100%", null, null, null, null, null, null, 0, 20, "createdAt");
        assertEquals(1, pctResult.getTotalElements());
        assertEquals(caseA1.getId(), pctResult.getContent().get(0).getId());

        // Search literal "_"
        Page<CaseRecord> underscoreResult = workflow.search(principal, "Special_", null, null, null, null, null, null, 0, 20, "createdAt");
        assertEquals(1, underscoreResult.getTotalElements());
        assertEquals(caseA1.getId(), underscoreResult.getContent().get(0).getId());

        // Search quote "'"
        Page<CaseRecord> quoteResult = workflow.search(principal, "O'Reilly", null, null, null, null, null, null, 0, 20, "createdAt");
        assertEquals(1, quoteResult.getTotalElements());
        assertEquals(caseA1.getId(), quoteResult.getContent().get(0).getId());
    }

    @Test
    void tSearch005TenantIsolationEnforced() {
        UserPrincipal principalA = UserPrincipal.from(clientA);
        Page<CaseRecord> resA = workflow.search(principalA, null, null, null, null, null, null, null, 0, 20, "createdAt");
        assertTrue(resA.getContent().stream().noneMatch(c -> c.getOrganisation().getId().equals(orgB.getId())));

        UserPrincipal principalB = UserPrincipal.from(clientB);
        Page<CaseRecord> resB = workflow.search(principalB, null, null, null, null, null, null, null, 0, 20, "createdAt");
        assertTrue(resB.getContent().stream().allMatch(c -> c.getOrganisation().getId().equals(orgB.getId())));
    }

    @Test
    void tSearch006AnalystSeesOnlyAssignedCases() {
        UserPrincipal analystPrincipal = UserPrincipal.from(analyst);
        Page<CaseRecord> analystResult = workflow.search(analystPrincipal, null, null, null, null, null, null, null, 0, 20, "createdAt");
        assertEquals(1, analystResult.getTotalElements());
        assertEquals(caseA1.getId(), analystResult.getContent().get(0).getId());
    }

    @Test
    void tSearch007ManagerSeesAllNonDeletedCases() {
        UserPrincipal managerPrincipal = UserPrincipal.from(manager);
        Page<CaseRecord> managerResult = workflow.search(managerPrincipal, null, null, null, null, null, null, null, 0, 20, "createdAt");
        assertEquals(3, managerResult.getTotalElements());
    }

    @Test
    void tSearch008AuditorAdminReceivesEmptyPage() {
        UserAccount auditor = users.save(new UserAccount(UUID.randomUUID(), orgA, "auditor@alpha.test", "hash", Role.AUDITOR_ADMIN));
        UserPrincipal auditorPrincipal = UserPrincipal.from(auditor);
        Page<CaseRecord> auditorResult = workflow.search(auditorPrincipal, null, null, null, null, null, null, null, 0, 20, "createdAt");
        assertEquals(0, auditorResult.getTotalElements());
    }
}

