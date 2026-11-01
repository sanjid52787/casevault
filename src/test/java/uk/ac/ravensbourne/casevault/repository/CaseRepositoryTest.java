package uk.ac.ravensbourne.casevault.repository;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

@DataJpaTest
@ActiveProfiles("test")
class CaseRepositoryTest {
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;
    @Autowired JdbcTemplate jdbc;

    @BeforeEach @AfterEach
    void cleanFixtures() { TestDataCleaner.clean(jdbc); }

    @Test
    void tAuthz005TenantDerivedQueryDoesNotCrossOrganisation() {
        var first = organisations.save(new Organisation(UUID.randomUUID(), "First Org"));
        var second = organisations.save(new Organisation(UUID.randomUUID(), "Second Org"));
        var user = users.save(new UserAccount(UUID.randomUUID(), first, "first@example.test", "hash", Role.CLIENT_USER));
        var record = cases.save(new CaseRecord(UUID.randomUUID(), first, "Synthetic incident", "Synthetic description",
                Category.OTHER, Severity.LOW, user));
        assertTrue(cases.findByIdAndOrganisationId(record.getId(), first.getId()).isPresent());
        assertTrue(cases.findByIdAndOrganisationId(record.getId(), second.getId()).isEmpty());
    }
}
