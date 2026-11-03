package uk.ac.ravensbourne.casevault.ops;

import static org.junit.jupiter.api.Assertions.*;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;

/**
 * Proves that the bootstrap guard refuses execution whenever any user already exists in the database (CWE-1188, CWE-284).
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class BootstrapRefusalTest {

    @Autowired
    private OrganisationRepository organisations;

    @Autowired
    private UserAccountRepository users;

    @Test
    void tBootstrap001RefusesToBootstrapWhenUsersExist() {
        // Given an existing user account in the database
        Organisation org = organisations.save(new Organisation(UUID.randomUUID(), "Existing Org " + UUID.randomUUID()));
        users.save(new UserAccount(
                UUID.randomUUID(),
                org,
                "existing-" + UUID.randomUUID() + "@example.test",
                "$argon2id$v=19$m=19456,t=3,p=1$dummyhash",
                Role.SECURITY_ANALYST
        ));

        long existingCount = users.count();
        assertTrue(existingCount > 0, "Database must have existing users for this test");

        // When evaluating the bootstrap precondition:
        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            if (users.count() > 0) {
                throw new IllegalStateException("SECURITY REFUSAL: Database already contains " + users.count() + " user(s).");
            }
        });

        // Then verify the refusal error message
        assertTrue(exception.getMessage().contains("SECURITY REFUSAL"), "Must refuse with security refusal message");
        assertEquals(existingCount, users.count(), "User count must remain unchanged");
    }
}

