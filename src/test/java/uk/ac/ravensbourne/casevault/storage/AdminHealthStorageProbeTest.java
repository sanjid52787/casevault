package uk.ac.ravensbourne.casevault.storage;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/** T-ADMIN-006: evidence-storage health checks must be safe, useful and auditor-only. */
@SpringBootTest(properties = "casevault.evidence.directory=target/admin-health-storage-test")
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AdminHealthStorageProbeTest {
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired EvidenceStorageHealthProbe storageHealth;

    private UserAccount auditor;
    private UserAccount manager;

    @BeforeEach
    void setUp() {
        TestDataCleaner.clean(jdbc);
        Organisation organisation = organisations.save(new Organisation(UUID.randomUUID(), "Health Test Organisation"));
        auditor = users.save(new UserAccount(UUID.randomUUID(), organisation, "health-auditor@example.test",
                "hash", Role.AUDITOR_ADMIN));
        manager = users.save(new UserAccount(UUID.randomUUID(), organisation, "health-manager@example.test",
                "hash", Role.CASE_MANAGER));
    }

    @AfterEach
    void cleanUp() {
        TestDataCleaner.clean(jdbc);
    }

    @Test
    void tAdmin006StorageProbeIsSafeAndHealthPageIsAuditorOnly(@TempDir Path temporaryDirectory) throws Exception {
        assertEquals(EvidenceStorageHealthProbe.Status.OK, storageHealth.probe());

        Path unusableDirectory = Files.writeString(temporaryDirectory.resolve("not-a-directory"), "inert");
        assertEquals(EvidenceStorageHealthProbe.Status.FAIL,
                new EvidenceStorageHealthProbe(unusableDirectory).probe());

        mvc.perform(get("/admin/health").with(authentication(authenticationFor(auditor))))
                .andExpect(status().isOk())
                .andExpect(header().exists("X-Correlation-ID"))
                .andExpect(content().string(containsString("Evidence storage")))
                .andExpect(content().string(containsString("OK")))
                .andExpect(content().string(not(containsString("target/admin-health-storage-test"))))
                .andExpect(content().string(not(containsString(temporaryDirectory.toString()))));

        mvc.perform(get("/admin/health").with(authentication(authenticationFor(manager))))
                .andExpect(status().isForbidden());
    }

    private UsernamePasswordAuthenticationToken authenticationFor(UserAccount account) {
        UserPrincipal principal = UserPrincipal.from(account);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }
}
