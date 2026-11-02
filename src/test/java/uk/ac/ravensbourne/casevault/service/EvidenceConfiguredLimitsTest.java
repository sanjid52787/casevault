package uk.ac.ravensbourne.casevault.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.EvidenceFileRepository;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/** T-FILE-014/015: configured evidence limits reject storage exhaustion before persistence. */
@SpringBootTest(properties = {
        "casevault.evidence.directory=target/evidence-configured-limits-test",
        "casevault.evidence.max-files-per-case=2",
        "casevault.evidence.max-bytes=4"
})
@ActiveProfiles("test")
class EvidenceConfiguredLimitsTest {
    private static final Path ROOT = Path.of("target/evidence-configured-limits-test").toAbsolutePath();

    @Autowired EvidenceService evidence;
    @Autowired EvidenceFileRepository files;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;
    @Autowired JdbcTemplate jdbc;
    @Autowired TestDataCleaner cleaner;

    private UserAccount client;
    private CaseRecord caseRecord;

    @BeforeEach
    void setUp() throws IOException {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        cleaner.clean();
        Files.createDirectories(ROOT);
        try (var paths = Files.list(ROOT)) {
            for (Path path : paths.toList()) Files.deleteIfExists(path);
        }
        Organisation organisation = organisations.save(new Organisation(UUID.randomUUID(), "Limit client"));
        client = users.save(new UserAccount(UUID.randomUUID(), organisation, "limit-client@test", "hash", Role.CLIENT_USER));
        caseRecord = cases.save(new CaseRecord(UUID.randomUUID(), organisation, "Limit case", "Synthetic",
                Category.OTHER, Severity.LOW, client));
    }

    @AfterEach
    void tearDown() {
        cleaner.clean();
    }

    @Test
    void tFile014ConfiguredPerCaseFileCapRejectsTheNextUpload() throws Exception {
        upload("one.txt", "one");
        upload("two.txt", "two");
        assertThrows(EvidenceRejectedException.class, () -> upload("three.txt", "tri"));
        assertEquals(2, files.countByCaseRecordId(caseRecord.getId()));
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM audit_events WHERE action='EVIDENCE_REJECTED' AND details_json='{\"event\":\"case-file-limit\"}'", Integer.class));
    }

    @Test
    void tFile015ConfiguredSizeLimitOverridesTheDefault() {
        assertThrows(EvidenceRejectedException.class, () -> upload("large.txt", "12345"));
        assertEquals(0, files.countByCaseRecordId(caseRecord.getId()));
    }

    private void upload(String filename, String content) throws IOException {
        evidence.upload(UserPrincipal.from(client), caseRecord.getId(),
                new MockMultipartFile("file", filename, "application/octet-stream", content.getBytes()));
    }
}
