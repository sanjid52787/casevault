package uk.ac.ravensbourne.casevault.service;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import uk.ac.ravensbourne.casevault.audit.PersistentAuditService;
import uk.ac.ravensbourne.casevault.domain.CaseNote;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.EvidenceFile;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.RemediationAction;
import uk.ac.ravensbourne.casevault.domain.ReportRecord;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseNoteRepository;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.EvidenceFileRepository;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.RemediationActionRepository;
import uk.ac.ravensbourne.casevault.repository.ReportRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/** T-RET-001..005: retention removes only closed cases and preserves audit-chain integrity. */
@SpringBootTest(properties = {
        "casevault.evidence.directory=target/retention-purge-test-evidence",
        "casevault.retention.enabled=false",
        "casevault.retention.grace-days=2"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RetentionPurgeServiceTest {
    private static final Path EVIDENCE_ROOT = Path.of("target/retention-purge-test-evidence").toAbsolutePath();

    @Autowired RetentionPurgeService retention;
    @Autowired PersistentAuditService audit;
    @Autowired EvidenceService evidence;
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;
    @Autowired CaseNoteRepository notes;
    @Autowired RemediationActionRepository actions;
    @Autowired ReportRepository reports;
    @Autowired EvidenceFileRepository evidenceFiles;
    @Autowired TestDataCleaner cleaner;

    private UserAccount client;
    private CaseRecord caseRecord;

    @BeforeEach
    void setUp() throws Exception {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        cleaner.clean();
        Files.createDirectories(EVIDENCE_ROOT);
        try (var paths = Files.list(EVIDENCE_ROOT)) {
            for (Path path : paths.toList()) Files.deleteIfExists(path);
        }
        Organisation organisation = organisations.save(new Organisation(UUID.randomUUID(), "Retention client"));
        client = users.save(new UserAccount(UUID.randomUUID(), organisation, "retention-client@test", "hash", Role.CLIENT_USER));
        caseRecord = cases.save(new CaseRecord(UUID.randomUUID(), organisation, "Expired synthetic case", "Synthetic",
                Category.OTHER, Severity.LOW, client));
    }

    @AfterEach
    void tearDown() {
        cleaner.clean();
    }

    @Test
    void tRet001ClosedExpiredCaseIsSoftDeletedAndHiddenFromClientList() throws Exception {
        closeAndExpire(caseRecord, null);

        assertEquals(1, retention.purgeNow().softDeleted());
        assertNotNull(jdbc.queryForObject("SELECT deleted_at FROM cases WHERE id=?", Object.class, caseRecord.getId()));
        mvc.perform(get("/cases").with(authentication(auth(client))))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("Expired synthetic case"))));
    }

    @Test
    void tRet002HardDeleteRemovesDependentRowsAndCiphertext() throws Exception {
        notes.save(new CaseNote(UUID.randomUUID(), caseRecord, client, "synthetic note", true));
        actions.save(new RemediationAction(UUID.randomUUID(), caseRecord, client, "synthetic action"));
        reports.save(new ReportRecord(UUID.randomUUID(), caseRecord, caseRecord.getOrganisation(), client));
        EvidenceFile stored = uploadEvidence();
        Path ciphertext = EVIDENCE_ROOT.resolve(stored.getStoredName().toString());
        assertTrueExists(ciphertext);

        closeAndExpire(caseRecord, Instant.now().minus(3, ChronoUnit.DAYS));
        assertEquals(1, retention.purgeNow().hardDeleted());

        assertFalse(cases.existsById(caseRecord.getId()));
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM case_notes WHERE case_id=?", Integer.class, caseRecord.getId()));
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM remediation_actions WHERE case_id=?", Integer.class, caseRecord.getId()));
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM reports WHERE case_id=?", Integer.class, caseRecord.getId()));
        assertEquals(0, evidenceFiles.countByCaseRecordId(caseRecord.getId()));
        assertFalse(Files.exists(ciphertext));
    }

    @Test
    void tRet003OpenCaseIsNeverPurged() {
        jdbc.update("UPDATE cases SET retention_until=? WHERE id=?", Instant.now().minus(2, ChronoUnit.DAYS), caseRecord.getId());

        var result = retention.purgeNow();
        assertEquals(0, result.softDeleted());
        assertEquals(0, result.hardDeleted());
        assertTrueExistsInDatabase(caseRecord.getId());
    }

    @Test
    void tRet004RetentionEventsKeepAuditChainValid() {
        closeAndExpire(caseRecord, null);

        retention.purgeNow();
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM audit_events WHERE action='RETENTION_PURGE'", Integer.class));
        assertTrue(audit.verifyChain().valid());
    }

    @Test
    void tRet005MissingCiphertextDoesNotAbortHardDelete() throws Exception {
        EvidenceFile stored = uploadEvidence();
        Files.deleteIfExists(EVIDENCE_ROOT.resolve(stored.getStoredName().toString()));
        closeAndExpire(caseRecord, Instant.now().minus(3, ChronoUnit.DAYS));

        assertDoesNotThrow(() -> retention.purgeNow());
        assertFalse(cases.existsById(caseRecord.getId()));
        assertEquals(0, evidenceFiles.countByCaseRecordId(caseRecord.getId()));
    }

    private EvidenceFile uploadEvidence() throws Exception {
        return evidence.upload(UserPrincipal.from(client), caseRecord.getId(),
                new MockMultipartFile("file", "retention.txt", "application/octet-stream", "inert retention evidence".getBytes()));
    }

    private void closeAndExpire(CaseRecord record, Instant deletedAt) {
        Instant retentionUntil = Instant.now().minus(1, ChronoUnit.DAYS);
        jdbc.update("UPDATE cases SET status='CLOSED', retention_until=?, deleted_at=? WHERE id=?", retentionUntil, deletedAt, record.getId());
    }

    private UsernamePasswordAuthenticationToken auth(UserAccount account) {
        UserPrincipal principal = UserPrincipal.from(account);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }

    private void assertTrueExists(Path path) {
        if (!Files.exists(path)) throw new AssertionError("Expected ciphertext file to exist");
    }

    private void assertTrueExistsInDatabase(UUID caseId) {
        if (!cases.existsById(caseId)) throw new AssertionError("Expected case to remain in the database");
    }
}
