package uk.ac.ravensbourne.casevault.service;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.multipart.MultipartFile;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.EvidenceFile;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.EvidenceFileRepository;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/** Inert, programmatically-created file checks for the Phase 6 validation and crypto controls. */
@SpringBootTest(properties = "casevault.evidence.directory=target/evidence-security-test")
@ActiveProfiles("test")
class EvidenceSecurityTest {
    private static final Path EVIDENCE_ROOT = Path.of("target/evidence-security-test").toAbsolutePath();
    private static final byte[] PNG = Base64.getDecoder().decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9J1N8AAAAASUVORK5CYII=");

    @Autowired EvidenceService evidence;
    @Autowired EvidenceFileRepository evidenceFiles;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;
    @Autowired JdbcTemplate jdbc;

    private UserAccount client;
    private CaseRecord caseOne;
    private CaseRecord caseTwo;

    @BeforeEach
    void setUp() throws IOException {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        jdbc.update("DELETE FROM evidence_files");
        jdbc.update("DELETE FROM reports");
        jdbc.update("DELETE FROM remediation_actions");
        jdbc.update("DELETE FROM case_notes");
        jdbc.update("DELETE FROM case_assignments");
        cases.deleteAll();
        users.deleteAll();
        organisations.deleteAll();
        Files.createDirectories(EVIDENCE_ROOT);
        try (var paths = Files.list(EVIDENCE_ROOT)) {
            for (Path path : paths.toList()) Files.deleteIfExists(path);
        }
        Organisation organisation = organisations.save(new Organisation(UUID.randomUUID(), "Evidence Client"));
        client = users.save(new UserAccount(UUID.randomUUID(), organisation, "evidence-client@test", "hash", Role.CLIENT_USER));
        caseOne = cases.save(new CaseRecord(UUID.randomUUID(), organisation, "Evidence case one", "Synthetic case",
                Category.OTHER, Severity.LOW, client));
        caseTwo = cases.save(new CaseRecord(UUID.randomUUID(), organisation, "Evidence case two", "Synthetic case",
                Category.OTHER, Severity.LOW, client));
    }

    @Test
    void tFile001ValidTxtPdfAndPngAccepted() throws Exception {
        assertDoesNotThrow(() -> upload(caseOne, "notes.txt", "inert text evidence".getBytes()));
        assertDoesNotThrow(() -> upload(caseOne, "report.pdf", "%PDF-1.4\nsynthetic\n%%EOF".getBytes()));
        assertDoesNotThrow(() -> upload(caseOne, "image.png", PNG));
        assertEquals(3, evidenceFiles.count());
    }

    @Test
    void tFile002OversizeRejectedBeforeBodyRead() {
        assertThrows(EvidenceRejectedException.class, () -> evidence.upload(principal(), caseOne.getId(), new OversizeFile()));
        assertEquals(1, countAudit("EVIDENCE_REJECTED", "size-invalid"));
    }

    @Test
    void tFile003DisguisedFilesRejected() {
        assertRejected("image.png", "plain text".getBytes());
        assertRejected("notes.txt", PNG);
        assertRejected("report.pdf", new byte[] {0x7f, 'E', 'L', 'F'});
        assertRejected("report.pdf", new byte[] {'M', 'Z', 0, 0});
        assertRejected("report.pdf", new byte[] {(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe});
    }

    @Test
    void tFile004PathTraversalNeutralisedAndControlCharactersRejected() throws Exception {
        EvidenceFile saved = upload(caseOne, "../safe.txt", "safe inert content".getBytes());
        assertEquals("safe.txt", saved.getName());
        assertThrows(EvidenceRejectedException.class,
                () -> upload(caseOne, "bad\u0000name.txt", "safe inert content".getBytes()));
        assertThrows(EvidenceRejectedException.class,
                () -> upload(caseOne, "bad\nname.txt", "safe inert content".getBytes()));
    }

    @Test
    void tFile005DoubleExtensionsRejected() {
        assertRejected("report.pdf.exe", "safe inert content".getBytes());
        assertRejected("notes.txt.png", PNG);
    }

    @Test
    void tFile006StoredBytesAreCiphertextAndFilenameIsRandom() throws Exception {
        byte[] marker = "UNIQUE-INERT-PLAINTEXT-MARKER".getBytes();
        EvidenceFile saved = upload(caseOne, "marker.txt", marker);
        Path stored = EVIDENCE_ROOT.resolve(saved.getStoredName().toString());
        byte[] onDisk = Files.readAllBytes(stored);
        assertFalse(new String(onDisk).contains("UNIQUE-INERT-PLAINTEXT-MARKER"));
        assertNotEquals(marker.length, onDisk.length);
        assertDoesNotThrow(() -> UUID.fromString(stored.getFileName().toString()));
        assertNotEquals("marker.txt", stored.getFileName().toString());
    }

    @Test
    void tFile007TamperedCiphertextFailsGcmAndIsAudited() throws Exception {
        EvidenceFile saved = upload(caseOne, "tampered.txt", "inert evidence".getBytes());
        Path stored = EVIDENCE_ROOT.resolve(saved.getStoredName().toString());
        byte[] ciphertext = Files.readAllBytes(stored);
        ciphertext[ciphertext.length - 1] ^= 1;
        Files.write(stored, ciphertext);
        EvidenceRejectedException exception = assertThrows(EvidenceRejectedException.class,
                () -> evidence.download(principal(), caseOne.getId(), saved.getId()));
        assertEquals("Evidence rejected", exception.getMessage());
        assertEquals(1, countAudit("EVIDENCE_REJECTED", "integrity-check-failed"));
    }

    @Test
    void tFile008CiphertextMovedToAnotherRecordFailsAssociatedData() throws Exception {
        EvidenceFile first = upload(caseOne, "first.txt", "first inert content".getBytes());
        EvidenceFile second = upload(caseTwo, "second.txt", "second inert content".getBytes());
        Files.copy(EVIDENCE_ROOT.resolve(first.getStoredName().toString()),
                EVIDENCE_ROOT.resolve(second.getStoredName().toString()), StandardCopyOption.REPLACE_EXISTING);
        assertThrows(EvidenceRejectedException.class,
                () -> evidence.download(principal(), caseTwo.getId(), second.getId()));
        assertEquals(1, countAudit("EVIDENCE_REJECTED", "integrity-check-failed"));
    }

    @Test
    void tFile012StoredSha256MatchesAndModifiedHashIsRejected() throws Exception {
        byte[] plaintext = "hashable inert content".getBytes();
        EvidenceFile saved = upload(caseOne, "hash.txt", plaintext);
        String expected = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(plaintext));
        assertEquals(expected, saved.getSha256().trim());
        assertArrayEquals(plaintext, evidence.download(principal(), caseOne.getId(), saved.getId()));
        jdbc.update("UPDATE evidence_files SET sha256=? WHERE id=?", "0".repeat(64), saved.getId());
        assertThrows(EvidenceRejectedException.class,
                () -> evidence.download(principal(), caseOne.getId(), saved.getId()));
    }

    private EvidenceFile upload(CaseRecord target, String name, byte[] content) throws IOException {
        return evidence.upload(principal(), target.getId(),
                new MockMultipartFile("file", name, "application/octet-stream", content));
    }

    private void assertRejected(String name, byte[] content) {
        assertThrows(EvidenceRejectedException.class, () -> upload(caseOne, name, content));
    }

    private UserPrincipal principal() {
        return UserPrincipal.from(client);
    }

    private int countAudit(String action, String event) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM audit_events WHERE action=? AND details_json=?", Integer.class,
                action, "{\"event\":\"" + event + "\"}");
    }

    private static final class OversizeFile implements MultipartFile {
        @Override public String getName() { return "file"; }
        @Override public String getOriginalFilename() { return "large.txt"; }
        @Override public String getContentType() { return "application/octet-stream"; }
        @Override public boolean isEmpty() { return false; }
        @Override public long getSize() { return 10L * 1024 * 1024 + 1; }
        @Override public byte[] getBytes() { throw new AssertionError("Body must not be read"); }
        @Override public InputStream getInputStream() { return new ByteArrayInputStream(new byte[0]); }
        @Override public void transferTo(File destination) { throw new UnsupportedOperationException(); }
    }
}
