package uk.ac.ravensbourne.casevault.ops;

import com.google.crypto.tink.Aead;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import uk.ac.ravensbourne.casevault.audit.PersistentAuditService;
import uk.ac.ravensbourne.casevault.crypto.KeysetProvider;
import uk.ac.ravensbourne.casevault.domain.EvidenceFile;
import uk.ac.ravensbourne.casevault.repository.EvidenceFileRepository;

/**
 * One-shot recovery drill verifier. It is unavailable in normal profiles and exposes no HTTP endpoint.
 * It verifies audit tamper evidence and one encrypted synthetic evidence object after a restore (CWE-345, CWE-311).
 */
@Component
@Profile("restore-verification")
public final class RestoreVerificationRunner implements ApplicationRunner {
    private static final Logger LOG = LoggerFactory.getLogger(RestoreVerificationRunner.class);

    private final PersistentAuditService auditService;
    private final EvidenceFileRepository evidenceFiles;
    private final Aead aead;
    private final Path evidenceDirectory;
    private final ConfigurableApplicationContext context;

    public RestoreVerificationRunner(PersistentAuditService auditService,
                                     EvidenceFileRepository evidenceFiles,
                                     KeysetProvider keysetProvider,
                                     @Value("${casevault.evidence.directory}") String evidenceDirectory,
                                     ConfigurableApplicationContext context) throws Exception {
        this.auditService = auditService;
        this.evidenceFiles = evidenceFiles;
        this.aead = keysetProvider.aead();
        this.evidenceDirectory = Path.of(evidenceDirectory).toAbsolutePath().normalize();
        this.context = context;
    }

    @Override
    public void run(ApplicationArguments arguments) throws Exception {
        var chain = auditService.verifyChain();
        if (!chain.valid()) {
            throw new IllegalStateException("Restored audit chain verification failed");
        }

        EvidenceFile sample = evidenceFiles.findAll().stream().findFirst()
                .orElseThrow(() -> new IllegalStateException("Restore drill requires one synthetic evidence record"));
        Path ciphertext = evidenceDirectory.resolve(sample.getStoredName().toString()).normalize();
        if (!ciphertext.startsWith(evidenceDirectory) || !Files.isRegularFile(ciphertext)) {
            throw new IllegalStateException("Restored evidence ciphertext is unavailable");
        }
        byte[] plaintext = aead.decrypt(Files.readAllBytes(ciphertext), associatedData(sample));
        byte[] expected = HexFormat.of().parseHex(sample.getSha256());
        byte[] actual = MessageDigest.getInstance("SHA-256").digest(plaintext);
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new IllegalStateException("Restored evidence integrity verification failed");
        }
        LOG.info("Restore verification completed: audit chain valid and one encrypted evidence object verified");
        context.close();
    }

    private byte[] associatedData(EvidenceFile evidence) {
        return (evidence.getCaseRecord().getId() + ":" + evidence.getId()).getBytes(StandardCharsets.UTF_8);
    }
}
