package uk.ac.ravensbourne.casevault.storage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Performs a non-disclosing evidence-store health probe. It creates and removes a server-generated
 * temporary file, proving that the evidence directory is usable without ever returning its path or
 * an exception to an administrator (CWE-200).
 */
@Service
public final class EvidenceStorageHealthProbe {
    public enum Status { OK, FAIL }

    private final Path directory;

    @Autowired
    public EvidenceStorageHealthProbe(@Value("${casevault.evidence.directory:uploads}") String directory) {
        this(Paths.get(directory).toAbsolutePath().normalize());
    }

    EvidenceStorageHealthProbe(Path directory) {
        this.directory = directory;
    }

    /** Returns only the safe health result; storage paths and exception details remain private. */
    public Status probe() {
        Path temporaryFile = null;
        try {
            Files.createDirectories(directory);
            temporaryFile = Files.createTempFile(directory, ".casevault-health-", ".tmp");
            Files.delete(temporaryFile);
            return Status.OK;
        } catch (IOException | RuntimeException exception) {
            if (temporaryFile != null) {
                try {
                    Files.deleteIfExists(temporaryFile);
                } catch (IOException | RuntimeException ignored) {
                    // Best-effort removal only: the result is already FAIL and no detail is exposed.
                }
            }
            return Status.FAIL;
        }
    }
}
