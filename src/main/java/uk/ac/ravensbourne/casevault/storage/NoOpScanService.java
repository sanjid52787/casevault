package uk.ac.ravensbourne.casevault.storage;

import java.nio.file.Path;
import org.springframework.stereotype.Service;

/**
 * Development and test scanner seam. It performs no malware detection and therefore must be
 * replaced by a local isolated scanner before a non-academic deployment (CWE-434).
 */
@Service
public class NoOpScanService implements ScanService {
    @Override
    public ScanResult scan(Path candidate) {
        return ScanResult.CLEAN;
    }
}
