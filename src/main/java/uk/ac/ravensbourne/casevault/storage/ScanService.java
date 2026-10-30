package uk.ac.ravensbourne.casevault.storage;

import java.nio.file.Path;

/**
 * Integration seam for an isolated malware scanner. CaseVault never submits evidence to a
 * third party scanner: production deployments must provide a local implementation.
 */
public interface ScanService {
    ScanResult scan(Path candidate);

    enum ScanResult {
        CLEAN,
        REJECTED,
        UNAVAILABLE
    }
}
