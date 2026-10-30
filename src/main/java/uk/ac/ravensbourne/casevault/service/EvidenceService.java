package uk.ac.ravensbourne.casevault.service;

import com.google.crypto.tink.Aead;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.apache.tika.Tika;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.crypto.KeysetProvider;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.EvidenceFile;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.EvidenceFileRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.storage.ScanService;

/**
 * Validates and stores evidence using a fail-closed pipeline. The client filename is metadata
 * only; ciphertext is addressed by a generated UUID and bound to its case and evidence UUID by
 * Tink AEAD associated data (CWE-22, CWE-434, CWE-311).
 */
@Service
public class EvidenceService {
    private static final long MAX_SIZE_BYTES = 10L * 1024 * 1024;
    private static final int MAX_FILENAME_LENGTH = 120;
    private static final Map<String, String> EXTENSIONS = Map.of(
            "txt", "text/plain", "pdf", "application/pdf", "png", "image/png");

    private final CaseAccessService access;
    private final AccessPolicy policy;
    private final CaseRepository cases;
    private final EvidenceFileRepository files;
    private final UserAccountRepository users;
    private final AuditService audit;
    private final ScanService scanner;
    private final Aead aead;
    private final Path root;
    private final Tika tika = new Tika();

    public EvidenceService(CaseAccessService access, AccessPolicy policy, CaseRepository cases,
                           EvidenceFileRepository files, UserAccountRepository users, AuditService audit,
                           ScanService scanner, KeysetProvider keysetProvider,
                           @Value("${casevault.evidence.directory:uploads}") String directory) throws Exception {
        this.access = access;
        this.policy = policy;
        this.cases = cases;
        this.files = files;
        this.users = users;
        this.audit = audit;
        this.scanner = scanner;
        this.aead = keysetProvider.aead();
        this.root = Paths.get(directory).toAbsolutePath().normalize();
        Files.createDirectories(root);
    }

    public EvidenceFile upload(UserPrincipal principal, UUID caseId, MultipartFile multipart) throws IOException {
        CaseRecord caseRecord = access.requireView(principal, caseId);
        boolean assigned = cases.existsAssignment(caseId, principal.id());
        if (!policy.canUploadEvidence(principal, caseRecord, assigned)) {
            throw new CaseNotFoundException();
        }

        // Fail-closed order: size, filename, extension, magic bytes, executable header, scanner,
        // hash, AEAD encryption, then storage.
        if (multipart.isEmpty() || multipart.getSize() > MAX_SIZE_BYTES) {
            throw rejected(principal, null, "size-invalid");
        }
        String displayName = sanitiseFilename(multipart.getOriginalFilename(), principal);
        String extension = extension(displayName, principal);
        byte[] plaintext = multipart.getBytes(); // Bounded above; documented residual risk.
        String detectedMime = tika.detect(plaintext);
        if (!EXTENSIONS.get(extension).equals(detectedMime)) {
            throw rejected(principal, null, "content-type-mismatch");
        }
        if (hasExecutableSignature(plaintext)) {
            throw rejected(principal, null, "executable-signature");
        }

        Path scanCandidate = Files.createTempFile(root, "scan-", ".tmp");
        try {
            Files.write(scanCandidate, plaintext, StandardOpenOption.TRUNCATE_EXISTING);
            if (scanner.scan(scanCandidate) != ScanService.ScanResult.CLEAN) {
                throw rejected(principal, null, "scan-not-clean");
            }
        } finally {
            Files.deleteIfExists(scanCandidate);
        }

        String sha256 = sha256(plaintext);
        UUID evidenceId = UUID.randomUUID();
        UUID storedName = UUID.randomUUID();
        Path storagePath = storagePath(storedName);
        try {
            byte[] ciphertext = aead.encrypt(plaintext, associatedData(caseId, evidenceId));
            Files.write(storagePath, ciphertext, StandardOpenOption.CREATE_NEW);
            EvidenceFile saved = files.save(new EvidenceFile(evidenceId, caseRecord, displayName, storedName,
                    detectedMime, plaintext.length, sha256,
                    users.findById(principal.id()).orElseThrow(CaseNotFoundException::new)));
            audit.record(principal, "EVIDENCE_UPLOADED", "EVIDENCE", evidenceId, "evidence-uploaded");
            return saved;
        } catch (GeneralSecurityException | IOException exception) {
            Files.deleteIfExists(storagePath);
            throw rejected(principal, evidenceId, "storage-failed");
        }
    }

    public byte[] download(UserPrincipal principal, UUID caseId, UUID evidenceId) {
        CaseRecord caseRecord = access.requireView(principal, caseId);
        EvidenceFile evidence = files.findByIdAndCaseRecordId(evidenceId, caseId)
                .orElseThrow(CaseNotFoundException::new);
        if (!policy.canDownloadEvidence(principal, caseRecord, cases.existsAssignment(caseId, principal.id()))) {
            throw new CaseNotFoundException();
        }
        try {
            byte[] ciphertext = Files.readAllBytes(storagePath(evidence.getStoredName()));
            byte[] plaintext = aead.decrypt(ciphertext, associatedData(caseId, evidenceId));
            if (!MessageDigest.isEqual(hexToBytes(evidence.getSha256()), hexToBytes(sha256(plaintext)))) {
                throw new GeneralSecurityException("Evidence digest mismatch");
            }
            audit.record(principal, "EVIDENCE_DOWNLOADED", "EVIDENCE", evidenceId, "evidence-downloaded");
            return plaintext;
        } catch (GeneralSecurityException | IOException | IllegalArgumentException exception) {
            throw rejected(principal, evidenceId, "integrity-check-failed");
        }
    }

    private EvidenceRejectedException rejected(UserPrincipal principal, UUID evidenceId, String reason) {
        audit.record(principal, "EVIDENCE_REJECTED", "EVIDENCE", evidenceId, reason);
        return new EvidenceRejectedException();
    }

    private String sanitiseFilename(String originalName, UserPrincipal principal) {
        if (originalName == null || originalName.indexOf('\0') >= 0 || originalName.chars().anyMatch(Character::isISOControl)) {
            throw rejected(principal, null, "filename-invalid");
        }
        String displayName;
        try {
            displayName = Paths.get(originalName.replace('\\', '/')).getFileName().toString().trim();
        } catch (InvalidPathException exception) {
            throw rejected(principal, null, "filename-invalid");
        }
        if (displayName.isBlank() || displayName.length() > MAX_FILENAME_LENGTH
                || !displayName.matches("[\\p{L}\\p{N}][\\p{L}\\p{N} ._()\\-]*")) {
            throw rejected(principal, null, "filename-invalid");
        }
        return displayName;
    }

    private String extension(String displayName, UserPrincipal principal) {
        int firstDot = displayName.indexOf('.');
        int lastDot = displayName.lastIndexOf('.');
        if (firstDot <= 0 || firstDot != lastDot || lastDot == displayName.length() - 1) {
            throw rejected(principal, null, "extension-invalid");
        }
        String extension = displayName.substring(lastDot + 1).toLowerCase(Locale.ROOT);
        if (!EXTENSIONS.containsKey(extension)) {
            throw rejected(principal, null, "extension-invalid");
        }
        return extension;
    }

    private boolean hasExecutableSignature(byte[] bytes) {
        return startsWith(bytes, 0x7f, 'E', 'L', 'F') || startsWith(bytes, 'M', 'Z')
                || startsWith(bytes, 0xca, 0xfe, 0xba, 0xbe) || startsWith(bytes, 0xfe, 0xed, 0xfa, 0xce)
                || startsWith(bytes, 0xfe, 0xed, 0xfa, 0xcf) || startsWith(bytes, 0xce, 0xfa, 0xed, 0xfe)
                || startsWith(bytes, 0xcf, 0xfa, 0xed, 0xfe) || startsWith(bytes, 0xbe, 0xba, 0xfe, 0xca)
                || startsWith(bytes, '#', '!') || startsWith(bytes, '<', '?', 'p', 'h', 'p')
                || startsWithIgnoreCase(bytes, "@echo") || startsWithIgnoreCase(bytes, "powershell");
    }

    private boolean startsWith(byte[] bytes, int... signature) {
        if (bytes.length < signature.length) return false;
        for (int index = 0; index < signature.length; index++) {
            if ((bytes[index] & 0xff) != signature[index]) return false;
        }
        return true;
    }

    private boolean startsWithIgnoreCase(byte[] bytes, String text) {
        if (bytes.length < text.length()) return false;
        return new String(bytes, 0, text.length(), StandardCharsets.US_ASCII).equalsIgnoreCase(text);
    }

    private Path storagePath(UUID storedName) {
        Path candidate = root.resolve(storedName.toString()).normalize();
        if (!candidate.startsWith(root)) throw new IllegalStateException("Invalid evidence storage path");
        return candidate;
    }

    private byte[] associatedData(UUID caseId, UUID evidenceId) {
        return (caseId + ":" + evidenceId).getBytes(StandardCharsets.UTF_8);
    }

    private String sha256(byte[] content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    private byte[] hexToBytes(String value) {
        return HexFormat.of().parseHex(value.trim());
    }
}
