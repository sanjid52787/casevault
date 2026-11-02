package uk.ac.ravensbourne.casevault.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import uk.ac.ravensbourne.casevault.audit.AuditEventType;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.config.RetentionProperties;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.repository.CaseAssignmentRepository;
import uk.ac.ravensbourne.casevault.repository.CaseNoteRepository;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.EvidenceFileRepository;
import uk.ac.ravensbourne.casevault.repository.RemediationActionRepository;
import uk.ac.ravensbourne.casevault.repository.ReportRepository;

/**
 * Purges only closed cases after their retention date. Soft deletion is an atomic conditional update;
 * hard deletion locks the candidate row, removes dependent rows, then removes ciphertext after commit.
 * This protects against duplicate work when multiple application instances schedule the same job (CWE-362).
 */
@Service
public class RetentionPurgeService {
    private static final Logger LOG = LoggerFactory.getLogger(RetentionPurgeService.class);
    private final RetentionProperties properties;
    private final Clock clock;
    private final CaseRepository cases;
    private final CaseAssignmentRepository assignments;
    private final CaseNoteRepository notes;
    private final RemediationActionRepository actions;
    private final ReportRepository reports;
    private final EvidenceFileRepository evidence;
    private final AuditService audit;
    private final Path evidenceRoot;

    public RetentionPurgeService(RetentionProperties properties, Clock clock, CaseRepository cases,
                                 CaseAssignmentRepository assignments, CaseNoteRepository notes,
                                 RemediationActionRepository actions, ReportRepository reports,
                                 EvidenceFileRepository evidence, AuditService audit,
                                 @Value("${casevault.evidence.directory:uploads}") String evidenceDirectory) {
        this.properties = properties;
        this.clock = clock;
        this.cases = cases;
        this.assignments = assignments;
        this.notes = notes;
        this.actions = actions;
        this.reports = reports;
        this.evidence = evidence;
        this.audit = audit;
        this.evidenceRoot = Paths.get(evidenceDirectory).toAbsolutePath().normalize();
    }

    @Scheduled(cron = "${casevault.retention.cron:0 0 3 * * *}")
    public void scheduledPurge() {
        if (properties.enabled()) purgeNow();
    }

    /** Runs one purge pass; exposed for authorised operational invocation and isolated integration tests. */
    @Transactional
    public RetentionPurgeResult purgeNow() {
        if (properties.graceDays() < 0) throw new IllegalStateException("Retention grace-days must not be negative");
        Instant now = clock.instant();
        int softDeleted = 0;
        for (UUID caseId : cases.findSoftDeleteCandidates(now)) {
            if (cases.claimSoftDelete(caseId, now, now) == 1) {
                softDeleted++;
                audit.record(null, AuditEventType.RETENTION_PURGE, "CASE", caseId, "soft-deleted-count-1");
            }
        }

        Instant hardDeleteBefore = now.minusSeconds(properties.graceDays() * 86_400L);
        int hardDeleted = 0;
        for (UUID caseId : cases.findHardDeleteCandidates(hardDeleteBefore)) {
            var candidate = cases.lockHardDeleteCandidate(caseId, hardDeleteBefore);
            if (candidate.isEmpty()) continue;
            hardDelete(candidate.orElseThrow());
            hardDeleted++;
            audit.record(null, AuditEventType.RETENTION_PURGE, "CASE", caseId, "hard-deleted-count-1");
        }
        return new RetentionPurgeResult(softDeleted, hardDeleted);
    }

    private void hardDelete(CaseRecord caseRecord) {
        UUID caseId = caseRecord.getId();
        List<UUID> storedNames = new ArrayList<>(evidence.findByCaseRecordId(caseId).stream()
                .map(file -> file.getStoredName()).toList());
        reports.deleteByCaseRecordId(caseId);
        actions.deleteByCaseRecordId(caseId);
        notes.deleteByCaseRecordId(caseId);
        evidence.deleteByCaseRecordId(caseId);
        assignments.deleteByCaseRecordId(caseId);
        cases.delete(caseRecord);
        cases.flush();
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                storedNames.forEach(storedName -> deleteCiphertext(caseId, storedName));
            }
        });
    }

    private void deleteCiphertext(UUID caseId, UUID storedName) {
        Path candidate = evidenceRoot.resolve(storedName.toString()).normalize();
        if (!candidate.startsWith(evidenceRoot)) {
            LOG.warn("Retention evidence cleanup rejected an invalid storage reference for caseId={}", caseId);
            return;
        }
        try {
            if (!Files.deleteIfExists(candidate)) {
                LOG.warn("Retention evidence cleanup found no ciphertext for caseId={}", caseId);
            }
        } catch (IOException exception) {
            LOG.warn("Retention evidence cleanup could not remove ciphertext for caseId={}", caseId);
        }
    }

    public record RetentionPurgeResult(int softDeleted, int hardDeleted) { }
}
