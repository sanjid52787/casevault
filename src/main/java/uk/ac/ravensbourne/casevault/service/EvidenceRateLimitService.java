package uk.ac.ravensbourne.casevault.service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.Refill;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.stereotype.Service;
import uk.ac.ravensbourne.casevault.common.TestOnly;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/**
 * Applies independent per-user and per-source-IP quotas before an evidence transfer. A small
 * secondary quota aggregates denial audit events so a flood cannot flood the audit chain.
 */
@Service
public class EvidenceRateLimitService {
    private final ConcurrentMap<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Bucket> denialAuditBuckets = new ConcurrentHashMap<>();
    private final AuditService audit;

    public EvidenceRateLimitService(AuditService audit) {
        this.audit = audit;
    }

    public void checkUpload(UserPrincipal principal, String sourceIp, UUID caseId) {
        check("upload", principal, sourceIp, caseId, 10, 30);
    }

    public void checkDownload(UserPrincipal principal, String sourceIp, UUID caseId) {
        check("download", principal, sourceIp, caseId, 30, 60);
    }

    /** Clears in-memory state between tests; production callers are blocked by an architecture rule. */
    @TestOnly
    public void reset() {
        buckets.clear();
        denialAuditBuckets.clear();
    }

    private void check(String operation, UserPrincipal principal, String sourceIp, UUID caseId,
                       long userCapacity, long ipCapacity) {
        ConsumptionProbe user = bucket(operation + ":user:" + principal.id(), userCapacity)
                .tryConsumeAndReturnRemaining(1);
        ConsumptionProbe ip = bucket(operation + ":ip:" + normaliseIp(sourceIp), ipCapacity)
                .tryConsumeAndReturnRemaining(1);
        if (user.isConsumed() && ip.isConsumed()) {
            return;
        }
        String auditKey = operation + ":" + principal.id();
        if (denialAuditBuckets.computeIfAbsent(auditKey, ignored -> newBucket(1)).tryConsume(1)) {
            audit.record(principal, "RATE_LIMITED", "EVIDENCE", caseId, operation + "-rate-limited");
        }
        long waitNanos = Math.max(user.isConsumed() ? 0 : user.getNanosToWaitForRefill(),
                ip.isConsumed() ? 0 : ip.getNanosToWaitForRefill());
        throw new EvidenceRateLimitExceededException(Math.max(1, (waitNanos + 999_999_999L) / 1_000_000_000L));
    }

    private Bucket bucket(String key, long capacity) {
        return buckets.computeIfAbsent(key, ignored -> newBucket(capacity));
    }

    private Bucket newBucket(long capacity) {
        return Bucket.builder().addLimit(Bandwidth.classic(capacity,
                Refill.greedy(capacity, Duration.ofMinutes(1)))).build();
    }

    private String normaliseIp(String sourceIp) {
        return sourceIp == null || sourceIp.isBlank() ? "unknown" : sourceIp.replaceAll("[\\r\\n]", "");
    }
}
