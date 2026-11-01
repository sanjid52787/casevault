package uk.ac.ravensbourne.casevault.service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.stereotype.Service;
import uk.ac.ravensbourne.casevault.audit.AuditEventType;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/**
 * Limits search and report generation independently by principal and source IP (CWE-770).
 * A separate one-token audit bucket records only one RATE_LIMITED event per principal/operation/window.
 */
@Service
public class CaseRateLimitService {
    private static final Duration WINDOW = Duration.ofMinutes(1);
    private final ConcurrentMap<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Bucket> denialAuditBuckets = new ConcurrentHashMap<>();
    private final AuditService audit;

    public CaseRateLimitService(AuditService audit) {
        this.audit = audit;
    }

    public void checkSearch(UserPrincipal principal, String sourceIp) {
        check("search", "SEARCH", principal, sourceIp, null, 3, 20);
    }

    public void checkReportGeneration(UserPrincipal principal, String sourceIp, UUID caseId) {
        check("report-generation", "REPORT", principal, sourceIp, caseId, 2, 20);
    }

    private void check(String operation, String targetType, UserPrincipal principal, String sourceIp, UUID targetId,
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
            audit.record(principal, AuditEventType.RATE_LIMITED, targetType, targetId, operation + "-rate-limited");
        }
        long waitNanos = Math.max(user.isConsumed() ? 0 : user.getNanosToWaitForRefill(),
                ip.isConsumed() ? 0 : ip.getNanosToWaitForRefill());
        throw new CaseRateLimitExceededException(Math.max(1, (waitNanos + 999_999_999L) / 1_000_000_000L));
    }

    private Bucket bucket(String key, long capacity) {
        return buckets.computeIfAbsent(key, ignored -> newBucket(capacity));
    }

    private Bucket newBucket(long capacity) {
        return Bucket.builder().addLimit(Bandwidth.builder().capacity(capacity).refillGreedy(capacity, WINDOW).build()).build();
    }

    private String normaliseIp(String sourceIp) {
        return sourceIp == null || sourceIp.isBlank() ? "unknown" : sourceIp.replaceAll("[\\r\\n]", "");
    }
}
