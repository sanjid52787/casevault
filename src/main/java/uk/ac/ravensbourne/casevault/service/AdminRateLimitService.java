package uk.ac.ravensbourne.casevault.service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.stereotype.Service;
import uk.ac.ravensbourne.casevault.audit.AuditEventType;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.common.TestOnly;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/**
 * Rate-limits admin account/org creation independently by principal (CWE-770).
 * A separate one-token audit bucket records only one RATE_LIMITED event per principal/window.
 */
@Service
public class AdminRateLimitService {
    private static final Duration WINDOW = Duration.ofMinutes(1);
    private final ConcurrentMap<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Bucket> denialAuditBuckets = new ConcurrentHashMap<>();
    private final AuditService audit;

    public AdminRateLimitService(AuditService audit) {
        this.audit = audit;
    }

    /** Limits user creation to 5 per minute per admin. */
    public void checkUserCreation(UserPrincipal principal) {
        check("admin-create-user", "ACCOUNT", principal, 5);
    }

    /** Limits organisation creation to 5 per minute per admin. */
    public void checkOrgCreation(UserPrincipal principal) {
        check("admin-create-org", "ORGANISATION", principal, 5);
    }

    /** Limits user deletion to 5 per minute per admin. */
    public void checkUserDeletion(UserPrincipal principal) {
        check("admin-delete-user", "ACCOUNT", principal, 5);
    }

    @TestOnly
    public void reset() {
        buckets.clear();
        denialAuditBuckets.clear();
    }

    private void check(String operation, String targetType, UserPrincipal principal, long capacity) {
        ConsumptionProbe probe = buckets.computeIfAbsent(operation + ":" + principal.id(),
                ignored -> newBucket(capacity)).tryConsumeAndReturnRemaining(1);
        if (probe.isConsumed()) {
            return;
        }
        String auditKey = operation + ":" + principal.id();
        if (denialAuditBuckets.computeIfAbsent(auditKey, ignored -> newBucket(1)).tryConsume(1)) {
            audit.record(principal, AuditEventType.RATE_LIMITED, targetType, null, operation + "-rate-limited");
        }
        long waitNanos = probe.getNanosToWaitForRefill();
        throw new CaseRateLimitExceededException(Math.max(1, (waitNanos + 999_999_999L) / 1_000_000_000L));
    }

    private Bucket newBucket(long capacity) {
        return Bucket.builder().addLimit(Bandwidth.builder().capacity(capacity).refillGreedy(capacity, WINDOW).build()).build();
    }
}

