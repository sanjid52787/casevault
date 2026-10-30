package uk.ac.ravensbourne.casevault.service;

/** Signals a deliberately short-lived evidence transfer quota breach (CWE-770). */
public final class EvidenceRateLimitExceededException extends RuntimeException {
    private final long retryAfterSeconds;

    public EvidenceRateLimitExceededException(long retryAfterSeconds) {
        super("Evidence transfer rate limit exceeded");
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
