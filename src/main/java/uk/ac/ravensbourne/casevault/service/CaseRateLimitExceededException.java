package uk.ac.ravensbourne.casevault.service;

/** Signals a search or report-generation quota breach without exposing quota internals (CWE-770). */
public final class CaseRateLimitExceededException extends RuntimeException {
    private final long retryAfterSeconds;

    public CaseRateLimitExceededException(long retryAfterSeconds) {
        super("Case operation rate limit exceeded");
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
