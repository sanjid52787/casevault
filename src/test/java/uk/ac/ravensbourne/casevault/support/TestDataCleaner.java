package uk.ac.ravensbourne.casevault.support;

import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import uk.ac.ravensbourne.casevault.security.LoginRateLimiter;
import uk.ac.ravensbourne.casevault.service.CaseRateLimitService;
import uk.ac.ravensbourne.casevault.service.EvidenceRateLimitService;

/**
 * Removes only mutable domain fixtures from the shared in-memory H2 database.
 * Audit rows and the chain head are deliberately excluded: the audit log is append-only test evidence.
 */
@Component
@Profile("test")
public final class TestDataCleaner {
    private final JdbcTemplate jdbc;
    private final CaseRateLimitService caseRateLimits;
    private final EvidenceRateLimitService evidenceRateLimits;
    private final LoginRateLimiter loginRateLimits;

    public TestDataCleaner(JdbcTemplate jdbc, CaseRateLimitService caseRateLimits,
                           EvidenceRateLimitService evidenceRateLimits, LoginRateLimiter loginRateLimits) {
        this.jdbc = jdbc;
        this.caseRateLimits = caseRateLimits;
        this.evidenceRateLimits = evidenceRateLimits;
        this.loginRateLimits = loginRateLimits;
    }

    /** Cleans database fixtures and all in-memory limiter state for a cached Spring test context. */
    public void clean() {
        clean(jdbc);
        caseRateLimits.reset();
        evidenceRateLimits.reset();
        loginRateLimits.reset();
    }

    public static void clean(JdbcTemplate jdbc) {
        jdbc.update("DELETE FROM reports");
        jdbc.update("DELETE FROM remediation_actions");
        jdbc.update("DELETE FROM case_notes");
        jdbc.update("DELETE FROM evidence_files");
        jdbc.update("DELETE FROM case_assignments");
        jdbc.update("DELETE FROM cases");
        jdbc.update("DELETE FROM users");
        jdbc.update("DELETE FROM organisations");
    }
}
