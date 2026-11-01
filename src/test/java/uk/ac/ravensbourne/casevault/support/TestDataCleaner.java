package uk.ac.ravensbourne.casevault.support;

import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Removes only mutable domain fixtures from the shared in-memory H2 database.
 * Audit rows and the chain head are deliberately excluded: the audit log is append-only test evidence.
 */
public final class TestDataCleaner {
    private TestDataCleaner() {
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
