package uk.ac.ravensbourne.casevault.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/** Ensures the report audit vocabulary is appendable by the protected audit implementation. */
@SpringBootTest
@ActiveProfiles("test")
class AuditServiceTest {
    @Autowired AuditService audit;
    @Autowired PersistentAuditService persistentAudit;
    @Autowired JdbcTemplate jdbc;

    @BeforeEach
    void reset() {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
    }

    @Test
    void tAudit005ReportLifecycleEventsAreTypedAndChained() {
        UserPrincipal actor = new UserPrincipal(UUID.randomUUID(), UUID.randomUUID(), "audit@example.test", "",
                Role.SECURITY_ANALYST.name(), true, false);
        UUID reportId = UUID.randomUUID();
        audit.record(actor, AuditEventType.REPORT_GENERATED, "REPORT", reportId, "report-generated");
        audit.record(actor, AuditEventType.REPORT_SUBMITTED, "REPORT", reportId, "report-submitted");
        audit.record(actor, AuditEventType.REPORT_APPROVED, "REPORT", reportId, "report-approved");
        audit.record(actor, AuditEventType.REPORT_DOWNLOADED, "REPORT", reportId, "report-downloaded");
        assertEquals(4, jdbc.queryForObject("SELECT COUNT(*) FROM audit_events", Integer.class));
        assertTrue(persistentAudit.verifyChain().valid());
    }
}
