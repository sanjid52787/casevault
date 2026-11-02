package uk.ac.ravensbourne.casevault.service;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import uk.ac.ravensbourne.casevault.audit.AuditChainVerification;
import uk.ac.ravensbourne.casevault.audit.AuditEventType;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.audit.PersistentAuditService;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/**
 * Read-only audit queries for AUDITOR_ADMIN. Filter values are always bind parameters, preventing
 * SQL injection in an operational security-log interface (CWE-89).
 */
@Service
public class AdminAuditService {
    private final JdbcTemplate jdbc;
    private final PersistentAuditService chain;
    private final AuditService audit;

    public AdminAuditService(JdbcTemplate jdbc, PersistentAuditService chain, AuditService audit) {
        this.jdbc = jdbc;
        this.chain = chain;
        this.audit = audit;
    }

    public List<Map<String, Object>> events(UserPrincipal actor, int page, int size, String action,
                                             String actorRole, String outcome, Instant from, Instant to) {
        requireAdministrator(actor);
        int safeSize = Math.min(Math.max(size, 1), 50);
        StringBuilder sql = new StringBuilder("SELECT id,ts,actor_role,action,target_type,outcome,correlation_id "
                + "FROM audit_events WHERE 1=1");
        List<Object> arguments = new ArrayList<>();
        appendTextFilter(sql, arguments, "action", action);
        appendTextFilter(sql, arguments, "actor_role", actorRole);
        appendTextFilter(sql, arguments, "outcome", outcome);
        if (from != null) {
            sql.append(" AND ts>=?");
            arguments.add(Timestamp.from(from));
        }
        if (to != null) {
            sql.append(" AND ts<=?");
            arguments.add(Timestamp.from(to));
        }
        sql.append(" ORDER BY id DESC LIMIT ? OFFSET ?");
        arguments.add(safeSize);
        arguments.add(Math.max(page, 0) * safeSize);
        return jdbc.queryForList(sql.toString(), arguments.toArray());
    }

    private void appendTextFilter(StringBuilder sql, List<Object> arguments, String column, String value) {
        if (value != null && !value.isBlank()) {
            sql.append(" AND ").append(column).append("=?");
            arguments.add(value.trim());
        }
    }

    public AuditChainVerification verify(UserPrincipal actor) {
        requireAdministrator(actor);
        AuditChainVerification result = chain.verifyChain();
        audit.record(actor, AuditEventType.AUDIT_VERIFY, "AUDIT", null, "audit-verify");
        return result;
    }

    public void viewed(UserPrincipal actor) {
        requireAdministrator(actor);
        audit.record(actor, AuditEventType.ADMIN_VIEW_AUDIT, "AUDIT", null, "audit-viewed");
    }

    public void healthViewed(UserPrincipal actor) {
        requireAdministrator(actor);
        audit.record(actor, AuditEventType.ADMIN_VIEW_HEALTH, "SYSTEM", null, "health-viewed");
    }

    private void requireAdministrator(UserPrincipal actor) {
        if (actor == null || !Role.AUDITOR_ADMIN.name().equals(actor.role())) {
            throw new AccessDeniedException("Administrative access is not permitted");
        }
    }
}
