package uk.ac.ravensbourne.casevault.audit;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/**
 * Appends metadata-only events protected by an HMAC-SHA256 chain (CWE-345, CWE-778).
 * A one-row `audit_chain_head` is locked with SELECT FOR UPDATE before an append; this serialises writers
 * across application instances without relying on JVM locking. The HMAC key comes only from configuration.
 */
@Service
public class PersistentAuditService implements AuditService {
    private static final Set<String> FORBIDDEN = Set.of("password", "token", "session", "secret", "cookie", "bearer");
    private final JdbcTemplate jdbc;
    private final byte[] key;

    public PersistentAuditService(JdbcTemplate jdbc, @Value("${casevault.audit.hmac-key:${AUDIT_HMAC_KEY:}}") String hmacKey) {
        if (hmacKey == null || hmacKey.isBlank()) throw new IllegalStateException("AUDIT_HMAC_KEY is required");
        this.jdbc = jdbc;
        this.key = hmacKey.getBytes(StandardCharsets.UTF_8);
    }

    @Override @Transactional
    public void record(UserPrincipal actor, String action, String targetType, UUID targetId, String details) {
        append(actor, action, targetType, targetId, "SUCCESS", details);
    }

    @Transactional
    public void recordDenied(UserPrincipal actor, String targetType, UUID targetId) {
        append(actor, "ACCESS_DENIED", targetType, targetId, "DENIED", "access-denied");
    }

    private void append(UserPrincipal actor, String action, String targetType, UUID targetId, String outcome, String details) {
        validateMetadata(action, targetType, details);
        Map<String, Object> head = jdbc.queryForMap("SELECT last_event_id, last_hash FROM audit_chain_head WHERE singleton = TRUE FOR UPDATE");
        String previous = (String) head.get("last_hash");
        Instant timestamp = Instant.now();
        UUID correlation = UUID.randomUUID();
        String safeDetails = "{\"event\":\"" + details + "\"}";
        String canonical = canonical(timestamp, actor, action, targetType, targetId, outcome, correlation, safeDetails, previous);
        String hash = hmac(canonical);
        jdbc.update("INSERT INTO audit_events (ts,actor_id,actor_role,action,target_type,target_id,outcome,correlation_id,details_json,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                timestamp, actor == null ? null : actor.id(), actor == null ? null : actor.role(), action, targetType, targetId, outcome, correlation, safeDetails, previous, hash);
        Long eventId = jdbc.queryForObject("SELECT MAX(id) FROM audit_events", Long.class);
        jdbc.update("UPDATE audit_chain_head SET last_event_id=?, last_hash=? WHERE singleton=TRUE", eventId, hash);
    }

    @Transactional(readOnly = true)
    public AuditChainVerification verifyChain() {
        String previous = null;
        var rows = jdbc.queryForList("SELECT id,ts,actor_id,actor_role,action,target_type,target_id,outcome,correlation_id,details_json,prev_hash,hash FROM audit_events ORDER BY id");
        for (var row : rows) {
            long id = ((Number) row.get("id")).longValue();
            String rowPrevious = (String) row.get("prev_hash");
            if (!Objects.equals(previous, rowPrevious)) return AuditChainVerification.broken(id);
            UserPrincipal actor = row.get("actor_id") == null ? null : new UserPrincipal(UUID.fromString(row.get("actor_id").toString()), UUID.randomUUID(), "audit@internal", "", row.get("actor_role").toString(), true, false);
            Instant ts = ((java.time.OffsetDateTime) row.get("ts")).toInstant();
            String actual = hmac(canonical(ts, actor, row.get("action").toString(), row.get("target_type").toString(), row.get("target_id") == null ? null : UUID.fromString(row.get("target_id").toString()), row.get("outcome").toString(), UUID.fromString(row.get("correlation_id").toString()), row.get("details_json").toString(), previous));
            if (!Objects.equals(actual, row.get("hash"))) return AuditChainVerification.broken(id);
            previous = actual;
        }
        return AuditChainVerification.intact();
    }

    private String canonical(Instant ts, UserPrincipal actor, String action, String targetType, UUID targetId, String outcome, UUID correlation, String details, String previous) {
        return "ts=" + ts.toEpochMilli() + "|actorId=" + (actor == null ? "" : actor.id()) + "|actorRole=" + (actor == null ? "" : actor.role()) + "|action=" + action + "|targetType=" + targetType + "|targetId=" + (targetId == null ? "" : targetId) + "|outcome=" + outcome + "|correlationId=" + correlation + "|details=" + details + "|prevHash=" + (previous == null ? "" : previous);
    }
    private String hmac(String value) { try { Mac mac=Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key,"HmacSHA256")); return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8))); } catch (GeneralSecurityException e) { throw new IllegalStateException("Audit HMAC unavailable",e); } }
    private void validateMetadata(String action,String targetType,String details) { String joined=(targetType+details).toLowerCase(Locale.ROOT); if (!action.matches("[A-Z_]{3,100}") || !targetType.matches("[A-Z_]{3,64}") || !details.matches("[a-z0-9-]{1,64}") || FORBIDDEN.stream().anyMatch(joined::contains)) throw new IllegalArgumentException("Unsafe audit metadata"); }
}
