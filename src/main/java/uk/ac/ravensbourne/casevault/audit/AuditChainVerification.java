package uk.ac.ravensbourne.casevault.audit;

import java.util.OptionalLong;

/** Result of independently recalculating the append-only HMAC audit chain. */
public record AuditChainVerification(boolean valid, OptionalLong firstBrokenEventId) {
    public static AuditChainVerification intact() { return new AuditChainVerification(true, OptionalLong.empty()); }
    public static AuditChainVerification broken(long id) { return new AuditChainVerification(false, OptionalLong.of(id)); }
}
