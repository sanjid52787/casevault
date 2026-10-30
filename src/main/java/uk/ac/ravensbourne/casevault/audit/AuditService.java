package uk.ac.ravensbourne.casevault.audit;
import java.util.UUID; import uk.ac.ravensbourne.casevault.security.UserPrincipal;
/** Phase 5 boundary for protected audit persistence, implemented fully in Phase 7. */
public interface AuditService { void record(UserPrincipal actor,String action,String targetType,UUID targetId,String details); default void record(UserPrincipal actor,AuditEventType action,String targetType,UUID targetId,String details){record(actor,action.name(),targetType,targetId,details);} }
