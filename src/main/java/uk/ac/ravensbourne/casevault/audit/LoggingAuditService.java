package uk.ac.ravensbourne.casevault.audit;
import java.util.UUID; import org.slf4j.*; import org.springframework.stereotype.Service; import uk.ac.ravensbourne.casevault.security.UserPrincipal;
/** Deprecated Phase 5 placeholder; retained only for source history and deliberately not registered as a bean. */
public class LoggingAuditService implements AuditService { private static final Logger LOG=LoggerFactory.getLogger(LoggingAuditService.class); public void record(UserPrincipal a,String action,String type,UUID id,String details){LOG.info("audit action={} actor={} type={} id={}",action,a.id(),type,id);} }
