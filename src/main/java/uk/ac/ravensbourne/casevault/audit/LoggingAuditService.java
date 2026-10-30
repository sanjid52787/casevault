package uk.ac.ravensbourne.casevault.audit;
import java.util.UUID; import org.slf4j.*; import org.springframework.stereotype.Service; import uk.ac.ravensbourne.casevault.security.UserPrincipal;
@Service public class LoggingAuditService implements AuditService { private static final Logger LOG=LoggerFactory.getLogger(LoggingAuditService.class); public void record(UserPrincipal a,String action,String type,UUID id,String details){LOG.info("audit action={} actor={} type={} id={} details={}",action,a.id(),type,id,details.replaceAll("[\\r\\n]",""));} }
