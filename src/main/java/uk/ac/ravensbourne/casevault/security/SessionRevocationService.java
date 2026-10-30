package uk.ac.ravensbourne.casevault.security;
import java.util.*; import org.springframework.session.FindByIndexNameSessionRepository; import org.springframework.stereotype.Service;
/** Deletes all indexed JDBC sessions for a principal after disablement or password change (CWE-613). */
@Service public class SessionRevocationService { private final FindByIndexNameSessionRepository<?> sessions; public SessionRevocationService(FindByIndexNameSessionRepository<?> s){sessions=s;} public void revokeAll(String username){sessions.findByPrincipalName(username).keySet().forEach(sessions::deleteById);} }
