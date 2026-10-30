package uk.ac.ravensbourne.casevault.service;

import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import uk.ac.ravensbourne.casevault.audit.AuditEventType;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.SessionRevocationService;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/** Account administration with self/last-admin protections (CWE-862, CWE-613). */
@Service
public class AdminAccountService {
    private final UserAccountRepository users; private final SessionRevocationService sessions; private final AuditService audit;
    public AdminAccountService(UserAccountRepository users, SessionRevocationService sessions, AuditService audit){this.users=users;this.sessions=sessions;this.audit=audit;}
    public List<UserAccount> accounts(){return users.findAll();}
    @Transactional public void disable(UserPrincipal actor, UUID id, String reason){
        requireReason(reason); UserAccount target=users.findById(id).orElseThrow(CaseNotFoundException::new);
        if(actor.id().equals(id)) throw new IllegalArgumentException("Administrative action is not permitted");
        if(target.getRole()==Role.AUDITOR_ADMIN && target.isEnabled() && users.findAll().stream().filter(u->u.isEnabled()&&u.getRole()==Role.AUDITOR_ADMIN).count()<=1) throw new IllegalArgumentException("Administrative action is not permitted");
        target.disable(); sessions.revokeAll(target.getEmail()); audit.record(actor,AuditEventType.ACCOUNT_DISABLED,"ACCOUNT",id,"account-disabled");
    }
    @Transactional public void enable(UserPrincipal actor,UUID id,String reason){requireReason(reason);UserAccount target=users.findById(id).orElseThrow(CaseNotFoundException::new);target.enable();audit.record(actor,AuditEventType.ACCOUNT_ENABLED,"ACCOUNT",id,"account-enabled");}
    @Transactional public void revoke(UserPrincipal actor,UUID id,String reason){requireReason(reason);UserAccount target=users.findById(id).orElseThrow(CaseNotFoundException::new);sessions.revokeAll(target.getEmail());audit.record(actor,AuditEventType.SESSIONS_REVOKED,"ACCOUNT",id,"sessions-revoked");}
    @Transactional public void forcePasswordReset(UserPrincipal actor,UUID id,String reason){requireReason(reason);UserAccount target=users.findById(id).orElseThrow(CaseNotFoundException::new);target.requirePasswordReset();sessions.revokeAll(target.getEmail());audit.record(actor,AuditEventType.FORCE_PASSWORD_RESET,"ACCOUNT",id,"reset-required");}
    private void requireReason(String reason){if(reason==null||reason.isBlank()||reason.length()>120||reason.chars().anyMatch(Character::isISOControl))throw new IllegalArgumentException("Administrative action is not permitted");}
}
