package uk.ac.ravensbourne.casevault.service;

import org.springframework.stereotype.Service;
import uk.ac.ravensbourne.casevault.domain.*;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/**
 * Central, deny-by-default object authorisation policy (OWASP API1:2023 / CWE-639).
 * Decision table: CLIENT_USER owns-organisation: view/create/upload, client-visible notes and approved reports only;
 * SECURITY_ANALYST assigned: view/add note/action/evidence/generate draft; CASE_MANAGER: view metadata, assign,
 * change status and approve if not generator; AUDITOR_ADMIN: audit/account administration only, never content.
 */
@Service public class AccessPolicy {
    public boolean canViewCase(UserPrincipal p, CaseRecord c, boolean assigned) { return switch (role(p)) { case CLIENT_USER -> sameOrganisation(p,c); case SECURITY_ANALYST -> assigned; case CASE_MANAGER -> true; case AUDITOR_ADMIN -> false; }; }
    public boolean canCreateCase(UserPrincipal p) { return role(p)==Role.CLIENT_USER; }
    public boolean canEditCaseMetadata(UserPrincipal p, CaseRecord c) { return role(p)==Role.CASE_MANAGER; }
    public boolean canAssign(UserPrincipal p, CaseRecord c) { return role(p)==Role.CASE_MANAGER; }
    public boolean canChangeStatus(UserPrincipal p, CaseRecord c) { return role(p)==Role.CASE_MANAGER; }
    public boolean canAddNote(UserPrincipal p, CaseRecord c, boolean assigned) { return role(p)==Role.SECURITY_ANALYST&&assigned; }
    public boolean canAddRemediation(UserPrincipal p, CaseRecord c, boolean assigned) { return canAddNote(p,c,assigned); }
    public boolean canUploadEvidence(UserPrincipal p, CaseRecord c, boolean assigned) { return (role(p)==Role.CLIENT_USER&&sameOrganisation(p,c))||(role(p)==Role.SECURITY_ANALYST&&assigned)||(role(p)==Role.CASE_MANAGER); }
    public boolean canDownloadEvidence(UserPrincipal p, CaseRecord c, boolean assigned) { return canUploadEvidence(p,c,assigned); }
    public boolean canGenerateReport(UserPrincipal p, CaseRecord c, boolean assigned) { return role(p)==Role.SECURITY_ANALYST&&assigned; }
    public boolean canApproveReport(UserPrincipal p, CaseRecord c, java.util.UUID generatedBy) { return role(p)==Role.CASE_MANAGER&&!p.id().equals(generatedBy); }
    public boolean canViewAudit(UserPrincipal p) { return role(p)==Role.AUDITOR_ADMIN; }
    public boolean canManageAccounts(UserPrincipal p) { return role(p)==Role.AUDITOR_ADMIN; }
    private static Role role(UserPrincipal p){return Role.valueOf(p.role());} private static boolean sameOrganisation(UserPrincipal p,CaseRecord c){return p.organisationId().equals(c.getOrganisation().getId());}
}
