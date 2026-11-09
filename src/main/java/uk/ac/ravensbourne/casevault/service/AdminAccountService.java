package uk.ac.ravensbourne.casevault.service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import uk.ac.ravensbourne.casevault.audit.AuditEventType;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.SessionRevocationService;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/**
 * Account and organisation administration with privilege-escalation, self/last-admin
 * and duplicate protections (CWE-269, CWE-862, CWE-613).
 */
@Service
public class AdminAccountService {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final UserAccountRepository users;
    private final OrganisationRepository organisations;
    private final SessionRevocationService sessions;
    private final AuditService audit;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AdminAccountService(UserAccountRepository users, OrganisationRepository organisations,
                               SessionRevocationService sessions, AuditService audit,
                               PasswordEncoder passwordEncoder) {
        this.users = users;
        this.organisations = organisations;
        this.sessions = sessions;
        this.audit = audit;
        this.passwordEncoder = passwordEncoder;
    }

    public AdminAccountService(UserAccountRepository users, SessionRevocationService sessions, AuditService audit) {
        this(users, null, sessions, audit, null);
    }

    public List<UserAccount> accounts(UserPrincipal actor) {
        requireAdministrator(actor);
        return users.findAll();
    }

    public List<Organisation> allOrganisations(UserPrincipal actor) {
        requireAdministrator(actor);
        return organisations.findAll();
    }

    /** Non-disclosing database connectivity probe (CWE-200): reduced to OK/FAIL; no exception detail escapes. */
    public String databaseStatus(UserPrincipal actor) {
        requireAdministrator(actor);
        try { users.count(); return "OK"; } catch (RuntimeException e) { return "FAIL"; }
    }

    /**
     * Creates a new user account with a generated one-time password.
     * The AUDITOR_ADMIN role is explicitly blocked to prevent privilege escalation (CWE-269).
     *
     * @return the generated plaintext password (shown once, never logged or stored)
     */
    @Transactional
    public String createUser(UserPrincipal actor, String email, Role role, UUID organisationId, String displayName) {
        requireAdministrator(actor);

        // Block privilege escalation: admins cannot create other admins
        if (role == Role.AUDITOR_ADMIN) {
            throw new IllegalArgumentException("Administrative action is not permitted");
        }

        // Normalise and validate email
        String normalisedEmail = email.trim().toLowerCase(Locale.ROOT);
        if (normalisedEmail.isEmpty() || normalisedEmail.length() > 254) {
            throw new IllegalArgumentException("Administrative action is not permitted");
        }

        // Reject duplicates
        if (users.findByEmail(normalisedEmail).isPresent()) {
            throw new IllegalArgumentException("An account with this email already exists");
        }

        // Validate organisation exists
        Organisation org = organisations.findById(organisationId)
                .orElseThrow(() -> new IllegalArgumentException("Organisation not found"));

        // Generate a secure random password (24 bytes → 32-char Base64url, exceeds 12-char policy)
        byte[] randomBytes = new byte[24];
        RANDOM.nextBytes(randomBytes);
        String generatedPassword = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        // Hash with the application's Argon2id encoder
        String hash = passwordEncoder.encode(generatedPassword);

        // Persist user with force-password-reset
        UUID userId = UUID.randomUUID();
        UserAccount account = new UserAccount(userId, org, normalisedEmail, hash, role);
        account.requirePasswordReset();
        if (displayName != null && !displayName.isBlank()) {
            account.setDisplayName(displayName.trim());
        }
        users.save(account);

        // Audit — detail is a slug, never the password
        audit.record(actor, AuditEventType.ACCOUNT_CREATED, "ACCOUNT", userId, "account-created");

        return generatedPassword;
    }

    /**
     * Creates a new organisation.
     */
    @Transactional
    public Organisation createOrganisation(UserPrincipal actor, String name) {
        requireAdministrator(actor);

        String trimmedName = name.trim();
        if (trimmedName.isEmpty() || trimmedName.length() > 160) {
            throw new IllegalArgumentException("Administrative action is not permitted");
        }

        if (organisations.findByName(trimmedName).isPresent()) {
            throw new IllegalArgumentException("An organisation with this name already exists");
        }

        UUID orgId = UUID.randomUUID();
        Organisation org = new Organisation(orgId, trimmedName);
        organisations.save(org);

        audit.record(actor, AuditEventType.ORGANISATION_CREATED, "ORGANISATION", orgId, "organisation-created");
        return org;
    }

    @Transactional
    public void disable(UserPrincipal actor, UUID id, String reason) {
        requireAdministrator(actor);
        requireReason(reason);
        UserAccount target = users.findById(id).orElseThrow(CaseNotFoundException::new);
        if (actor.id().equals(id)) throw new IllegalArgumentException("Administrative action is not permitted");
        if (target.getRole() == Role.AUDITOR_ADMIN && target.isEnabled()
                && users.findAll().stream().filter(u -> u.isEnabled() && u.getRole() == Role.AUDITOR_ADMIN).count() <= 1) {
            throw new IllegalArgumentException("Administrative action is not permitted");
        }
        target.disable();
        sessions.revokeAll(target.getEmail());
        audit.record(actor, AuditEventType.ACCOUNT_DISABLED, "ACCOUNT", id, "account-disabled");
    }

    @Transactional
    public void enable(UserPrincipal actor, UUID id, String reason) {
        requireAdministrator(actor);
        requireReason(reason);
        UserAccount target = users.findById(id).orElseThrow(CaseNotFoundException::new);
        target.enable();
        audit.record(actor, AuditEventType.ACCOUNT_ENABLED, "ACCOUNT", id, "account-enabled");
    }

    @Transactional
    public void revoke(UserPrincipal actor, UUID id, String reason) {
        requireAdministrator(actor);
        requireReason(reason);
        UserAccount target = users.findById(id).orElseThrow(CaseNotFoundException::new);
        sessions.revokeAll(target.getEmail());
        audit.record(actor, AuditEventType.SESSIONS_REVOKED, "ACCOUNT", id, "sessions-revoked");
    }

    @Transactional
    public void forcePasswordReset(UserPrincipal actor, UUID id, String reason) {
        requireAdministrator(actor);
        requireReason(reason);
        UserAccount target = users.findById(id).orElseThrow(CaseNotFoundException::new);
        target.requirePasswordReset();
        sessions.revokeAll(target.getEmail());
        audit.record(actor, AuditEventType.FORCE_PASSWORD_RESET, "ACCOUNT", id, "reset-required");
    }

    @Transactional
    public void delete(UserPrincipal actor, UUID id, String reason) {
        requireAdministrator(actor);
        requireReason(reason);
        UserAccount target = users.findById(id).orElseThrow(CaseNotFoundException::new);
        if (target.isDeleted()) {
            throw new IllegalArgumentException("Account is already deleted");
        }
        if (actor.id().equals(id)) {
            throw new IllegalArgumentException("Administrative action is not permitted");
        }
        if (target.getRole() == Role.AUDITOR_ADMIN
                && users.findAll().stream().filter(u -> !u.isDeleted() && u.isEnabled() && u.getRole() == Role.AUDITOR_ADMIN).count() <= 1) {
            throw new IllegalArgumentException("Administrative action is not permitted");
        }
        String originalEmail = target.getEmail();
        target.markDeleted();
        sessions.revokeAll(originalEmail);
        audit.record(actor, AuditEventType.ACCOUNT_DELETED, "ACCOUNT", id, "account-deleted");
    }

    private void requireReason(String reason) {
        if (reason == null || reason.isBlank() || reason.length() > 120
                || reason.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Administrative action is not permitted");
        }
    }

    private void requireAdministrator(UserPrincipal actor) {
        if (actor == null || actor.role() == null || !Role.AUDITOR_ADMIN.name().equals(actor.role())) {
            throw new AccessDeniedException("Administrative action is not permitted");
        }
    }
}
