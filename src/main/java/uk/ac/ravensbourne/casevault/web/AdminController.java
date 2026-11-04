package uk.ac.ravensbourne.casevault.web;

import jakarta.validation.Valid;
import java.time.Instant;
import java.util.*;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.*;
import uk.ac.ravensbourne.casevault.storage.EvidenceStorageHealthProbe;
import uk.ac.ravensbourne.casevault.web.dto.CreateOrganisationRequest;
import uk.ac.ravensbourne.casevault.web.dto.CreateUserRequest;

/** Auditor-only administration; content-case routes remain unavailable to this role. */
@Controller
@RequestMapping("/admin")
@PreAuthorize("hasRole('AUDITOR_ADMIN')")
public class AdminController {
    private final AdminAccountService accounts;
    private final AdminAuditService audits;
    private final EvidenceStorageHealthProbe storageHealth;
    private final AdminRateLimitService rateLimiter;

    public AdminController(AdminAccountService a, AdminAuditService u,
                           EvidenceStorageHealthProbe storageHealth, AdminRateLimitService rateLimiter) {
        accounts = a;
        audits = u;
        this.storageHealth = storageHealth;
        this.rateLimiter = rateLimiter;
    }

    @GetMapping("/accounts")
    String accounts(@AuthenticationPrincipal UserPrincipal p, Model m) {
        m.addAttribute("accounts", accounts.accounts(p));
        m.addAttribute("me", p);
        return "admin-accounts";
    }

    // ── User creation ──

    @GetMapping("/accounts/create")
    String createUserForm(@AuthenticationPrincipal UserPrincipal p, Model m) {
        m.addAttribute("organisations", accounts.allOrganisations(p));
        m.addAttribute("allowedRoles", List.of(Role.CLIENT_USER, Role.SECURITY_ANALYST, Role.CASE_MANAGER));
        m.addAttribute("request", new CreateUserRequest("", null, null, ""));
        return "admin-create-user";
    }

    @PostMapping("/accounts/create")
    String createUser(@AuthenticationPrincipal UserPrincipal p,
                      @Valid @ModelAttribute("request") CreateUserRequest request,
                      BindingResult binding, Model m, RedirectAttributes ra) {
        rateLimiter.checkUserCreation(p);

        // Server-side block of AUDITOR_ADMIN role regardless of form manipulation
        if (request.role() == Role.AUDITOR_ADMIN) {
            binding.rejectValue("role", "role.invalid", "This role cannot be assigned");
        }

        if (binding.hasErrors()) {
            m.addAttribute("organisations", accounts.allOrganisations(p));
            m.addAttribute("allowedRoles", List.of(Role.CLIENT_USER, Role.SECURITY_ANALYST, Role.CASE_MANAGER));
            return "admin-create-user";
        }

        try {
            String generatedPassword = accounts.createUser(
                    p, request.email(), request.role(), request.organisationId(), request.displayName());
            m.addAttribute("createdEmail", request.email());
            m.addAttribute("generatedPassword", generatedPassword);
            return "admin-user-created";
        } catch (IllegalArgumentException e) {
            m.addAttribute("errorMessage", e.getMessage());
            m.addAttribute("organisations", accounts.allOrganisations(p));
            m.addAttribute("allowedRoles", List.of(Role.CLIENT_USER, Role.SECURITY_ANALYST, Role.CASE_MANAGER));
            return "admin-create-user";
        }
    }

    // ── Organisation creation ──

    @GetMapping("/organisations/create")
    String createOrgForm(Model m) {
        m.addAttribute("request", new CreateOrganisationRequest(""));
        return "admin-create-org";
    }

    @PostMapping("/organisations/create")
    String createOrg(@AuthenticationPrincipal UserPrincipal p,
                     @Valid @ModelAttribute("request") CreateOrganisationRequest request,
                     BindingResult binding, Model m, RedirectAttributes ra) {
        rateLimiter.checkOrgCreation(p);
        if (binding.hasErrors()) {
            return "admin-create-org";
        }

        try {
            accounts.createOrganisation(p, request.name());
            ra.addFlashAttribute("successMessage", "Organisation created successfully");
            return "redirect:/admin/accounts";
        } catch (IllegalArgumentException e) {
            m.addAttribute("errorMessage", e.getMessage());
            return "admin-create-org";
        }
    }

    // ── Existing account actions ──

    @PostMapping("/accounts/{id}/disable")
    String disable(@AuthenticationPrincipal UserPrincipal p, @PathVariable UUID id, @RequestParam String reason) {
        accounts.disable(p, id, reason);
        return "redirect:/admin/accounts";
    }

    @PostMapping("/accounts/{id}/enable")
    String enable(@AuthenticationPrincipal UserPrincipal p, @PathVariable UUID id, @RequestParam String reason) {
        accounts.enable(p, id, reason);
        return "redirect:/admin/accounts";
    }

    @PostMapping("/accounts/{id}/revoke")
    String revoke(@AuthenticationPrincipal UserPrincipal p, @PathVariable UUID id, @RequestParam String reason) {
        accounts.revoke(p, id, reason);
        return "redirect:/admin/accounts";
    }

    @PostMapping("/accounts/{id}/force-password-reset")
    String reset(@AuthenticationPrincipal UserPrincipal p, @PathVariable UUID id, @RequestParam String reason) {
        accounts.forcePasswordReset(p, id, reason);
        return "redirect:/admin/accounts";
    }

    @PostMapping("/accounts/{id}/delete")
    String delete(@AuthenticationPrincipal UserPrincipal p, @PathVariable UUID id, @RequestParam String reason) {
        rateLimiter.checkUserDeletion(p);
        accounts.delete(p, id, reason);
        return "redirect:/admin/accounts";
    }

    // ── Audit & health ──

    @GetMapping("/audit")
    String audit(@AuthenticationPrincipal UserPrincipal p,
                 @RequestParam(defaultValue = "0") int page,
                 @RequestParam(defaultValue = "20") int size,
                 @RequestParam(required = false) String action,
                 @RequestParam(required = false) String actorRole,
                 @RequestParam(required = false) String outcome,
                 @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
                 @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
                 Model m) {
        audits.viewed(p);
        m.addAttribute("events", audits.events(p, page, size, action, actorRole, outcome, from, to));
        m.addAttribute("selectedAction", action);
        m.addAttribute("selectedActorRole", actorRole);
        m.addAttribute("selectedOutcome", outcome);
        m.addAttribute("selectedFrom", from);
        m.addAttribute("selectedTo", to);
        m.addAttribute("currentPage", page);
        return "admin-audit";
    }

    @PostMapping("/audit/verify")
    String verify(@AuthenticationPrincipal UserPrincipal p, Model m) {
        m.addAttribute("verification", audits.verify(p));
        return "admin-audit-verify";
    }

    @GetMapping("/health")
    String health(@AuthenticationPrincipal UserPrincipal p, Model m) {
        audits.healthViewed(p);
        m.addAttribute("dbStatus", accounts.databaseStatus(p));
        m.addAttribute("storageStatus", storageHealth.probe());
        m.addAttribute("checkedAt", Instant.now());
        return "admin-health";
    }
}
