package uk.ac.ravensbourne.casevault.web;

import java.time.Instant;
import java.util.*;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.*;
import uk.ac.ravensbourne.casevault.storage.EvidenceStorageHealthProbe;

/** Auditor-only administration; content-case routes remain unavailable to this role. */
@Controller
@RequestMapping("/admin")
@PreAuthorize("hasRole('AUDITOR_ADMIN')")
public class AdminController {
    private final AdminAccountService accounts;
    private final AdminAuditService audits;
    private final EvidenceStorageHealthProbe storageHealth;

    public AdminController(AdminAccountService a, AdminAuditService u, EvidenceStorageHealthProbe storageHealth) {
        accounts = a;
        audits = u;
        this.storageHealth = storageHealth;
    }

    @GetMapping("/accounts")
    String accounts(@AuthenticationPrincipal UserPrincipal p, Model m) {
        m.addAttribute("accounts", accounts.accounts(p));
        m.addAttribute("me", p);
        return "admin-accounts";
    }

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
