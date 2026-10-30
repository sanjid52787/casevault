package uk.ac.ravensbourne.casevault.web;

import jakarta.validation.Valid;
import java.time.LocalDate;
import java.util.UUID;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import uk.ac.ravensbourne.casevault.domain.CaseStatus;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.CaseManagementService;
import uk.ac.ravensbourne.casevault.service.CaseViewService;
import uk.ac.ravensbourne.casevault.service.CaseWorkflowService;
import uk.ac.ravensbourne.casevault.service.ReportApprovalService;
import uk.ac.ravensbourne.casevault.web.dto.CaseMutationRequests;
import uk.ac.ravensbourne.casevault.web.dto.CreateCaseRequest;

@Controller
@RequestMapping("/cases")
public class CaseController {
    private final CaseManagementService management;
    private final ReportApprovalService reports;
    private final CaseWorkflowService workflow;
    private final CaseViewService views;

    public CaseController(CaseManagementService management, ReportApprovalService reports,
                          CaseWorkflowService workflow, CaseViewService views) {
        this.management = management;
        this.reports = reports;
        this.workflow = workflow;
        this.views = views;
    }

    @GetMapping("/new") @PreAuthorize("hasRole('CLIENT_USER')")
    String createForm() { return "case-form"; }

    @PostMapping @PreAuthorize("hasRole('CLIENT_USER')")
    String create(@AuthenticationPrincipal UserPrincipal principal, @Valid @ModelAttribute CreateCaseRequest request,
                  BindingResult errors) {
        if (errors.hasErrors()) return "case-form";
        return "redirect:/cases/" + management.create(principal, request).getId();
    }

    @GetMapping
    String list(@AuthenticationPrincipal UserPrincipal principal, @RequestParam(required = false) String q,
                @RequestParam(required = false) Category category, @RequestParam(required = false) Severity severity,
                @RequestParam(required = false) CaseStatus status, @RequestParam(required = false) UUID owner,
                @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
                @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to,
                @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size,
                @RequestParam(defaultValue = "createdAt") String sort, Model model) {
        model.addAttribute("cases", workflow.search(principal, q, category, severity, status, owner, from, to, page, size, sort));
        model.addAttribute("query", q == null ? "" : q);
        return "case-list";
    }

    @GetMapping("/{id}") @PreAuthorize("isAuthenticated()")
    String view(@AuthenticationPrincipal UserPrincipal principal, @PathVariable UUID id, Model model) {
        var detail = views.view(principal, id);
        model.addAttribute("caseRecord", detail.caseRecord());
        model.addAttribute("notes", detail.notes());
        return "case-detail";
    }

    @PostMapping("/{id}/assign") @PreAuthorize("hasRole('CASE_MANAGER')")
    String assign(@AuthenticationPrincipal UserPrincipal principal, @PathVariable UUID id,
                  @Valid @ModelAttribute CaseMutationRequests.Assign request) {
        workflow.assign(principal, id, request);
        return "redirect:/cases/" + id;
    }

    @PostMapping("/{id}/status") @PreAuthorize("hasRole('CASE_MANAGER')")
    String status(@AuthenticationPrincipal UserPrincipal principal, @PathVariable UUID id,
                  @Valid @ModelAttribute CaseMutationRequests.Status request) {
        workflow.status(principal, id, request);
        return "redirect:/cases/" + id;
    }

    @PostMapping("/{id}/notes") @PreAuthorize("hasAnyRole('SECURITY_ANALYST','CASE_MANAGER')")
    String note(@AuthenticationPrincipal UserPrincipal principal, @PathVariable UUID id,
                @Valid @ModelAttribute CaseMutationRequests.Note request) {
        workflow.note(principal, id, request);
        return "redirect:/cases/" + id;
    }

    @PostMapping("/{id}/actions") @PreAuthorize("hasAnyRole('SECURITY_ANALYST','CASE_MANAGER')")
    String action(@AuthenticationPrincipal UserPrincipal principal, @PathVariable UUID id,
                  @Valid @ModelAttribute CaseMutationRequests.Action request) {
        workflow.action(principal, id, request);
        return "redirect:/cases/" + id;
    }

    @PostMapping("/{caseId}/reports/{reportId}/approve") @PreAuthorize("hasRole('CASE_MANAGER')")
    @ResponseBody
    String approve(@AuthenticationPrincipal UserPrincipal principal, @PathVariable UUID caseId, @PathVariable UUID reportId) {
        reports.approve(principal, caseId, reportId);
        return "approved";
    }
}
