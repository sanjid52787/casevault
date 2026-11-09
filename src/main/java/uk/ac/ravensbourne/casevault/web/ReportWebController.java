package uk.ac.ravensbourne.casevault.web;

import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import uk.ac.ravensbourne.casevault.report.ReportService;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.CaseRateLimitService;
import uk.ac.ravensbourne.casevault.service.ReportApprovalService;

/** HTML workflow adapter. It never decides role or tenant access: services do so before every mutation. */
@Controller
@RequestMapping("/cases/{caseId}/reports")
public class ReportWebController {
    private final ReportService reports;
    private final ReportApprovalService approvals;
    private final CaseRateLimitService limits;

    public ReportWebController(ReportService reports, ReportApprovalService approvals, CaseRateLimitService limits) {
        this.reports = reports;
        this.approvals = approvals;
        this.limits = limits;
    }

    /* The /_ui prefix keeps browser form handlers distinct from the JSON endpoints. */
    @PostMapping("/_ui/generate")
    String generate(@AuthenticationPrincipal UserPrincipal principal, @PathVariable UUID caseId, HttpServletRequest request) {
        limits.checkReportGeneration(principal, request.getRemoteAddr(), caseId);
        reports.generate(principal, caseId);
        return "redirect:/cases/" + caseId;
    }

    @PostMapping("/_ui/{reportId}/submit")
    String submit(@AuthenticationPrincipal UserPrincipal principal, @PathVariable UUID caseId, @PathVariable UUID reportId) {
        reports.submit(principal, caseId, reportId);
        return "redirect:/cases/" + caseId;
    }

    @PostMapping("/_ui/{reportId}/approve")
    String approve(@AuthenticationPrincipal UserPrincipal principal, @PathVariable UUID caseId, @PathVariable UUID reportId) {
        approvals.approve(principal, caseId, reportId);
        return "redirect:/cases/" + caseId;
    }
}
