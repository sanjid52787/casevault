package uk.ac.ravensbourne.casevault.web;

import java.util.UUID;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.EvidenceRateLimitService;
import uk.ac.ravensbourne.casevault.service.EvidenceService;
import jakarta.servlet.http.HttpServletRequest;

/** Browser form adapter; all validation, rate limiting and access decisions remain in EvidenceService. */
@Controller
@RequestMapping("/cases/{caseId}/evidence")
public class EvidenceWebController {
    private final EvidenceService evidence;
    private final EvidenceRateLimitService rateLimit;

    public EvidenceWebController(EvidenceService evidence, EvidenceRateLimitService rateLimit) {
        this.evidence = evidence;
        this.rateLimit = rateLimit;
    }

    @PostMapping("/upload")
    String upload(@AuthenticationPrincipal UserPrincipal principal, @PathVariable UUID caseId,
                  @RequestParam("file") MultipartFile file, HttpServletRequest request) throws Exception {
        rateLimit.checkUpload(principal, request.getRemoteAddr(), caseId);
        evidence.upload(principal, caseId, file);
        return "redirect:/cases/" + caseId;
    }
}
