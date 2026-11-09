package uk.ac.ravensbourne.casevault.web;

import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.EvidenceRateLimitService;
import uk.ac.ravensbourne.casevault.service.EvidenceRejectedException;
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

    @ExceptionHandler(EvidenceRejectedException.class)
    public String handleEvidenceRejected(HttpServletRequest request, RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("error",
                "This file was not accepted. Only approved evidence types within the size limit are allowed.");
        redirectAttributes.addFlashAttribute("message",
                "This file was not accepted. Only approved evidence types within the size limit are allowed.");
        String caseId = extractCaseId(request);
        return "redirect:" + (caseId.isBlank() ? "/cases" : "/cases/" + caseId);
    }

    private String extractCaseId(HttpServletRequest request) {
        Object uriVarsObj = request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        if (uriVarsObj instanceof Map<?, ?> uriVars) {
            Object id = uriVars.get("caseId");
            if (id != null) {
                return id.toString();
            }
        }
        String uri = request.getRequestURI();
        if (uri != null) {
            Matcher matcher = Pattern.compile("/cases/([^/]+)").matcher(uri);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return "";
    }
}
