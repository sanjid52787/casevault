package uk.ac.ravensbourne.casevault.web;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.EvidenceRateLimitExceededException;
import uk.ac.ravensbourne.casevault.service.EvidenceRateLimitService;
import uk.ac.ravensbourne.casevault.service.EvidenceRejectedException;
import uk.ac.ravensbourne.casevault.service.EvidenceService;

/** Serves evidence only as authorised attachments, never from a static resource location. */
@RestController
@RequestMapping("/cases/{caseId}/evidence")
public class EvidenceController {
    private final EvidenceService evidence;
    private final EvidenceRateLimitService rateLimit;

    public EvidenceController(EvidenceService evidence, EvidenceRateLimitService rateLimit) {
        this.evidence = evidence;
        this.rateLimit = rateLimit;
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Void> upload(@AuthenticationPrincipal UserPrincipal principal,
                                       @PathVariable UUID caseId, @RequestParam("file") MultipartFile file,
                                       HttpServletRequest request) throws Exception {
        rateLimit.checkUpload(principal, request.getRemoteAddr(), caseId);
        var saved = evidence.upload(principal, caseId, file);
        return ResponseEntity.created(java.net.URI.create("/cases/" + caseId + "/evidence/" + saved.getId())).build();
    }

    @GetMapping("/{id}")
    public ResponseEntity<byte[]> download(@AuthenticationPrincipal UserPrincipal principal,
                                           @PathVariable UUID caseId, @PathVariable UUID id,
                                           HttpServletRequest request) {
        rateLimit.checkDownload(principal, request.getRemoteAddr(), caseId);
        byte[] content = evidence.download(principal, caseId, id);
        String generatedFilename = "evidence-" + URLEncoder.encode(id.toString(), StandardCharsets.UTF_8);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename*=UTF-8''" + generatedFilename)
                .header("X-Content-Type-Options", "nosniff")
                .cacheControl(CacheControl.noStore())
                .body(content);
    }

    @ExceptionHandler(EvidenceRateLimitExceededException.class)
    ResponseEntity<Void> tooManyRequests(EvidenceRateLimitExceededException exception) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.RETRY_AFTER, Long.toString(exception.retryAfterSeconds()))
                .build();
    }

    @ExceptionHandler(EvidenceRejectedException.class)
    public RedirectView handleEvidenceRejected(HttpServletRequest request, RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("error",
                "This file was not accepted. Only approved evidence types within the size limit are allowed.");
        redirectAttributes.addFlashAttribute("message",
                "This file was not accepted. Only approved evidence types within the size limit are allowed.");
        String caseId = extractCaseId(request);
        return new RedirectView(caseId.isBlank() ? "/cases" : "/cases/" + caseId, true);
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
