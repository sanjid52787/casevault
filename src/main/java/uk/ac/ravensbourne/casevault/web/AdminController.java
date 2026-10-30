package uk.ac.ravensbourne.casevault.web;
import org.springframework.security.access.prepost.PreAuthorize; import org.springframework.stereotype.Controller; import org.springframework.web.bind.annotation.*;
@Controller @RequestMapping("/admin") @PreAuthorize("hasRole('AUDITOR_ADMIN')") public class AdminController { @GetMapping("/health") @ResponseBody public String health(){return "administrative health metadata";} }
