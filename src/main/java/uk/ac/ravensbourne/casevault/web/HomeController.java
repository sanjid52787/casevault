package uk.ac.ravensbourne.casevault.web;

import org.springframework.stereotype.Controller;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.ui.Model;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.DashboardService;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
    private final DashboardService dashboard;

    public HomeController(DashboardService dashboard) {
        this.dashboard = dashboard;
    }

    @GetMapping("/")
    String home(@AuthenticationPrincipal UserPrincipal principal, Model model) {
        model.addAttribute("role", principal == null ? "" : principal.role());
        if (principal != null) model.addAttribute("summary", dashboard.summary(principal));
        return "home";
    }
}
