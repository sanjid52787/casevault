package uk.ac.ravensbourne.casevault.web;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Handles presentation of the login view.
 * If the user is already authenticated with an active session, visiting /login
 * immediately redirects to the dashboard to prevent session state desynchronization
 * and accidental re-authentication/session-eviction across multiple browser tabs/windows (CWE-613).
 */
@Controller
public class LoginController {

    @GetMapping("/login")
    public String login(@RequestParam(required = false) String redirect,
                        Authentication authentication,
                        Model model) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/";
        }
        model.addAttribute("redirect", redirect == null ? "" : redirect);
        return "login";
    }
}
