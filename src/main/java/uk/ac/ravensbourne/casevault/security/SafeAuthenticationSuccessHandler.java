package uk.ac.ravensbourne.casevault.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/** Prevents post-authentication open redirects (CWE-601) by allowing only local absolute paths. */
@Component
public final class SafeAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String target = request.getParameter("redirect");
        response.sendRedirect(isSafeRelativePath(target) ? target : request.getContextPath() + "/");
    }

    static boolean isSafeRelativePath(String target) {
        if (target == null || target.isBlank() || !target.startsWith("/") || target.startsWith("//")
                || target.contains("\\") || target.chars().anyMatch(Character::isISOControl)) return false;
        try {
            URI uri = URI.create(target);
            return !uri.isAbsolute() && uri.getRawAuthority() == null;
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }
}
