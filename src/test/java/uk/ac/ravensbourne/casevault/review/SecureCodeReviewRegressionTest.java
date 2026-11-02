package uk.ac.ravensbourne.casevault.review;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.SessionRevocationService;
import uk.ac.ravensbourne.casevault.security.LoginRateLimiter;
import uk.ac.ravensbourne.casevault.security.LoginRateLimitFilter;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.AdminAccountService;

/** Regression coverage for Phase 9 review findings F-SCR-002 and F-SCR-003. */
class SecureCodeReviewRegressionTest {
    @Test
    /** F-SCR-002 regression. */
    void tScr002DevSeederDoesNotPutPlaintextPasswordInApplicationLogTemplate() throws Exception {
        String source = Files.readString(Path.of("src/main/java/uk/ac/ravensbourne/casevault/config/DevDataSeeder.java"));
        assertFalse(source.contains("LOG.warn(\"DEV ONLY credentials for {} — email: {}; password: {}\""));
    }

    @Test
    /** F-SCR-003 regression. */
    void tScr003NonAdminCannotInvokeAccountDisableServiceDirectly() {
        UserAccountRepository users = mock(UserAccountRepository.class);
        SessionRevocationService sessions = mock(SessionRevocationService.class);
        AuditService audit = mock(AuditService.class);
        AdminAccountService service = new AdminAccountService(users, sessions, audit);
        UserPrincipal client = new UserPrincipal(UUID.randomUUID(), UUID.randomUUID(), "client@example.test", "",
                Role.CLIENT_USER.name(), true, false);

        assertThrows(AccessDeniedException.class,
                () -> service.disable(client, UUID.randomUUID(), "synthetic authorised-review test"));
        verifyNoInteractions(users, sessions, audit);
    }

    @Test
    /** F-SCR-004 regression / T-SCR-004. */
    void tScr004LoginLimiterReturnsRetryDelayAndWritesOnlyOneAuditEventPerWindow() {
        AuditService audit = mock(AuditService.class);
        LoginRateLimiter limiter = new LoginRateLimiter(audit);
        for (int attempt = 0; attempt < 10; attempt++) {
            assertTrue(limiter.consume("203.0.113.90", "review@example.test").allowed());
        }
        LoginRateLimiter.Decision denied = limiter.consume("203.0.113.90", "review@example.test");
        assertFalse(denied.allowed());
        assertFalse(denied.retryAfterSeconds() < 1);
        limiter.consume("203.0.113.90", "review@example.test");
        org.mockito.Mockito.verify(audit, org.mockito.Mockito.times(1))
                .record(org.mockito.ArgumentMatchers.isNull(), org.mockito.ArgumentMatchers.eq(uk.ac.ravensbourne.casevault.audit.AuditEventType.RATE_LIMITED),
                        org.mockito.ArgumentMatchers.eq("AUTH"), org.mockito.ArgumentMatchers.isNull(), org.mockito.ArgumentMatchers.eq("login-rate-limited"));
    }

    @Test
    void tScr004LoginFilterReturns429WithRetryAfter() throws Exception {
        LoginRateLimitFilter filter = new LoginRateLimitFilter(new LoginRateLimiter(mock(AuditService.class)));
        for (int attempt = 0; attempt < 10; attempt++) {
            filter.doFilter(loginRequest(), new MockHttpServletResponse(), new MockFilterChain());
        }
        MockHttpServletResponse denied = new MockHttpServletResponse();
        filter.doFilter(loginRequest(), denied, new MockFilterChain());
        org.junit.jupiter.api.Assertions.assertEquals(429, denied.getStatus());
        org.junit.jupiter.api.Assertions.assertNotNull(denied.getHeader("Retry-After"));
    }

    private MockHttpServletRequest loginRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setServletPath("/login");
        request.setRemoteAddr("203.0.113.91");
        request.addParameter("username", "review-filter@example.test");
        return request;
    }
}
