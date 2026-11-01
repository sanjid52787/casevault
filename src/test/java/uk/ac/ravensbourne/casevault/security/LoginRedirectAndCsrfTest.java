package uk.ac.ravensbourne.casevault.security;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/** Verifies post-authentication redirect safety and session-bound CSRF tokens. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class LoginRedirectAndCsrfTest {
    private static final Pattern CSRF = Pattern.compile("name=\"([^\"]+)\" value=\"([^\"]+)\"");

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired PasswordEncoder encoder;
    private UserAccount user;

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM SPRING_SESSION_ATTRIBUTES");
        jdbc.update("DELETE FROM SPRING_SESSION");
        TestDataCleaner.clean(jdbc);
        Organisation organisation = organisations.save(new Organisation(UUID.randomUUID(), "Redirect Test Organisation"));
        user = users.save(new UserAccount(UUID.randomUUID(), organisation, "redirect@example.test",
                encoder.encode("correct horse battery staple"), Role.CLIENT_USER));
    }

    @AfterEach
    void cleanUp() {
        jdbc.update("DELETE FROM SPRING_SESSION_ATTRIBUTES");
        jdbc.update("DELETE FROM SPRING_SESSION");
        TestDataCleaner.clean(jdbc);
    }

    @Test
    void tRedir001OnlySameOriginRelativeTargetsAreAccepted() throws Exception {
        login("/cases").andExpect(redirectedUrl("/cases"));
        login("https://attacker.example/").andExpect(redirectedUrl("/"));
        login("//attacker.example/").andExpect(redirectedUrl("/"));
        login("javascript:alert(1)").andExpect(redirectedUrl("/"));
    }

    @Test
    void tCsrf001PostWithoutTokenReturns403() throws Exception {
        mvc.perform(post("/cases").with(authentication(auth()))
                        .param("title", "Synthetic incident")
                        .param("description", "Synthetic description")
                        .param("category", "OTHER").param("severity", "LOW"))
                .andExpect(status().isForbidden());
    }

    @Test
    void tCsrf002TokenFromAnotherSessionIsRejected() throws Exception {
        MockHttpSession firstSession = new MockHttpSession();
        String page = mvc.perform(get("/login").session(firstSession))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        Matcher matcher = CSRF.matcher(page);
        assertNotNull(matcher.find() ? matcher.group(1) : null, "login form must contain a CSRF token");
        String parameterName = matcher.group(1);
        String token = matcher.group(2);

        mvc.perform(post("/logout").session(new MockHttpSession()).param(parameterName, token))
                .andExpect(status().isForbidden());
    }

    private org.springframework.test.web.servlet.ResultActions login(String redirect) throws Exception {
        return mvc.perform(post("/login").with(csrf())
                .param("username", user.getEmail())
                .param("password", "correct horse battery staple")
                .param("redirect", redirect));
    }

    private UsernamePasswordAuthenticationToken auth() {
        UserPrincipal principal = UserPrincipal.from(user);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }
}
