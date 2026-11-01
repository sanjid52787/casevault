package uk.ac.ravensbourne.casevault.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/** Verifies strict CSP delivery and bans client-side injection sinks (OWASP ASVS V14). */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityHeadersTest {
    private static final Pattern EVENT_HANDLER = Pattern.compile("(?is)<[^>]*\\s+on[a-z][a-z0-9:_-]*\\s*=");
    private static final Pattern SCRIPT_OR_STYLE = Pattern.compile("(?is)<(script|style)\\b([^>]*)>");

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;

    private UserAccount client;
    private UserAccount auditor;
    private CaseRecord caseRecord;

    @BeforeEach
    void setUp() {
        TestDataCleaner.clean(jdbc);
        Organisation clientOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Header Client"));
        Organisation internalOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Header Internal"));
        client = users.save(new UserAccount(UUID.randomUUID(), clientOrganisation, "headers-client@example.test",
                "hash", Role.CLIENT_USER));
        auditor = users.save(new UserAccount(UUID.randomUUID(), internalOrganisation, "headers-auditor@example.test",
                "hash", Role.AUDITOR_ADMIN));
        caseRecord = cases.save(new CaseRecord(UUID.randomUUID(), clientOrganisation, "Header test case",
                "Synthetic content", Category.OTHER, Severity.LOW, client));
    }

    @AfterEach
    void cleanUp() {
        TestDataCleaner.clean(jdbc);
    }

    @Test
    void tHdr001NonceCspAndBrowserHeadersOnKeyRoutes() throws Exception {
        assertStrictCsp(mvc.perform(get("/login")));
        assertStrictCsp(mvc.perform(get("/cases").with(authentication(auth(client)))));
        assertStrictCsp(mvc.perform(get("/cases/{id}", caseRecord.getId()).with(authentication(auth(client)))));
        assertStrictCsp(mvc.perform(get("/admin/health").with(authentication(auth(auditor)))));
    }

    @Test
    void tHdr002TemplatesAndStaticJavaScriptForbidUnsafeSinks() throws Exception {
        scanDirectory(Path.of("src/main/resources/templates"), path -> true);
        scanDirectory(Path.of("src/main/resources/static"), path -> path.toString().endsWith(".js"));
    }

    @Test
    void tCors001PreflightIsRefused() throws Exception {
        mvc.perform(options("/cases").header("Origin", "https://evil.example")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    private void assertStrictCsp(ResultActions response) throws Exception {
        response.andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'none'")))
                .andExpect(header().string("Content-Security-Policy", containsString("'nonce-")))
                .andExpect(header().string("Content-Security-Policy", not(containsString("unsafe-inline"))))
                .andExpect(header().string("Content-Security-Policy", not(containsString("unsafe-eval"))))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"));
    }

    private void scanDirectory(Path root, java.util.function.Predicate<Path> include) throws IOException {
        try (var paths = Files.walk(root)) {
            for (Path path : paths.filter(Files::isRegularFile).filter(include).toList()) {
                assertSafeClientSource(path, Files.readString(path));
            }
        }
    }

    private void assertSafeClientSource(Path path, String source) {
        String lower = source.toLowerCase(Locale.ROOT);
        assertFalse(lower.contains("th:utext"), () -> path + " contains th:utext");
        assertFalse(lower.contains("innerhtml"), () -> path + " contains innerHTML");
        assertFalse(lower.contains("document.write"), () -> path + " contains document.write");
        assertFalse(Pattern.compile("(?i)\\beval\\s*\\(").matcher(source).find(), () -> path + " contains eval(");
        assertFalse(lower.contains("localstorage"), () -> path + " contains localStorage");
        assertFalse(lower.contains("sessionstorage"), () -> path + " contains sessionStorage");
        assertFalse(EVENT_HANDLER.matcher(source).find(), () -> path + " contains an inline event handler");

        Matcher tag = SCRIPT_OR_STYLE.matcher(source);
        while (tag.find()) {
            assertTrue(Pattern.compile("(?i)\\bnonce\\s*=").matcher(tag.group(2)).find(),
                    () -> path + " contains a " + tag.group(1) + " element without a nonce attribute");
        }
    }

    private UsernamePasswordAuthenticationToken auth(UserAccount account) {
        UserPrincipal principal = UserPrincipal.from(account);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }
}
