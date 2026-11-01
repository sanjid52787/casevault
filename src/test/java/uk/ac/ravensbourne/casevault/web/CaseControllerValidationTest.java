package uk.ac.ravensbourne.casevault.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
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
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/** Regression tests for safe, usable server-side validation of the create-case form. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class CaseControllerValidationTest {
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    private UserAccount client;

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        TestDataCleaner.clean(jdbc);
        Organisation organisation = organisations.save(new Organisation(UUID.randomUUID(), "Validation Client"));
        client = users.save(new UserAccount(UUID.randomUUID(), organisation, "validation-client@test", "hash", Role.CLIENT_USER));
    }

    @AfterEach
    void cleanFixtures() { TestDataCleaner.clean(jdbc); }

    @Test
    void tCase006InvalidTitleShowsEscapedValidationMessage() throws Exception {
        mvc.perform(post("/cases").with(authentication(auth())).with(csrf())
                        .param("title", "bad")
                        .param("description", "Synthetic description")
                        .param("category", "OTHER")
                        .param("severity", "LOW"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Enter a title between 5 and 120 characters.")))
                .andExpect(content().string(not(containsString("Exception"))))
                .andExpect(content().string(not(containsString("java.lang"))));
    }

    @Test
    void tCase007UnknownEnumIsRejectedGracefully() throws Exception {
        mvc.perform(post("/cases").with(authentication(auth())).with(csrf())
                        .param("title", "Valid incident title")
                        .param("description", "Synthetic description")
                        .param("category", "NOT_A_CATEGORY")
                        .param("severity", "LOW"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Choose a valid category.")))
                .andExpect(content().string(not(containsString("Exception"))))
                .andExpect(content().string(not(containsString("uk.ac.ravensbourne"))));
    }

    private UsernamePasswordAuthenticationToken auth() {
        UserPrincipal principal = UserPrincipal.from(client);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }
}
