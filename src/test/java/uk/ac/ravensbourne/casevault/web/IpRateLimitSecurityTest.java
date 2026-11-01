package uk.ac.ravensbourne.casevault.web;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
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

/** T-RATE-005 proves the search IP bucket is shared by different principals (CWE-770). */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IpRateLimitSecurityTest {
    private static final String SHARED_IP = "198.51.100.55";

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired TestDataCleaner cleaner;

    private UserAccount firstClient;
    private UserAccount secondClient;

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        cleaner.clean();
        firstClient = user("IP Rate Client A", "ip-rate-a@example.test");
        secondClient = user("IP Rate Client B", "ip-rate-b@example.test");
    }

    @AfterEach
    void cleanUp() {
        cleaner.clean();
    }

    @Test
    void tRate005DifferentUsersOnTheSameIpShareTheIpBucket() throws Exception {
        for (int request = 0; request < 3; request++) {
            search(firstClient).andExpect(status().isOk());
        }
        for (int request = 0; request < 2; request++) {
            search(secondClient).andExpect(status().isOk());
        }
        search(secondClient)
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"));
    }

    private org.springframework.test.web.servlet.ResultActions search(UserAccount account) throws Exception {
        return mvc.perform(get("/cases")
                .with(authentication(auth(account)))
                .with(request -> { request.setRemoteAddr(SHARED_IP); return request; }));
    }

    private UserAccount user(String organisationName, String email) {
        Organisation organisation = organisations.save(new Organisation(UUID.randomUUID(), organisationName));
        return users.save(new UserAccount(UUID.randomUUID(), organisation, email, "hash", Role.CLIENT_USER));
    }

    private UsernamePasswordAuthenticationToken auth(UserAccount account) {
        UserPrincipal principal = UserPrincipal.from(account);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }
}
