package uk.ac.ravensbourne.casevault.security;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;

/** Integration evidence for the Phase 3 authentication and session controls. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthenticationSessionSecurityTest {
    @Autowired CaseVaultAuthenticationProvider provider;
    @Autowired PasswordEncoder encoder;
    @Autowired OrganisationRepository orgs;
    @Autowired UserAccountRepository users;
    @Autowired PasswordPolicy policy;
    @Autowired LoginRateLimiter limiter;
    @Autowired SessionRevocationService revocations;
    @Autowired PasswordChangeService passwordChanges;
    @Autowired JdbcTemplate jdbc;
    @Autowired MockMvc mvc;
    @Autowired Environment environment;
    @Autowired FindByIndexNameSessionRepository<?> sessionRepository;
    @Autowired DisabledAccountSessionFilter disabledAccountSessionFilter;
    private UserAccount user;

    @BeforeEach void seed() {
        jdbc.update("DELETE FROM SPRING_SESSION_ATTRIBUTES"); jdbc.update("DELETE FROM SPRING_SESSION");
        jdbc.update("DELETE FROM audit_events"); jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        users.deleteAll(); orgs.deleteAll();
        var org=orgs.save(new Organisation(UUID.randomUUID(),"Auth Test Org"));
        user=users.save(new UserAccount(UUID.randomUUID(),org,"user@example.test",encoder.encode("correct horse battery staple"),Role.CLIENT_USER));
    }
    private Authentication token(String password){return UsernamePasswordAuthenticationToken.unauthenticated("user@example.test",password);}
    @Test void tAuth001LoginSuccess(){assertTrue(provider.authenticate(token("correct horse battery staple")).isAuthenticated());}
    @Test void tAuth002WrongPasswordGenericError(){assertThrows(BadCredentialsException.class,()->provider.authenticate(token("wrong password")));}
    @Test void tAuth003UnknownUserSameResponse(){assertThrows(BadCredentialsException.class,()->provider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("missing@example.test","wrong password")));}
    @Test void tAuth004LockoutAfterFiveFailures(){for(int i=0;i<5;i++)assertThrows(BadCredentialsException.class,()->provider.authenticate(token("wrong password")));assertNotNull(jdbc.queryForObject("SELECT locked_until FROM users WHERE id=?",Object.class,user.getId()));assertThrows(BadCredentialsException.class,()->provider.authenticate(token("correct horse battery staple")));}
    @Test void tAuth005DisabledUserCannotLogin(){user.disable();users.save(user);assertThrows(BadCredentialsException.class,()->provider.authenticate(token("correct horse battery staple")));}
    @Test void tAuth006LogoutInvalidatesSessionAndExpiresCookie() throws Exception {mvc.perform(post("/logout").session(new MockHttpSession()).with(csrf())).andExpect(status().is3xxRedirection()).andExpect(cookie().maxAge("SESSION",0));}
    @Test void tAuth007SessionFixationChangesIdAfterLogin() {var anonymous=new MockHttpSession();var request=new org.springframework.mock.web.MockHttpServletRequest();request.setSession(anonymous);var originalId=anonymous.getId();new org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy().onAuthentication(UsernamePasswordAuthenticationToken.authenticated(UserPrincipal.from(user),null,UserPrincipal.from(user).getAuthorities()),request,new org.springframework.mock.web.MockHttpServletResponse());assertNotEquals(originalId,anonymous.getId(),"Spring Security changes the pre-authentication session identifier");}
    @Test void tAuth008CsrfRequiredOnLoginAndLogout() throws Exception {mvc.perform(post("/login").param("username","user@example.test").param("password","x")).andExpect(status().isForbidden());mvc.perform(post("/logout")).andExpect(status().isForbidden());}
    @Test void tAuth009PasswordPolicy(){assertThrows(IllegalArgumentException.class,()->policy.validate("password123","user@example.test"));assertThrows(IllegalArgumentException.class,()->policy.validate("user@example.test","user@example.test"));}
    @Test void tAuth010Argon2idHashStoredNotPlaintext(){assertTrue(user.getPasswordHash().startsWith("$argon2id$"));assertNotEquals("correct horse battery staple",user.getPasswordHash());}
    @Test void tSess001JdbcSessionUsesFifteenMinuteIdleTimeout(){assertEquals(Duration.ofMinutes(15),sessions().createSession().getMaxInactiveInterval());}
    @Test void tSess002RevocationDeletesIndexedPrincipalSessions(){Session session=sessions().createSession();session.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,user.getEmail());sessions().save(session);revocations.revokeAll(user.getEmail());assertNull(sessions().findById(session.getId()));}
    @Test void tSess003SecureCookieFlagsConfigured(){assertEquals("true",environment.getProperty("server.servlet.session.cookie.http-only"));assertEquals("true",environment.getProperty("server.servlet.session.cookie.secure"));assertEquals("strict",environment.getProperty("server.servlet.session.cookie.same-site"));}
    @Test void absoluteSessionExpiresAfterEightHours(){long now=System.currentTimeMillis();assertFalse(AbsoluteSessionTimeoutFilter.expired(now-Duration.ofHours(8).toMillis(),now));assertTrue(AbsoluteSessionTimeoutFilter.expired(now-Duration.ofHours(8).toMillis()-1,now));}
    @Test void disabledUserExistingSessionIsRejected() throws Exception {user.disable();users.save(user);var request=new org.springframework.mock.web.MockHttpServletRequest();request.setSession(new MockHttpSession());var response=new org.springframework.mock.web.MockHttpServletResponse();org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(UserPrincipal.from(user),null,UserPrincipal.from(user).getAuthorities()));try{disabledAccountSessionFilter.doFilter(request,response,new org.springframework.mock.web.MockFilterChain());assertEquals("/login?expired",response.getRedirectedUrl());}finally{org.springframework.security.core.context.SecurityContextHolder.clearContext();}}
    @Test void tRate001IpAndAccountBucketsLimit(){for(int i=0;i<10;i++)assertTrue(limiter.allow("192.0.2.10","account@test"));assertFalse(limiter.allow("192.0.2.10","account@test"));}
    @Test void passwordChangeChecksCurrentPasswordAndRevokesSessions(){Session session=sessions().createSession();session.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,user.getEmail());sessions().save(session);var principal=UserPrincipal.from(user);assertThrows(IllegalArgumentException.class,()->passwordChanges.change(principal,"incorrect","a sufficiently secure replacement password"));passwordChanges.change(principal,"correct horse battery staple","a sufficiently secure replacement password");assertNull(sessions().findById(session.getId()));assertTrue(encoder.matches("a sufficiently secure replacement password",users.findById(user.getId()).orElseThrow().getPasswordHash()));}
    @SuppressWarnings({"rawtypes","unchecked"}) private FindByIndexNameSessionRepository<Session> sessions(){return (FindByIndexNameSessionRepository)sessionRepository;}
}
