package uk.ac.ravensbourne.casevault.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import uk.ac.ravensbourne.casevault.security.*;

/**
 * Establishes a deny-by-default HTTP baseline to reduce accidental endpoint exposure (OWASP A01).
 * Authentication and fine-grained authorisation are introduced in subsequent phases.
 */
@Configuration @EnableMethodSecurity
public class SecurityConfiguration {
    @Bean PasswordEncoder passwordEncoder(){ return new Argon2PasswordEncoder(16, 32, 1, 19456, 3); }

    /**
     * Backs Spring Security's concurrent-session control with the JDBC session store,
     * rather than an in-memory registry. This makes the two-session cap effective
     * across application instances (CWE-613).
     */
    @Bean
    @SuppressWarnings({"rawtypes", "unchecked"})
    SessionRegistry sessionRegistry(FindByIndexNameSessionRepository sessionRepository) {
        return new SpringSessionBackedSessionRegistry<Session>(sessionRepository);
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, CaseVaultAuthenticationProvider provider, LoginRateLimitFilter loginRate, AbsoluteSessionTimeoutFilter absolute, DisabledAccountSessionFilter disabled, SessionRegistry sessionRegistry, SafeAuthenticationSuccessHandler successHandler) throws Exception {
        return http
                .authenticationProvider(provider)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/css/**", "/actuator/health").permitAll()
                        .requestMatchers("/admin/**").hasRole("AUDITOR_ADMIN")
                        .anyRequest().authenticated())
                .formLogin(login -> login.loginPage("/login").successHandler(successHandler).failureUrl("/login?error"))
                .logout(logout -> logout.logoutUrl("/logout").invalidateHttpSession(true).deleteCookies("SESSION").logoutSuccessUrl("/login?logout"))
                .sessionManagement(session -> session.sessionFixation(fixation->fixation.changeSessionId())
                        .maximumSessions(2).maxSessionsPreventsLogin(false).sessionRegistry(sessionRegistry))
                .addFilterBefore(loginRate, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(absolute, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(disabled, AbsoluteSessionTimeoutFilter.class)
                .build();
    }
}
