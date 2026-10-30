package uk.ac.ravensbourne.casevault.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Establishes a deny-by-default HTTP baseline to reduce accidental endpoint exposure (OWASP A01).
 * Authentication and fine-grained authorisation are introduced in subsequent phases.
 */
@Configuration
public class SecurityConfiguration {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/actuator/health").permitAll()
                        .anyRequest().denyAll())
                .build();
    }
}
