package uk.ac.ravensbourne.casevault.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import uk.ac.ravensbourne.casevault.security.CaseVaultUserDetailsService;

/**
 * Establishes a deny-by-default HTTP baseline to reduce accidental endpoint exposure (OWASP A01).
 * Authentication and fine-grained authorisation are introduced in subsequent phases.
 */
@Configuration
public class SecurityConfiguration {
    @Bean PasswordEncoder passwordEncoder(){ return new Argon2PasswordEncoder(16, 32, 1, 19456, 3); }
    @Bean DaoAuthenticationProvider authenticationProvider(CaseVaultUserDetailsService users, PasswordEncoder encoder){var provider=new DaoAuthenticationProvider(encoder);provider.setUserDetailsService(users);provider.setHideUserNotFoundExceptions(true);return provider;}
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, DaoAuthenticationProvider provider) throws Exception {
        return http
                .authenticationProvider(provider)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/css/**", "/actuator/health").permitAll()
                        .anyRequest().authenticated())
                .formLogin(login -> login.loginPage("/login").defaultSuccessUrl("/",true).failureUrl("/login?error"))
                .logout(logout -> logout.logoutUrl("/logout").invalidateHttpSession(true).deleteCookies("SESSION").logoutSuccessUrl("/login?logout"))
                .build();
    }
}
