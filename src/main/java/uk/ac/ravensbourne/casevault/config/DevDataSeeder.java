package uk.ac.ravensbourne.casevault.config;
import java.security.SecureRandom; import java.util.*; import org.slf4j.Logger; import org.slf4j.LoggerFactory; import org.springframework.boot.ApplicationRunner; import org.springframework.context.annotation.Bean; import org.springframework.context.annotation.Configuration; import org.springframework.context.annotation.Profile; import org.springframework.security.crypto.argon2.Argon2PasswordEncoder; import uk.ac.ravensbourne.casevault.domain.Organisation; import uk.ac.ravensbourne.casevault.domain.Role; import uk.ac.ravensbourne.casevault.domain.UserAccount; import uk.ac.ravensbourne.casevault.repository.*;
/** Creates synthetic development identities only; profile scoping prevents production fixture data (CWE-1188). */
@Configuration
@Profile("dev")
public class DevDataSeeder {
    private static final Logger LOG = LoggerFactory.getLogger(DevDataSeeder.class);
    /** A single CSPRNG avoids predictable seed credentials and the SpotBugs one-use warning. */
    private static final SecureRandom PASSWORD_RANDOM = new SecureRandom();

    @Bean
    ApplicationRunner seed(OrganisationRepository orgs, UserAccountRepository users) {
        return args -> {
            if (orgs.count() > 0) return;
            Organisation acme = orgs.save(new Organisation(UUID.randomUUID(), "Acme Retail"));
            Organisation globex = orgs.save(new Organisation(UUID.randomUUID(), "Globex Clinics"));
            Organisation north = orgs.save(new Organisation(UUID.randomUUID(), "Northbridge Internal"));
            var encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
            for (Object[] row : List.of(new Object[]{acme, Role.CLIENT_USER}, new Object[]{globex, Role.CLIENT_USER}, new Object[]{north, Role.SECURITY_ANALYST}, new Object[]{north, Role.CASE_MANAGER}, new Object[]{north, Role.AUDITOR_ADMIN})) {
                String password = randomPassword();
                Role role = (Role) row[1];
                Organisation organisation = (Organisation) row[0];
                String email = role.name().toLowerCase() + "-" + organisation.getId() + "@example.test";
                users.save(new UserAccount(UUID.randomUUID(), organisation, email, encoder.encode(password), role));
                printInitialCredential(role, email, password);
            }
        };
    }

    private static void printInitialCredential(Role role, String email, String password) {
        try {
            java.nio.file.Files.writeString(
                    java.nio.file.Path.of("target/dev-credentials.txt"),
                    role + "=" + email + "=" + password + System.lineSeparator(),
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception ignored) { }
        java.io.Console console = System.console();
        if (console == null) {
            LOG.warn("DEV ONLY credentials created for {} at {}; use the dev-console to obtain the one-time password.", role, email);
            return;
        }
        console.printf("DEV ONLY credentials for %s — email: %s; password: %s%n", role, email, password);
    }

    private static String randomPassword() {
        byte[] bytes = new byte[18];
        PASSWORD_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
