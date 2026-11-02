package uk.ac.ravensbourne.casevault.config;

import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.*;

/**
 * Creates synthetic development identities only; profile scoping prevents production fixture data (CWE-1188).
 */
@Configuration
@Profile("dev")
public class DevDataSeeder {
    private static final Logger LOG = LoggerFactory.getLogger(DevDataSeeder.class);

    @Bean
    ApplicationRunner seed(OrganisationRepository orgs, UserAccountRepository users) {
        return args -> {
            if (orgs.count() > 0) return;
            Organisation acme = orgs.save(new Organisation(UUID.randomUUID(), "Acme Retail"));
            Organisation globex = orgs.save(new Organisation(UUID.randomUUID(), "Globex Clinics"));
            Organisation north = orgs.save(new Organisation(UUID.randomUUID(), "Northbridge Internal"));
            var encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

            List<Object[]> standardAccounts = List.of(
                    new Object[]{acme, Role.CLIENT_USER, "client@example.test", "ClientPass123!@#"},
                    new Object[]{globex, Role.CLIENT_USER, "globex@example.test", "GlobexPass123!@#"},
                    new Object[]{north, Role.SECURITY_ANALYST, "analyst@example.test", "AnalystPass123!@#"},
                    new Object[]{north, Role.CASE_MANAGER, "manager@example.test", "ManagerPass123!@#"},
                    new Object[]{north, Role.AUDITOR_ADMIN, "admin@example.test", "AdminPass123!@#"}
            );

            StringBuilder banner = new StringBuilder();
            banner.append("\n========================================================================\n");
            banner.append("CaseVault Development Credentials:\n");

            for (Object[] row : standardAccounts) {
                Organisation organisation = (Organisation) row[0];
                Role role = (Role) row[1];
                String email = (String) row[2];
                String password = (String) row[3];
                users.save(new UserAccount(UUID.randomUUID(), organisation, email, encoder.encode(password), role));
                banner.append(String.format("  %-17s email: %-22s password: %s%n", role + ":", email, password));
                printInitialCredential(role, email, password);
            }
            banner.append("========================================================================\n");
            System.out.println(banner);
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
    }
}
