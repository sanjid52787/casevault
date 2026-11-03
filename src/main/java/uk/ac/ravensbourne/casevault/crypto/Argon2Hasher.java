package uk.ac.ravensbourne.casevault.crypto;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.security.crypto.password.PasswordEncoder;
import uk.ac.ravensbourne.casevault.config.SecurityConfiguration;

/**
 * CLI utility for generating an Argon2id password hash for initial administrator bootstrap (CWE-521, CWE-916).
 * <p>
 * Derives its exact parameters directly from {@link SecurityConfiguration#passwordEncoder()} rather than hardcoding
 * cryptographic settings. Passwords are read strictly from a secret file path or standard input to avoid process-table
 * disclosure (CWE-214). Plaintext passwords are never logged or printed.
 */
public final class Argon2Hasher {
    private Argon2Hasher() { }

    public static void main(String[] args) throws Exception {
        String rawPassword;
        Path outputFile = null;

        if (args.length >= 1 && !"-".equals(args[0])) {
            Path secretFile = Path.of(args[0]).toAbsolutePath().normalize();
            if (!Files.isRegularFile(secretFile)) {
                throw new IllegalArgumentException("Secret file not found: " + secretFile);
            }
            rawPassword = Files.readString(secretFile, StandardCharsets.UTF_8).trim();
            if (args.length >= 2) {
                outputFile = Path.of(args[1]).toAbsolutePath().normalize();
            }
        } else {
            rawPassword = new String(System.in.readAllBytes(), StandardCharsets.UTF_8).trim();
            if (args.length >= 1 && !"-".equals(args[0])) {
                outputFile = Path.of(args[0]).toAbsolutePath().normalize();
            }
        }

        if (rawPassword.isBlank()) {
            throw new IllegalArgumentException("Password input cannot be blank");
        }

        PasswordEncoder encoder = new SecurityConfiguration().passwordEncoder();
        String hash = encoder.encode(rawPassword);

        if (outputFile != null) {
            Path parent = outputFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(outputFile, hash, StandardCharsets.UTF_8);
        } else {
            System.out.println(hash);
        }
    }
}

