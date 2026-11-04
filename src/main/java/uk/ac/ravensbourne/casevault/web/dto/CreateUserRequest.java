package uk.ac.ravensbourne.casevault.web.dto;

import jakarta.validation.constraints.*;
import java.util.UUID;
import uk.ac.ravensbourne.casevault.domain.Role;

/**
 * Admin user-creation request; Bean Validation provides server-side defence (CWE-20).
 * The role allow-list deliberately excludes AUDITOR_ADMIN to prevent privilege escalation.
 */
public record CreateUserRequest(
    @NotBlank @Email @Size(max = 254) String email,
    @NotNull Role role,
    @NotNull UUID organisationId,
    @Size(max = 160) String displayName
) {}

