package uk.ac.ravensbourne.casevault.web.dto;

import jakarta.validation.constraints.*;

/** Admin organisation-creation request; Bean Validation provides server-side defence (CWE-20). */
public record CreateOrganisationRequest(
    @NotBlank @Size(min = 2, max = 160) String name
) {}

