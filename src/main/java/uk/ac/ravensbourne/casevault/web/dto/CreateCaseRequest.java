package uk.ac.ravensbourne.casevault.web.dto;
import jakarta.validation.constraints.*; import uk.ac.ravensbourne.casevault.domain.*;
public record CreateCaseRequest(@NotBlank @Size(min=5,max=120) String title,@NotBlank @Size(max=5000) String description,@NotNull Category category,@NotNull Severity severity) { }
