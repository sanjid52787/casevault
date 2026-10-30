package uk.ac.ravensbourne.casevault.web.dto;
import jakarta.validation.constraints.*; import java.util.*; import uk.ac.ravensbourne.casevault.domain.*;
public final class CaseMutationRequests { private CaseMutationRequests(){} public record Assign(@NotNull UUID analystId){} public record Status(@NotNull CaseStatus status,Long version){public Status(CaseStatus status){this(status,null);}} public record Note(@NotBlank @Size(max=5000) String body,boolean clientVisible){} public record Action(@NotBlank @Size(max=5000) String description,@NotNull RemediationStatus status){} }
