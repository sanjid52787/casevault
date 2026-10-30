package uk.ac.ravensbourne.casevault.config;
import jakarta.validation.constraints.NotBlank; import org.springframework.boot.context.properties.ConfigurationProperties;
@ConfigurationProperties("casevault.secrets") public record CaseVaultSecretsProperties(@NotBlank String databasePassword,@NotBlank String tinkKeysetPath,@NotBlank String auditHmacKey,@NotBlank String sessionSecret) { }
