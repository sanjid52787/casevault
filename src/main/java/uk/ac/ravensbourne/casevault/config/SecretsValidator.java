package uk.ac.ravensbourne.casevault.config;
import org.springframework.boot.context.properties.EnableConfigurationProperties; import org.springframework.context.annotation.*; import org.springframework.validation.annotation.Validated;
/** Fails production startup when cryptographic or session secrets are missing (CWE-798). */
@Configuration @Profile("prod") @EnableConfigurationProperties(CaseVaultSecretsProperties.class) @Validated public class SecretsValidator { }
