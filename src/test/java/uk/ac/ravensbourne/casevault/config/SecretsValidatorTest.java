package uk.ac.ravensbourne.casevault.config;
import static org.junit.jupiter.api.Assertions.*; import jakarta.validation.Validation; import org.junit.jupiter.api.Test;
class SecretsValidatorTest { @Test void tConfig001RejectsBlankProductionSecrets(){var validator=Validation.buildDefaultValidatorFactory().getValidator();var invalid=new CaseVaultSecretsProperties("","","","");assertEquals(4,validator.validate(invalid).size());} }
