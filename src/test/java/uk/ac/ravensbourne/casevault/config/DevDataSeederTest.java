package uk.ac.ravensbourne.casevault.config;
import static org.junit.jupiter.api.Assertions.*; import org.junit.jupiter.api.Test; import org.springframework.context.annotation.Profile;
class DevDataSeederTest { @Test void tDev001SeederIsNeverActiveInProd(){var profile=DevDataSeeder.class.getAnnotation(Profile.class);assertNotNull(profile);assertArrayEquals(new String[]{"dev"},profile.value());} }
