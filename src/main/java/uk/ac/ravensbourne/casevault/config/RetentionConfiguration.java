package uk.ac.ravensbourne.casevault.config;

import java.time.Clock;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(RetentionProperties.class)
public class RetentionConfiguration {
    @Bean
    Clock retentionClock() {
        return Clock.systemUTC();
    }
}
