package uk.ac.ravensbourne.casevault.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Operational retention policy: disabled unless explicitly enabled by a deployment profile. */
@ConfigurationProperties("casevault.retention")
public record RetentionProperties(boolean enabled, String cron, long retentionDays, long graceDays) { }
