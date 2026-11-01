package uk.ac.ravensbourne.casevault.report;
import org.springframework.stereotype.Service;
/** Removes common accidental secrets and identifiers before client report generation. */
@Service public class Redactor { public String redact(String value){return value.replaceAll("(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}","[redacted-email]").replaceAll("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b","[redacted-ip]").replaceAll("(?i)\\b(?:api[_-]?key|token|secret)\\s*[=:]\\s*[A-Za-z0-9_\\-]{8,}\\b|\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b|\\bsk-[A-Za-z0-9_-]{16,}\\b","[redacted-secret]");} }
