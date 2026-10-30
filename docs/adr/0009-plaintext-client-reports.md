# ADR 0009: Plaintext downloadable client reports

CaseVault generates downloadable UTF-8 plaintext reports rather than PDF. This avoids a new rendering
library and a larger active content surface. The report includes only authorised case metadata,
client-visible findings and remediation status after Redactor processing; it excludes evidence,
internal notes, user identifiers and cross-tenant data.
