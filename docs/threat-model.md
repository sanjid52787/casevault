# CaseVault threat model

## Evidence upload residual risk

Evidence upload currently reads a file into memory after the multipart size check and before Tika
inspection, scanning, hashing and AEAD encryption. This keeps the validation sequence simple and
ensures that no unvalidated content reaches the permanent store. It still creates bounded memory
pressure: a concurrent set of requests can hold up to 10 MiB each.

The residual risk is mitigated by the 10 MiB application and multipart limits, independent
per-user and per-source-IP Bucket4j quotas, and an aggregated rate-limit audit event. A future
streaming pipeline may reduce this further, but must preserve the current fail-closed ordering and
AEAD associated-data binding.

The bundled `NoOpScanService` accepts synthetic academic evidence only. It is an integration seam,
not an anti-malware control. A real deployment requires a local isolated scanner implementation.
