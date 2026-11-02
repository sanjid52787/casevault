# Third-party licences

| Dependency | Version | Licence | Purpose |
|---|---:|---|---|
| Spring Boot starters | 3.4.2 | Apache-2.0 | Web framework, MVC, Security, JPA, validation, actuator, tests |
| Flyway Core / PostgreSQL module | 10.20.1 | Apache-2.0 | Database migrations |
| PostgreSQL JDBC | 42.7.5 | BSD-2-Clause | PostgreSQL connectivity |
| Spring Session JDBC | 3.4.1 | Apache-2.0 | Server-side sessions |
| Thymeleaf Spring Security extras | 3.1.3.RELEASE | Apache-2.0 | Template security integration |
| Bucket4j | 8.10.1 | Apache-2.0 | Rate limiting |
| Google Tink | 1.16.0 | Apache-2.0 | Authenticated encryption |
| Error Prone annotations | 2.27.0 | Apache-2.0 | Tink/Gson transitive-version convergence |
| Apache Tika Core | 3.0.0 | Apache-2.0 | File content detection |
| OWASP Java HTML Sanitizer | 20240325.1 | Apache-2.0 | Rich-text sanitisation if introduced |
| Bouncy Castle Provider | 1.80 | MIT-like | Argon2id provider support |
| H2 | 2.3.232 | MPL-2.0 or EPL-1.0 | Test database only |
| Testcontainers | 1.20.4 | MIT | Optional integration-test infrastructure |

## Generated transitive inventory review

Generated on 2026-11-02 with:

```text
./mvnw -B -Plicence-report license:aggregate-third-party-report
```

The generated Maven report found **0 dependencies with no declared licence**. It is a local build artefact at
`target/aggregate-third-party-report.html`; the CycloneDX reference under `docs/assurance/sbom/` is the committed
dependency snapshot. The direct dependency table above remains a human-readable summary, while the Maven report
is the authoritative resolved transitive inventory for the build date.

Most resolved runtime dependencies declare Apache-2.0, MIT, BSD, EPL or MPL-family licences. The report also
shows dual-licensed transitive components, including Logback (EPL-1.0 or LGPL) and JNA (Apache-2.0 or
LGPL-2.1-or-later), and Jakarta APIs carrying EPL/GPL-with-Classpath-Exception alternatives. These are not
automatically classified as incompatible because use is as unmodified library dependencies, but distribution,
licence notices and any future change to bundled/modified code require a human licence review before release.
No AGPL dependency or missing-licence entry was reported by this run.
