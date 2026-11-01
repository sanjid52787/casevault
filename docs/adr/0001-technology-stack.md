# ADR 0001: Technology stack

**Status:** Accepted (Phase 0)
**Date:** 2026-10-30

## Context

CaseVault needs a maintainable Java web application with strong, standard security building blocks and a server-rendered interface.

## Decision

- Use Java 21 LTS and Spring Boot 3.4.x with Spring MVC, Security, Data JPA, Validation, and Thymeleaf.
- Use Thymeleaf server-side rendering. It reduces client-side attack surface by avoiding a separate rich client and its browser-stored credentials/API contracts; it does not replace server-side validation or authorisation.
- Use PostgreSQL in deployed environments and Flyway for versioned migrations.
- Use Google Tink AES-GCM AEAD for evidence encryption at rest; test uses an ephemeral in-memory keyset and non-test profiles load a configured keyset path.
- Use Spring Security's Argon2id password encoder, backed by Bouncy Castle, for authentication.

## Consequences

These mature components reduce custom security code. They require pinned dependency review, patched releases, correct operational configuration, and automated tests. Authentication, encrypted evidence and persistence controls now exist; this ADR remains a design decision, while current test evidence is indexed separately.
