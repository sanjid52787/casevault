# Accepted Security Risks Register (.trivyignore)

This document records vulnerabilities suppressed in [`.trivyignore`](../../.trivyignore) for container and filesystem scans. In accordance with CaseVault security standards, suppression is only permitted when code evidence proves the vulnerable component or execution path is not reachable or utilized, and where remediation requires a major framework migration not permissible within current project constraints.

---

## 1. Risk Register

| CVE ID | Library & Installed Version | Severity | Fixed Version | Rationale & Proof of Non-Usage | Conditions Under Which Risk Returns | Review Date | Planned Action |
|---|---|---|---|---|---|---|---|
| **CVE-2026-47884** | `org.springframework:spring-webmvc:6.2.19` | CRITICAL | `7.0.9` (requires Spring Framework 7 / Spring Boot 4 major upgrade) | **Feature not used.** Vulnerability resides in XSLT view resolution (`XsltView`, `XsltViewResolver`). CaseVault uses server-rendered Thymeleaf (`thymeleaf-spring6`) exclusively; no XSLT templates or view resolvers exist in `src/`. | Adding XSLT template rendering, configuring `XsltViewResolver`, or rendering untrusted XSL stylesheets before upgrading to Spring Framework 7+. | 2026-11-09 | migrate to Spring Boot 4 after the assessment |
| **CVE-2026-47890** | `org.springframework:spring-webmvc:6.2.19` | CRITICAL | `7.0.9` (requires Spring Framework 7 / Spring Boot 4 major upgrade) | **Feature not used.** Vulnerability affects Server-Sent Events (SSE) stream processing in `SseEmitter` / `ResponseBodyEmitter` and WebFlux SSE views. CaseVault does not use streaming endpoints, does not import WebFlux, and does not instantiate `SseEmitter` or `ResponseBodyEmitter`. | Introducing asynchronous streaming endpoints, Server-Sent Events (`text/event-stream`), `SseEmitter`, or `ResponseBodyEmitter` before upgrading to Spring Framework 7+. | 2026-11-09 | migrate to Spring Boot 4 after the assessment |

---

## 2. Verification Evidence (Reproducible Search Commands)

Verification was performed on 2026-11-09 across the entire codebase to confirm that none of the vulnerable classes, media types, or reactive streaming components are referenced.

### 2.1 Evidence for CVE-2026-47884 (`XsltView` / `XsltViewResolver`)

#### Command 1: Search for `XsltView`
```bash
git grep -in "XsltView" src/; if ($LASTEXITCODE -ne 0) { "no matches found (exit code $LASTEXITCODE)" }
```
**Output**:
```text
no matches found (exit code 1)
```

#### Command 2: Search for `XsltViewResolver`
```bash
git grep -in "XsltViewResolver" src/; if ($LASTEXITCODE -ne 0) { "no matches found (exit code $LASTEXITCODE)" }
```
**Output**:
```text
no matches found (exit code 1)
```

---

### 2.2 Evidence for CVE-2026-47890 (`SseEmitter` / `ResponseBodyEmitter` / `text/event-stream` / `WebFlux`)

#### Command 3: Search for `SseEmitter`
```bash
git grep -in "SseEmitter" src/; if ($LASTEXITCODE -ne 0) { "no matches found (exit code $LASTEXITCODE)" }
```
**Output**:
```text
no matches found (exit code 1)
```

#### Command 4: Search for `ResponseBodyEmitter`
```bash
git grep -in "ResponseBodyEmitter" src/; if ($LASTEXITCODE -ne 0) { "no matches found (exit code $LASTEXITCODE)" }
```
**Output**:
```text
no matches found (exit code 1)
```

#### Command 5: Search for `text/event-stream`
```bash
git grep -in "text/event-stream" src/; if ($LASTEXITCODE -ne 0) { "no matches found (exit code $LASTEXITCODE)" }
```
**Output**:
```text
no matches found (exit code 1)
```

#### Command 6: Search for `WebFlux`
```bash
git grep -in "WebFlux" src/ pom.xml; if ($LASTEXITCODE -ne 0) { "no matches found (exit code $LASTEXITCODE)" }
```
**Output**:
```text
no matches found (exit code 1)
```

---

## 3. Maintenance and Lifecycle Policy

1. **Automated CI Enforcement**: [`.trivyignore`](../../.trivyignore) is mounted into the container scanning step of `.github/workflows/ci.yml`. Any vulnerability outside of these two explicitly accepted entries will immediately fail the CI build (`--exit-code 1`).
2. **Re-Verification on Changes**: If any team member introduces real-time messaging, asynchronous streaming, or document transformation views, this document and [`.trivyignore`](../../.trivyignore) must be immediately invalidated.
3. **Target Resolution**: Planned action is to **migrate to Spring Boot 4 after the assessment** when Spring Framework 7 becomes the standard production baseline for CaseVault.

