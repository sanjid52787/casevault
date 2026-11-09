# CaseVault Local Runbook (Windows & PowerShell)

This runbook provides exact procedures for operating CaseVault locally on Windows using PowerShell, both **without Docker** (development/evaluation mode with synthetic accounts and in-memory database) and **with Docker** (hardened production container topology).

---

# Part 1: Running Locally Without Docker (Development Mode)

Running CaseVault directly on Windows without Docker uses the `dev` profile with an in-memory PostgreSQL-compatible H2 database, local Tink keyset, and seeded synthetic accounts across all four system roles.

## 1. Prerequisites

* **OS**: Windows 10/11 with PowerShell 5.1 or PowerShell 7+.
* **Java**: Eclipse Temurin OpenJDK 21 LTS (`java -version`).
* **Maven**: Built-in Maven Wrapper (`.\mvnw.cmd`).

## 2. Configuration & Property Names

All configuration adheres strictly to `src/main/resources/application.yml` and `application-dev.yml`:

| Configuration Property | Environment Variable | Development Value / Purpose |
| :--- | :--- | :--- |
| `spring.profiles.active` | `SPRING_PROFILES_ACTIVE` | `dev` |
| Maven runtime opts | `MAVEN_OPTS` | `-Dspring-boot.run.useTestClasspath=true` (exposes test-scoped H2 driver) |
| `spring.datasource.url` | `CASEVAULT_DB_URL` | `jdbc:h2:mem:casevaultdev;MODE=PostgreSQL;DB_CLOSE_DELAY=-1` |
| `spring.datasource.username` | `CASEVAULT_DB_USERNAME` | `sa` |
| `spring.datasource.password` | `CASEVAULT_DB_PASSWORD` | `""` (empty string) |
| `casevault.audit.hmac-key` | `AUDIT_HMAC_KEY` | Process-local 32-byte Base64 key for HMAC-SHA256 audit log chain |
| `casevault.crypto.tink.keyset-path` | `TINK_KEYSET_PATH` | Path to generated Tink AES-256-GCM keyset (e.g. `target\dev-tink-keyset.json`) |
| `casevault.evidence.directory` | `CASEVAULT_EVIDENCE_DIRECTORY` | `uploads` (created in working directory, encrypted at rest) |
| `casevault.evidence.max-bytes` | `CASEVAULT_EVIDENCE_MAX_BYTES` | `10485760` (10 MB maximum upload limit) |
| `casevault.evidence.max-files-per-case`| `CASEVAULT_EVIDENCE_MAX_FILES_PER_CASE` | `20` files per case |

## 3. Quick Start (Automated Script)

The repository provides an automated startup script `scripts/start-dev.ps1` that sets all environment variables, generates the ephemeral audit key and Tink keyset, and launches the application:

```powershell
.\scripts\start-dev.ps1
```

## 4. Manual Exact PowerShell Commands (Step-by-Step)

To configure and launch CaseVault manually from PowerShell without Docker:

```powershell
# 1. Set development profile and classpath options
$env:SPRING_PROFILES_ACTIVE = "dev"
$env:MAVEN_OPTS = "-Dspring-boot.run.useTestClasspath=true"

# 2. Configure in-memory PostgreSQL-mode H2 database
$env:CASEVAULT_DB_URL = "jdbc:h2:mem:casevaultdev;MODE=PostgreSQL;DB_CLOSE_DELAY=-1"
$env:CASEVAULT_DB_USERNAME = "sa"
$env:CASEVAULT_DB_PASSWORD = ""

# 3. Generate random 32-byte Base64 HMAC key for audit logging
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$auditBytes = New-Object byte[] 32
$rng.GetBytes($auditBytes)
$rng.Dispose()
$env:AUDIT_HMAC_KEY = [Convert]::ToBase64String($auditBytes)

# 4. Generate local Tink AES-GCM keyset for evidence encryption
New-Item -ItemType Directory -Path "target" -Force | Out-Null
$keysetPath = "target\dev-tink-keyset.json"
if (-not (Test-Path $keysetPath)) {
    .\mvnw.cmd -Dexec.mainClass=uk.ac.ravensbourne.casevault.crypto.DevTinkKeysetGenerator "-Dexec.args=$keysetPath" exec:java
}
$env:TINK_KEYSET_PATH = (Resolve-Path $keysetPath).Path

# 5. Launch CaseVault
.\mvnw.cmd spring-boot:run
```

## 5. Where Synthetic Logins Are Printed

When CaseVault starts under the `dev` profile, `uk.ac.ravensbourne.casevault.config.DevDataSeeder` automatically creates synthetic accounts, writes them to `target/dev-credentials.txt`, and outputs a formatted banner to stdout:

```text
========================================================================
CaseVault Development Credentials:
  CLIENT_USER:      email: client@example.test    password: ClientPass123!@#
  CLIENT_USER:      email: globex@example.test    password: GlobexPass123!@#
  SECURITY_ANALYST: email: analyst@example.test   password: AnalystPass123!@#
  CASE_MANAGER:     email: manager@example.test   password: ManagerPass123!@#
  AUDITOR_ADMIN:    email: admin@example.test     password: AdminPass123!@#
========================================================================
```

* **File location**: `target/dev-credentials.txt`
* **Log location**: Console stdout during application startup

## 6. URLs Per Role

Access the application in your browser at `http://localhost:8080`:

| Role | Synthetic Login | Primary URLs & Permissions |
| :--- | :--- | :--- |
| **Authentication** | *(All roles)* | `http://localhost:8080/login`<br>`http://localhost:8080/logout`<br>`http://localhost:8080/password/change` |
| **CLIENT_USER** | `client@example.test`<br>`globex@example.test` | `http://localhost:8080/cases` (View cases belonging to own organization only)<br>`http://localhost:8080/cases/new` (Submit new security incident case) |
| **SECURITY_ANALYST** | `analyst@example.test` | `http://localhost:8080/cases` (Investigation queue; assigned cases only)<br>`http://localhost:8080/cases/{id}` (Add investigation notes, remediation actions, upload evidence) |
| **CASE_MANAGER** | `manager@example.test` | `http://localhost:8080/cases` (View all cases across consultancy)<br>`http://localhost:8080/cases/{id}` (Assign analysts, transition case status, approve remediation reports) |
| **AUDITOR_ADMIN** | `admin@example.test` | `http://localhost:8080/admin/audit` (Inspect tamper-evident audit log)<br>`POST http://localhost:8080/admin/audit/verify` (Verify HMAC hash chain integrity)<br>`http://localhost:8080/admin/users` (User management: disable accounts, revoke sessions, reset lockout)<br>`http://localhost:8080/admin/health` (Storage probe and database health) |

## 7. Reset Steps (Development Mode)

Because the development database is stored in-memory (`jdbc:h2:mem:casevaultdev`), database state resets automatically when the process terminates.

To perform a complete clean reset of all local artifacts (evidence uploads, Tink keyset, and cached credentials):

```powershell
# 1. Stop the application (Ctrl+C in the terminal)

# 2. Clean uploaded evidence files
if (Test-Path "uploads") {
    Remove-Item -Recurse -Force "uploads"
}

# 3. Clean generated dev keys and credentials
if (Test-Path "target\dev-tink-keyset.json") {
    Remove-Item -Force "target\dev-tink-keyset.json"
}
if (Test-Path "target\dev-credentials.txt") {
    Remove-Item -Force "target\dev-credentials.txt"
}
```

---

# Part 2: Running Locally With Docker (Hardened Production Mode)

This section guides operators through deploying CaseVault in **production Docker mode** (`SPRING_PROFILES_ACTIVE=prod`) using PostgreSQL, Nginx reverse proxy with TLS, and Docker secrets.

## 1. Prerequisites

* **Operating System**: Windows 10/11 with PowerShell 5.1 or PowerShell 7+.
* **Docker Desktop**: Running with Compose v2.
* **OpenSSL**: Available in `PATH` (included with Git for Windows).
* **Port Availability**: Port `443` on `localhost` must be free.

## 2. Generate Local Secrets and TLS Certificates

CaseVault enforces strict secret separation in `prod` profile:

```powershell
# 1. Ensure secrets directory exists
New-Item -ItemType Directory -Path "secrets" -Force | Out-Null

# 2. Generate random high-entropy Docker secrets with owner-only permissions
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$names = @("postgres_password", "db_password", "migrator_password", "audit_hmac_key", "session_secret")

foreach ($name in $names) {
    $secretPath = "secrets\$name.txt"
    if (-not (Test-Path $secretPath)) {
        $bytes = New-Object byte[] 32
        $rng.GetBytes($bytes)
        $secretValue = [Convert]::ToBase64String($bytes)
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText((Resolve-Path .).Path + "\$secretPath", $secretValue, $utf8NoBom)
        icacls.exe $secretPath /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
        Write-Host "Created $secretPath" -ForegroundColor Green
    }
}
$rng.Dispose()

# 3. Generate Tink AES-256-GCM Keyset
.\scripts\gen-tink-keyset.ps1 -OutputPath "secrets\tink-keyset.json"
icacls.exe "secrets\tink-keyset.json" /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null

# 4. Generate local self-signed TLS certificate for Nginx proxy
New-Item -ItemType Directory -Path "secrets\tls" -Force | Out-Null
if (-not (Test-Path "secrets\tls\dev.crt")) {
    & "C:\Program Files\Git\usr\bin\openssl.exe" req -x509 -nodes -days 7 -newkey rsa:2048 `
        -keyout "secrets\tls\dev.key" `
        -out "secrets\tls\dev.crt" `
        -subj "/CN=localhost/O=Northbridge Cyber Response/OU=Local Development"
    icacls.exe "secrets\tls\dev.key" /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
    Write-Host "Generated TLS certificate and key in secrets\tls\" -ForegroundColor Green
}
```

## 3. Build and Start the Docker Stack

```powershell
# Build application image using multi-stage Dockerfile
docker compose -f docker-compose.yml -f docker-compose.hardened.yml build --no-cache

# Launch all services in background
docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d

# Verify service health
curl.exe --insecure --silent https://localhost/actuator/health
```

## 4. Bootstrap Initial AUDITOR_ADMIN Account

In production Docker mode, synthetic users are **not seeded** to eliminate default credential risks (CWE-1188). To provision the initial administrator:

```powershell
.\scripts\bootstrap-admin.ps1
```

Retrieve password from `secrets\admin_initial_password.txt` and log in at `https://localhost/login`.

## 5. Teardown (Docker Mode)

```powershell
# Stop containers
docker compose -f docker-compose.yml -f docker-compose.hardened.yml down

# Purge named volumes (complete state reset)
docker compose -f docker-compose.yml -f docker-compose.hardened.yml down -v
```
