# CaseVault Local Docker Deployment Runbook (Windows & PowerShell)

This runbook guides operators through deploying, provisioning, and operating CaseVault in **production Docker mode** on Windows using PowerShell.

---

## 1. Prerequisites

* **Operating System**: Windows 10/11 with PowerShell 5.1 or PowerShell 7+.
* **Docker Desktop**: Running with the Compose v2 plugin enabled.
* **Java**: Eclipse Temurin OpenJDK 21 LTS (`java -version`).
* **OpenSSL**: Available in `PATH` (included with Git for Windows at `C:\Program Files\Git\usr\bin\openssl.exe`).
* **Port Availability**: Port `443` on `localhost` must be free.

---

## 2. Generate Local Secrets and TLS Certificates

CaseVault enforces strict secret separation. In production Docker mode (`SPRING_PROFILES_ACTIVE: prod`), no secrets or credentials are hardcoded or checked into source control. All secrets are stored under `secrets/`, which is ignored by `.gitignore`.

From the project root in PowerShell:

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
        [System.IO.File]::WriteAllText((Resolve-Path .).Path + "\$secretPath", $secretValue, [System.Text.Encoding]::UTF8)
        icacls.exe $secretPath /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
        Write-Host "Created $secretPath" -ForegroundColor Green
    }
}
$rng.Dispose()

# 3. Generate Tink AES-256-GCM Keyset
.\scripts\gen-tink-keyset.ps1 -OutputPath "secrets\tink-keyset.json"
icacls.exe "secrets\tink-keyset.json" /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null

# 4. Generate local-only self-signed TLS certificate for Nginx proxy
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

---

## 3. Build and Start the Docker Stack

Build the hardened image and start the complete topology (PostgreSQL, Spring Boot app, Flyway migrator, DB grants enforcer, and Nginx reverse proxy):

```powershell
# Build application image using multi-stage Dockerfile
docker compose -f docker-compose.yml -f docker-compose.hardened.yml build --no-cache

# Launch all services in background
docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d
```

Verify service status and health:

```powershell
# Check running containers (storage-init and db-grants exit 0 after completing setup)
docker compose -f docker-compose.yml -f docker-compose.hardened.yml ps

# Probe health endpoint through the TLS reverse proxy
curl.exe --insecure --silent https://localhost/actuator/health
# Expected output: {"status":"UP"}
```

---

## 4. Bootstrap Initial AUDITOR_ADMIN Account

In Docker mode (`prod` profile), synthetic users are **not seeded** to eliminate default credential risks (CWE-1188). The database contains schema tables but zero user accounts.

To securely provision the first `AUDITOR_ADMIN`:

```powershell
.\scripts\bootstrap-admin.ps1
```

### What this script does:
1. **Connectivity Check**: Verifies that PostgreSQL is healthy and accepting queries.
2. **Strict Guard**: Queries `SELECT COUNT(*) FROM users;`. **If any user already exists, it immediately halts and refuses execution** (exit code 1) to prevent account hijacking or tampering.
3. **Password Generation/Ingestion**: Reads or generates a strong 32-character password in `secrets/admin_initial_password.txt` with owner-only ACLs (`icacls`).
4. **Argon2id Hashing**: Uses `Argon2Hasher` via `.\mvnw.cmd` to derive the hash using the application's actual `SecurityConfiguration.passwordEncoder()` bean (m=19456, t=3, p=1). Plaintext passwords are never passed via CLI arguments or printed.
5. **Safe SQL Insertion**: Provisions organisation `Northbridge Internal` and user `admin@example.test` with `role = 'AUDITOR_ADMIN'` and `force_password_reset = true`.
6. **Audit Integrity**: Direct SQL does not touch `audit_events`. The HMAC-SHA256 audit chain remains unperturbed.

### Proving Refusal on Initialized Database:
To test and prove that the bootstrap guard refuses execution once users exist:

```powershell
# Run the refusal test script
.\scripts\test-bootstrap-refusal.ps1
# Expected output: SUCCESS: bootstrap-admin.ps1 refused to execute and reported SECURITY REFUSAL as expected.
```

---

## 5. Authenticate and Complete Forced Password Reset

1. **Retrieve the Initial Password**:
   ```powershell
   Get-Content secrets\admin_initial_password.txt
   ```
2. **Access CaseVault Web Interface**:
   * Open `https://localhost/login` in your browser.
   * Enter Email: `admin@example.test`.
   * Enter Password: *(Value from `secrets\admin_initial_password.txt`)*.
3. **Change Password**:
   * Navigate to `https://localhost/password/change`.
   * Submit your current initial password and a new secure password (12+ characters, not common).
   * Upon change, `force_password_reset` is cleared, other sessions are revoked, and `PASSWORD_CHANGED` is logged into the audit chain.

---

## 6. Verify System Health and Audit Hash Chain

As `AUDITOR_ADMIN`, verify system integrity from the web interface:

1. **System Health**:
   * Visit `https://localhost/admin/health` to confirm database connectivity and storage probe status.
2. **Audit Verification**:
   * Visit `https://localhost/admin/audit` to view recorded security events (`LOGIN_SUCCESS`, `PASSWORD_CHANGED`).
   * Click **Verify chain integrity** (`POST /admin/audit/verify`).
   * Confirmation message: `Audit chain verification: INTACT (0 broken events)`.

---

## 7. Shutdown and Teardown

To stop the Docker stack:

```powershell
docker compose -f docker-compose.yml -f docker-compose.hardened.yml down
```

To stop and purge persistent named volumes (for a clean restart):

```powershell
docker compose -f docker-compose.yml -f docker-compose.hardened.yml down -v
```

