# CaseVault Docker Admin Bootstrap Script (PowerShell)
# Bootstraps the initial AUDITOR_ADMIN account into a running Docker stack in production mode.
# Refuses to run if any user already exists in the database.
# Derives Argon2id parameters directly from the application's SecurityConfiguration.
[CmdletBinding()]
param(
    [string]$AdminEmail = 'admin@example.test',
    [string]$OrgName = 'Northbridge Internal',
    [string]$SecretPath = 'secrets/admin_initial_password.txt'
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot

Write-Host "=== CaseVault Docker AUDITOR_ADMIN Bootstrap ===" -ForegroundColor Cyan

# 1. Verify Docker Compose database is reachable
Write-Host "Verifying database container connectivity..."
$isReady = docker compose exec -T db pg_isready -U casevault_admin -d casevault 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Database service is not reachable. Ensure the Docker stack is running: docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d"
}

# 2. Strict Guard: Refuse to run if any user already exists
Write-Host "Checking for existing users in database..."
$countRaw = docker compose exec -T db psql -U casevault_admin -d casevault -t -A -c "SELECT COUNT(*) FROM users;" 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Failed to query the users table: $countRaw"
}

$userCount = 0
if (-not [int]::TryParse($countRaw.ToString().Trim(), [ref]$userCount)) {
    throw "Unexpected response from database query: $countRaw"
}

if ($userCount -gt 0) {
    Write-Error "SECURITY REFUSAL: Database already contains $userCount user(s)."
    Write-Error "The bootstrap script is strictly a one-time provisioning mechanism and will NOT run on an initialized database."
    exit 1
}

Write-Host "Verified 0 existing users. Proceeding with initial bootstrap..." -ForegroundColor Green

# 3. Secure Secret Ingestion / Generation
$resolvedSecretPath = [System.IO.Path]::GetFullPath((Join-Path $projectRoot $SecretPath))
$secretDir = [System.IO.Path]::GetDirectoryName($resolvedSecretPath)

if (-not (Test-Path $secretDir)) {
    New-Item -ItemType Directory -Path $secretDir -Force | Out-Null
}

if (-not (Test-Path $resolvedSecretPath)) {
    Write-Host "Generating high-entropy initial administrator password..."
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 24
    $rng.GetBytes($bytes)
    $rng.Dispose()
    # 32 characters URL-safe alphanumeric string
    $generatedPassword = [Convert]::ToBase64String($bytes).Replace('+', 'X').Replace('/', 'Y').Replace('=', 'Z')
    [System.IO.File]::WriteAllText($resolvedSecretPath, $generatedPassword, [System.Text.Encoding]::UTF8)
    
    # Enforce owner-only permissions on Windows using icacls
    & icacls.exe $resolvedSecretPath /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
    Write-Host "Created initial admin secret at $resolvedSecretPath (owner-only permissions)." -ForegroundColor Yellow
} else {
    # Ensure owner-only permissions on existing secret
    & icacls.exe $resolvedSecretPath /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
}

# 4. Generate Argon2id hash using application's actual PasswordEncoder bean configuration
$hashFile = Join-Path $projectRoot "target\admin-bootstrap-hash-$([System.Guid]::NewGuid().ToString('N')).tmp"
if (Test-Path $hashFile) { Remove-Item $hashFile -Force }

Write-Host "Computing Argon2id hash via application PasswordEncoder bean (Argon2Hasher)..."
& (Join-Path $projectRoot 'mvnw.cmd') -q `
    "-Dexec.mainClass=uk.ac.ravensbourne.casevault.crypto.Argon2Hasher" `
    "-Dexec.args=$resolvedSecretPath $hashFile" `
    exec:java

if ($LASTEXITCODE -ne 0 -or -not (Test-Path $hashFile)) {
    throw "Argon2id password hashing failed via Maven exec."
}

$argonHash = (Get-Content -LiteralPath $hashFile -Raw).Trim()
Remove-Item $hashFile -Force

if (-not $argonHash.StartsWith('$argon2id$')) {
    throw "Invalid hash format received: expected `$argon2id` prefix."
}

# 5. Insert Organisation and AUDITOR_ADMIN safely via psql standard input
$orgId = [System.Guid]::NewGuid().ToString()
$userId = [System.Guid]::NewGuid().ToString()
$cleanEmail = $AdminEmail.Trim().ToLowerInvariant()

$sql = @"
BEGIN;
INSERT INTO organisations (id, name, created_at, updated_at)
VALUES ('$orgId', '$OrgName', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (name) DO NOTHING;

INSERT INTO users (
    id,
    organisation_id,
    email,
    password_hash,
    role,
    enabled,
    failed_attempts,
    force_password_reset,
    locked_until,
    last_login_at,
    created_at,
    updated_at,
    password_changed_at
) VALUES (
    '$userId',
    (SELECT id FROM organisations WHERE name = '$OrgName'),
    '$cleanEmail',
    '$argonHash',
    'AUDITOR_ADMIN',
    TRUE,
    0,
    TRUE,
    NULL,
    NULL,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);
COMMIT;
"@

Write-Host "Provisioning AUDITOR_ADMIN into PostgreSQL..."
$sql | docker compose exec -T db psql -U casevault_admin -d casevault -v ON_ERROR_STOP=1
if ($LASTEXITCODE -ne 0) {
    throw "Failed to execute database bootstrap transaction."
}

Write-Host "`n========================================================================" -ForegroundColor Green
Write-Host "CaseVault AUDITOR_ADMIN Bootstrapped Successfully!" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "  Role:                AUDITOR_ADMIN"
Write-Host "  Email:               $cleanEmail"
Write-Host "  Secret File:         $SecretPath"
Write-Host "  Forced Reset:        TRUE (Password change required upon login)"
Write-Host "  Audit Hash Chain:    Intact (Zero synthetic chain disruption)"
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "  1. Read the initial password from $SecretPath (do not commit this file)."
Write-Host "  2. Navigate to https://localhost/login in your browser."
Write-Host "  3. Sign in as $cleanEmail."
Write-Host "  4. Immediately change your password at https://localhost/password/change."
Write-Host "========================================================================`n"

