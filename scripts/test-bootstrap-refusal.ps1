# Tests that scripts/bootstrap-admin.ps1 strictly refuses to run when users already exist in the database.
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot

Write-Host "Testing bootstrap refusal guard..." -ForegroundColor Cyan

# Check if Docker compose db is running
$isReady = docker compose exec -T db pg_isready -U casevault_admin -d casevault 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Docker database container is not running. Skipping live Docker refusal check."
    exit 0
}

# Check user count
$countRaw = docker compose exec -T db psql -U casevault_admin -d casevault -t -A -c "SELECT COUNT(*) FROM users;" 2>&1
$userCount = [int]($countRaw.ToString().Trim())

if ($userCount -eq 0) {
    Write-Host "Database is currently uninitialized (0 users). Cannot test refusal on empty DB."
    exit 0
}

Write-Host "Database currently has $userCount user(s). Running bootstrap-admin.ps1 to verify refusal..."

$output = & powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\bootstrap-admin.ps1" 2>&1
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
    Write-Error "TEST FAILED: bootstrap-admin.ps1 should have exited with code 1, but exited with 0!"
    exit 1
}

$outputString = $output -join "`n"
if ($outputString -match "SECURITY REFUSAL: Database already contains") {
    Write-Host "SUCCESS: bootstrap-admin.ps1 refused to execute and reported SECURITY REFUSAL as expected." -ForegroundColor Green
    exit 0
} else {
    Write-Error "TEST FAILED: Expected 'SECURITY REFUSAL' message, got: $outputString"
    exit 1
}

