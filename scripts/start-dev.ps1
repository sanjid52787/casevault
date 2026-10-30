# Starts CaseVault locally with an ephemeral H2 database and synthetic dev users.
# Maven Wrapper downloads Maven and all Java dependencies declared in pom.xml.
$ErrorActionPreference = 'Stop'

function Get-Java21Home {
    if ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME 'bin\java.exe'))) {
        return $env:JAVA_HOME
    }
    $candidate = Get-ChildItem 'C:\Program Files\Eclipse Adoptium' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'jdk-21*' } | Select-Object -First 1
    if ($candidate) { return $candidate.FullName }
    return $null
}

$javaHome = Get-Java21Home
if (-not $javaHome) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw 'Java 21 is required. Install Eclipse Temurin JDK 21, then run this script again.'
    }
    Write-Host 'Installing Eclipse Temurin JDK 21 via winget...'
    winget install --id EclipseAdoptium.Temurin.21.JDK --exact --accept-package-agreements --accept-source-agreements
    $javaHome = Get-Java21Home
    if (-not $javaHome) {
        throw 'Java was installed but is not available in this PowerShell session. Close/open PowerShell, then run this script again.'
    }
}

$env:JAVA_HOME = $javaHome
$env:Path = "$javaHome\bin;$env:Path"
$env:SPRING_PROFILES_ACTIVE = 'dev'
$env:MAVEN_OPTS = '-Dspring-boot.run.useTestClasspath=true'
$env:CASEVAULT_DB_URL = 'jdbc:h2:mem:casevaultdev;MODE=PostgreSQL;DB_CLOSE_DELAY=-1'
$env:CASEVAULT_DB_USERNAME = 'sa'
$env:CASEVAULT_DB_PASSWORD = ''

# Local, process-only audit key. It is never written to a repository file.
$random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 32
$random.GetBytes($bytes)
$random.Dispose()
$env:AUDIT_HMAC_KEY = [Convert]::ToBase64String($bytes)

Write-Host 'Starting CaseVault at http://localhost:8080/login'
Write-Host 'Copy the DEV ONLY email/password pair printed after startup.'
& "$PSScriptRoot\..\mvnw.cmd" spring-boot:run
