# CaseVault

CaseVault is a secure, server-rendered case-management and evidence-sharing platform for the fictional Northbridge Cyber Response consultancy.

# project install and run process
# Git install:
winget install --id Git.Git --exact --accept-package-agreements --accept-source-agreements

# Java 21 install:
winget install --id EclipseAdoptium.Temurin.21.JDK --exact --accept-package-agreements --accept-source-agreements

# Windows App Installer / winget update or install:
winget install --id Microsoft.AppInstaller --exact --accept-package-agreements --accept-source-agreements

# Check all installation:
git --version
java -version
winget --version

# Run project:
Set-ExecutionPolicy -Scope Process Bypass

.\scripts\start-dev.ps1

## Prerequisites

- Java 21 (LTS)
- PostgreSQL (for local application execution)

## Build and run

Run `./mvnw -B verify` to build and test. Local run and deployment instructions will be added in a later phase.

### Windows quick start

Run the following from PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\start-dev.ps1
```

The script checks for Java 21, attempts installation through `winget` if needed, downloads Maven/dependencies through the Maven Wrapper, starts a temporary H2 development database, and launches the app. Open `http://localhost:8080/login` and use the synthetic `DEV ONLY credentials` printed in the terminal.

## Security notice

This academic project accepts only synthetic data and inert evidence files. Never use real client data, credentials, malware, or unauthorised targets.
