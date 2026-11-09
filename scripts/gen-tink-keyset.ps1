param(
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\secrets\dev.tink.keyset')
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)

if (Test-Path -LiteralPath $resolvedOutput) {
    throw "Refusing to overwrite an existing keyset: $resolvedOutput"
}

& (Join-Path $projectRoot 'mvnw.cmd') -q -DskipTests compile
& (Join-Path $projectRoot 'mvnw.cmd') -q dependency:build-classpath "-Dmdep.outputFile=$projectRoot\target\tink-classpath.txt"

$dependencyClasspath = (Get-Content -LiteralPath (Join-Path $projectRoot 'target\tink-classpath.txt') -Raw).Trim()
$classpath = (Join-Path $projectRoot 'target\classes') + ';' + $dependencyClasspath
& java -cp $classpath uk.ac.ravensbourne.casevault.crypto.DevTinkKeysetGenerator $resolvedOutput

Write-Host "Created development Tink keyset at $resolvedOutput"
Write-Host 'Set TINK_KEYSET_PATH to this path before starting the dev profile. Never commit or share this file.'
