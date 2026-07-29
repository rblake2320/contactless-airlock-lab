$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$secretPath = Join-Path $env:USERPROFILE ".airlock.env"
$containerName = "airlock-postgres-test"

if (-not (Test-Path -LiteralPath $secretPath -PathType Leaf)) {
    throw "Approved Airlock secret reference is missing: $secretPath"
}

$containerState = docker inspect $containerName --format "{{.State.Running}}" 2>$null
if ($LASTEXITCODE -ne 0 -or $containerState -ne "true") {
    throw "Dedicated PostgreSQL container '$containerName' is not running."
}

docker exec $containerName pg_isready -U airlock -d airlock *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Dedicated PostgreSQL container '$containerName' is not ready."
}

$connectionLine = Get-Content -LiteralPath $secretPath |
    Where-Object { $_ -match "^AIRLOCK_POSTGRES_URL=" } |
    Select-Object -First 1
if (-not $connectionLine) {
    throw "AIRLOCK_POSTGRES_URL is missing from the approved secret reference."
}

$priorValue = $env:AIRLOCK_POSTGRES_URL
try {
    $env:AIRLOCK_POSTGRES_URL =
        $connectionLine.Substring("AIRLOCK_POSTGRES_URL=".Length)
    Push-Location -LiteralPath $repoRoot
    try {
        & npm run test:postgres
        if ($LASTEXITCODE -ne 0) {
            throw "Real PostgreSQL integration test failed with exit $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    if ($null -eq $priorValue) {
        Remove-Item Env:AIRLOCK_POSTGRES_URL -ErrorAction SilentlyContinue
    }
    else {
        $env:AIRLOCK_POSTGRES_URL = $priorValue
    }
}
