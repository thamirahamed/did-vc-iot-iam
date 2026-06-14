param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("current", "low_latency", "larger_batch", "light_endorsement")]
    [string]$Profile,

    [int]$Runs = 1,
    [int]$WarmupRuns = 0,
    [switch]$Overwrite
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$ResultDir = Join-Path $RepoRoot "data\dashboard\fabric-tuning-results"
$RawDir = Join-Path $ResultDir "$Profile-raw"
$ResultPath = Join-Path $ResultDir "$Profile.json"

$Profiles = @{
    current = @{
        label = "Original Fabric baseline"
        description = "Saved comparison profile using the original Fabric test-network batch settings"
        batch_timeout = "2s"
        block_size = "max_message_count=10, preferred_max_bytes=512 KB, absolute_max_bytes=99 MB"
        endorsement_policy = "current"
        env = @{
            FABRIC_BATCH_TIMEOUT = "2s"
            FABRIC_MAX_MESSAGE_COUNT = "10"
            FABRIC_ABSOLUTE_MAX_BYTES = "99 MB"
            FABRIC_PREFERRED_MAX_BYTES = "512 KB"
        }
    }
    low_latency = @{
        label = "Fast block commit"
        description = "Smaller blocks and shorter batch timeout for lower latency IAM writes"
        batch_timeout = "500ms"
        block_size = "max_message_count=5, preferred_max_bytes=512 KB, absolute_max_bytes=10 MB"
        endorsement_policy = "current"
        env = @{
            FABRIC_BATCH_TIMEOUT = "500ms"
            FABRIC_MAX_MESSAGE_COUNT = "5"
            FABRIC_ABSOLUTE_MAX_BYTES = "10 MB"
            FABRIC_PREFERRED_MAX_BYTES = "512 KB"
        }
    }
    larger_batch = @{
        label = "Main tuned Fabric settings"
        description = "Main Fabric configuration used by the demo pipeline and benchmark API flows"
        batch_timeout = "2s"
        block_size = "max_message_count=50, preferred_max_bytes=2 MB, absolute_max_bytes=10 MB"
        endorsement_policy = "current"
        env = @{
            FABRIC_BATCH_TIMEOUT = "2s"
            FABRIC_MAX_MESSAGE_COUNT = "50"
            FABRIC_ABSOLUTE_MAX_BYTES = "10 MB"
            FABRIC_PREFERRED_MAX_BYTES = "2 MB"
        }
    }
    light_endorsement = @{
        label = "Light endorsement"
        description = "Lighter endorsement policy if chaincode/config supports it"
        batch_timeout = "current"
        block_size = "current"
        endorsement_policy = "not_applicable"
        env = @{}
    }
}

function Load-ProjectEnv {
    $envPath = Join-Path $RepoRoot ".env.project"
    if (-not (Test-Path -LiteralPath $envPath)) {
        throw ".env.project was not found at $envPath"
    }
    foreach ($line in Get-Content -LiteralPath $envPath) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#") -or $trimmed -notmatch "^[A-Za-z_][A-Za-z0-9_]*=") {
            continue
        }
        $key, $value = $trimmed.Split("=", 2)
        $value = $value.Trim().Trim('"').Trim("'")
        Set-Item -Path "Env:$key" -Value $value
    }
}

function Write-ProfileResult {
    param([hashtable]$Result)
    New-Item -ItemType Directory -Force -Path $ResultDir | Out-Null
    $Result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    Write-Host "Saved Fabric tuning result: $ResultPath"
}

function Wait-HttpOk {
    param([string]$Url, [string]$Name)
    for ($i = 0; $i -lt 60; $i++) {
        try {
            Invoke-RestMethod -Uri $Url -TimeoutSec 5 | Out-Null
            Write-Host "$Name healthy"
            return
        } catch {
            Start-Sleep -Seconds 2
        }
    }
    throw "$Name did not become healthy at $Url"
}

function Latest-File {
    param([string]$Pattern)
    Get-ChildItem -LiteralPath $RawDir -Filter $Pattern | Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function MetricValue {
    param($Rows, [string]$Metric, [string]$Column = "mean")
    $row = $Rows | Where-Object { $_.metric -eq $Metric } | Select-Object -First 1
    if ($null -eq $row -or [string]::IsNullOrWhiteSpace($row.$Column)) {
        return $null
    }
    return [double]$row.$Column
}

function OperationAverage {
    param($Rows, [string[]]$Operations, [string]$Column = "mean")
    $values = @()
    foreach ($operation in $Operations) {
        $row = $Rows | Where-Object { $_.operation -eq $operation } | Select-Object -First 1
        if ($null -ne $row -and -not [string]::IsNullOrWhiteSpace($row.$Column)) {
            $values += [double]$row.$Column
        }
    }
    if ($values.Count -eq 0) {
        return $null
    }
    return ($values | Measure-Object -Average).Average
}

$profileConfig = $Profiles[$Profile]
$startedAt = (Get-Date).ToUniversalTime().ToString("o")

if ($Profile -eq "light_endorsement") {
    Write-ProfileResult @{
        profile_id = $Profile
        label = $profileConfig.label
        status = "not_supported"
        reason = "Endorsement policy cannot be changed safely after chaincode deployment in this runner"
        block_size = $profileConfig.block_size
        batch_timeout = $profileConfig.batch_timeout
        endorsement_policy = $profileConfig.endorsement_policy
        started_at = $startedAt
        finished_at = (Get-Date).ToUniversalTime().ToString("o")
    }
    exit 0
}

try {
    Load-ProjectEnv
    foreach ($key in $profileConfig.env.Keys) {
        Set-Item -Path "Env:$key" -Value $profileConfig.env[$key]
    }

    New-Item -ItemType Directory -Force -Path $RawDir | Out-Null

    docker compose --env-file .env.project `
        -f docker-compose.yml `
        -f docker-compose.fabric.yml `
        -f docker-compose.perf.yml `
        -f docker-compose.dashboard.yml `
        up -d --build

    Wait-HttpOk "http://localhost:8000/health" "issuer"
    Wait-HttpOk "http://localhost:8001/health" "verifier"
    Wait-HttpOk "http://localhost:8010/health" "fabric-adapter"

    $env:BENCHMARK_RUNS = [string]$Runs
    $env:BENCHMARK_WARMUP_RUNS = [string]$WarmupRuns
    $env:BENCHMARK_OUTPUT_DIR = $RawDir
    $env:FABRIC_OPS_RUNS = [string]$Runs
    $env:FABRIC_OPS_WARMUP_RUNS = [string]$WarmupRuns
    $env:FABRIC_OPS_OUTPUT_DIR = $RawDir
    $env:BENCHMARK_PROFILE = "fabric_accumulator_perf"
    $env:BENCHMARK_LABEL = "fabric_tuning_$Profile"
    $env:FABRIC_OPS_LABEL = "fabric_tuning_$Profile"
    $env:REVOCATION_MODE = "accumulator"
    $env:AUDIT_MODE = "async"
    $env:FABRIC_CLIENT_MODE = "adapter"
    $env:FABRIC_ENABLED = "true"
    $env:ISSUER_URL = "http://localhost:8000"
    $env:VERIFIER_URL = "http://localhost:8001"
    $env:FABRIC_ADAPTER_URL = "http://localhost:8010"
    $env:HTTP_TIMEOUT_SECONDS = "60"
    $env:HTTP_RETRY_ATTEMPTS = "5"
    $env:HTTP_RETRY_SLEEP_SECONDS = "1"

    Push-Location $RepoRoot
    try {
        python scripts\benchmark_pipeline.py
        python scripts\benchmark_fabric_ops.py
        $env:FABRIC_OPS_MODE = "fabric_write_pressure"
        $env:FABRIC_OPS_LABEL = "fabric_tuning_${Profile}_write_pressure"
        $env:FABRIC_OPS_RUNS = "1"
        $env:FABRIC_OPS_WARMUP_RUNS = "0"
        python scripts\benchmark_fabric_ops.py
        Remove-Item Env:FABRIC_OPS_MODE -ErrorAction SilentlyContinue
    } finally {
        Pop-Location
    }

    $pipelineSummary = Latest-File "benchmark_summary_*.csv"
    $fabricOpsSummary = Latest-File "fabric_ops_summary_*.csv"
    $writePressureSummary = Latest-File "fabric_write_pressure_*.json"
    if ($null -eq $pipelineSummary) {
        throw "Pipeline benchmark summary was not created"
    }
    if ($null -eq $fabricOpsSummary) {
        throw "Fabric ops benchmark summary was not created"
    }
    if ($null -eq $writePressureSummary) {
        throw "Fabric write pressure summary was not created"
    }

    $pipelineRows = Import-Csv -LiteralPath $pipelineSummary.FullName
    $opsRows = Import-Csv -LiteralPath $fabricOpsSummary.FullName
    $writePressure = Get-Content -LiteralPath $writePressureSummary.FullName -Raw | ConvertFrom-Json
    $readOps = @("ping", "read_did", "read_credential_status", "get_accumulator_state", "list_audit_events")
    $writeOps = @("register_did", "register_credential_status", "revoke_credential", "put_accumulator_state", "add_audit_event")
    $fullLifecycle = MetricValue $pipelineRows "full_iteration_ms"
    $tps = $null
    if ($null -ne $fullLifecycle -and $fullLifecycle -gt 0) {
        $tps = [math]::Round(1000.0 / $fullLifecycle, 3)
    }
    $ledgerReadMs = OperationAverage $opsRows $readOps "mean"
    $ledgerWriteMs = OperationAverage $opsRows $writeOps "mean"
    $readTps = $null
    if ($null -ne $ledgerReadMs -and $ledgerReadMs -gt 0) {
        $readTps = [math]::Round(1000.0 / $ledgerReadMs, 3)
    }
    $writeTps = $null
    if ($null -ne $ledgerWriteMs -and $ledgerWriteMs -gt 0) {
        $writeTps = [math]::Round(1000.0 / $ledgerWriteMs, 3)
    }

    Write-ProfileResult @{
        profile_id = $Profile
        label = $profileConfig.label
        status = "completed"
        reason = $null
        block_size = $profileConfig.block_size
        batch_timeout = $profileConfig.batch_timeout
        endorsement_policy = $profileConfig.endorsement_policy
        full_lifecycle_ms = $fullLifecycle
        auth_allow_ms = MetricValue $pipelineRows "auth_allow_ms"
        revocation_ms = MetricValue $pipelineRows "revoke_capability_ms"
        proof_refresh_ms = MetricValue $pipelineRows "proof_refresh_ms"
        ledger_read_ms = $ledgerReadMs
        ledger_write_ms = $ledgerWriteMs
        read_p50_ms = OperationAverage $opsRows $readOps "p50"
        read_p95_ms = OperationAverage $opsRows $readOps "p95"
        write_p50_ms = OperationAverage $opsRows $writeOps "p50"
        write_p95_ms = OperationAverage $opsRows $writeOps "p95"
        read_tps = $readTps
        write_tps = $writeTps
        tps = $tps
        cpu = $null
        ram = $null
        started_at = $startedAt
        finished_at = (Get-Date).ToUniversalTime().ToString("o")
        pipeline_summary_path = $pipelineSummary.FullName
        fabric_ops_summary_path = $fabricOpsSummary.FullName
        write_pressure_summary_path = $writePressureSummary.FullName
        write_pressure = $writePressure
    }
} catch {
    Write-ProfileResult @{
        profile_id = $Profile
        label = $profileConfig.label
        status = "failed"
        reason = ($_.Exception.Message -replace "\s+", " ").Substring(0, [Math]::Min(240, ($_.Exception.Message -replace "\s+", " ").Length))
        block_size = $profileConfig.block_size
        batch_timeout = $profileConfig.batch_timeout
        endorsement_policy = $profileConfig.endorsement_policy
        started_at = $startedAt
        finished_at = (Get-Date).ToUniversalTime().ToString("o")
    }
    throw
}
