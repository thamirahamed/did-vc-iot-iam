param(
    [int]$Runs = 1,
    [int]$WarmupRuns = 0
)

$ErrorActionPreference = "Stop"
$Runner = Join-Path $PSScriptRoot "run_fabric_profile_benchmark.ps1"
$Profiles = @("current", "low_latency", "larger_batch", "light_endorsement")

foreach ($profile in $Profiles) {
    Write-Host "Running Fabric tuning profile: $profile"
    & $Runner -Profile $profile -Runs $Runs -WarmupRuns $WarmupRuns -Overwrite
}
