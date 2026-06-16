param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$FabricVersion = if ($env:FABRIC_VERSION) { $env:FABRIC_VERSION } else { "2.5.15" }
$FabricCaVersion = if ($env:FABRIC_CA_VERSION) { $env:FABRIC_CA_VERSION } else { "1.5.15" }
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$ThirdParty = Join-Path $RepoRoot "third_party"
$FabricSamples = Join-Path $ThirdParty "fabric-samples"

foreach ($commandName in @("git", "curl.exe", "bash")) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "$commandName is required to install Fabric Samples."
    }
}

if ((Test-Path $FabricSamples) -and -not $Force) {
    Write-Host "Fabric Samples already exists: $FabricSamples"
    Write-Host "Use -Force to run the installer again."
} else {
    New-Item -ItemType Directory -Force -Path $ThirdParty | Out-Null
    Push-Location $ThirdParty
    try {
        curl.exe -sSL https://bit.ly/2ysbOFE -o install-fabric.sh
        bash install-fabric.sh $FabricVersion $FabricCaVersion
    } finally {
        Pop-Location
    }
}

$FabricSamplesValue = ($FabricSamples -replace "\\", "/")
$OrgsValue = ((Join-Path $FabricSamples "test-network/organizations") -replace "\\", "/")

Write-Host ""
Write-Host "Fabric Samples path:"
Write-Host "  FABRIC_SAMPLES_PATH=$FabricSamplesValue"
Write-Host "  FABRIC_SAMPLES_ORGS_HOST_PATH=$OrgsValue"
Write-Host ""
Write-Host "Next:"
Write-Host "  Copy .env.project.example to .env.project."
Write-Host "  Set those two values in .env.project, using absolute paths with forward slashes on Windows."
