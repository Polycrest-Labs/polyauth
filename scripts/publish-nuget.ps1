param(
    [string] $PackagePath = "artifacts/packages/PolyAuth.0.1.0.nupkg",
    [string] $Source = "https://api.nuget.org/v3/index.json"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($env:NUGET_API_KEY)) {
    throw "Set NUGET_API_KEY to a NuGet.org API key with Push scope before publishing."
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$package = Resolve-Path (Join-Path $repoRoot $PackagePath)

dotnet nuget push $package `
    --source $Source `
    --api-key $env:NUGET_API_KEY `
    --skip-duplicate
