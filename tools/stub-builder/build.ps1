# Convenience wrapper that drives `stubs/<arch>/build.ps1` for all arches.
# M0 placeholder.

param(
    [string]$Arch = 'pe-x64',
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$repo = Resolve-Path (Join-Path (Split-Path -Parent $PSCommandPath) '..\..')
$stubScript = Join-Path $repo "stubs\$Arch\build.ps1"

if (-not (Test-Path -LiteralPath $stubScript)) {
    throw "no stub builder at $stubScript"
}

& $stubScript @PSBoundParameters
