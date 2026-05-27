# upobf E2E test runner.
#
# Usage:
#   .\tests\e2e\pack_run_verify.ps1                       # uses demo
#   .\tests\e2e\pack_run_verify.ps1 -Input some.exe       # custom input
#
# Returns exit code 0 on success, non-zero on any failure.

param(
    [string]$InputPath  = "demo\PatchInstaller.exe",
    [string]$Output     = "packed_e2e.exe",
    [int]$RuntimeSeconds = 5,
    [switch]$NoCompress,
    # Phase A1: when set, build the stub through the IR-level pass
    # plugin (`tools/obfuscator-passes/build/Release/upobf-passes.dll`).
    # The plugin must already be built; we don't auto-build it here
    # because it has its own dev-SDK prerequisites (LLVM 21 dev libs
    # under .tools/).
    [switch]$WithIRPipeline,
    # Override the seed forwarded to the IR pass plugin. Defaults to a
    # value derived from the current time so successive E2E runs
    # produce visibly different stubs (useful when manually scanning
    # for static signatures).
    [uint32]$IRPassSeed = 0
)

$ErrorActionPreference = 'Stop'

$repo = Resolve-Path (Join-Path (Split-Path -Parent $PSCommandPath) '..\..')
$inputPath  = Join-Path $repo $InputPath
$outputPath = Join-Path $repo $Output

if (-not (Test-Path -LiteralPath $inputPath)) {
    Write-Error "Input file not found: $inputPath"
    exit 2
}

# 1. Build stub
Write-Host "[e2e] Building stub..."
$stubBuildArgs = @{}
if ($WithIRPipeline) {
    $pluginPath = Join-Path $repo 'tools\obfuscator-passes\build\Release\upobf-passes.dll'
    if (-not (Test-Path -LiteralPath $pluginPath)) {
        Write-Error "IR pass plugin not found: $pluginPath. Run tools/obfuscator-passes/build.ps1 first."
        exit 3
    }
    $seed = $IRPassSeed
    if ($seed -eq 0) {
        # PowerShell's -band on Int64 returns Int64; cast through
        # uint64 to keep the low 32 bits before narrowing.
        $low = [uint64]([DateTime]::Now.Ticks) -band 0xFFFFFFFFul
        $seed = [uint32]$low
    }
    Write-Host "[e2e]   IR pipeline ENABLED (plugin=$pluginPath, seed=0x$([Convert]::ToString($seed,16)))"
    & (Join-Path $repo 'stubs\pe-x64\build.ps1') -PassPlugin $pluginPath -PassSeed $seed
} else {
    & (Join-Path $repo 'stubs\pe-x64\build.ps1')
}
if ($LASTEXITCODE -ne 0) { Write-Error "stub build failed"; exit 3 }

# 2. Build packer (release for sane perf timings)
Write-Host "[e2e] Building packer (release)..."
Push-Location $repo
try {
    & cargo build --release -q -p upobf-cli
    if ($LASTEXITCODE -ne 0) { Write-Error "packer build failed"; exit 4 }
} finally {
    Pop-Location
}

# 3. Pack
$packerArgs = @('pack', $inputPath, '-o', $outputPath)
if ($NoCompress) { $packerArgs += '--no-compress' }
Write-Host "[e2e] Packing..."
$packerExe = Join-Path $repo 'target\release\upobf.exe'
$env:RUST_LOG = 'error'
$packStart = Get-Date
& $packerExe @packerArgs
if ($LASTEXITCODE -ne 0) { Write-Error "pack failed"; exit 5 }
$packDuration = (Get-Date) - $packStart

$origSize = (Get-Item -LiteralPath $inputPath).Length
$packSize = (Get-Item -LiteralPath $outputPath).Length
$ratio = [math]::Round($packSize / $origSize * 100, 1)
Write-Host "[e2e] Pack:    $origSize -> $packSize bytes ($ratio%)  in $([math]::Round($packDuration.TotalSeconds,2))s"

# 4. Run packed binary
Write-Host "[e2e] Launching packed binary..."
$startedAt = Get-Date
$proc = Start-Process -FilePath $outputPath -PassThru -ErrorAction SilentlyContinue
if (-not $proc) {
    Write-Error "failed to launch packed binary"
    exit 6
}

Start-Sleep -Seconds $RuntimeSeconds
$elapsed = (Get-Date) - $startedAt

if ($proc.HasExited) {
    Write-Error ("packed binary exited prematurely with code 0x{0:X}" -f $proc.ExitCode)
    exit 7
}

$ws = [math]::Round($proc.WorkingSet64 / 1MB, 1)
$threads = $proc.Threads.Count
$title = $proc.MainWindowTitle
Write-Host "[e2e] Runtime: WS=${ws}MB Title='$title' Threads=$threads after $([math]::Round($elapsed.TotalSeconds,1))s"

Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Wait-Process -Id $proc.Id -Timeout 3 -ErrorAction SilentlyContinue

# 5. Polymorphism check: pack again and ensure SHA256 differs
$outputPath2 = $outputPath -replace '\.exe$', '_b.exe'
Write-Host "[e2e] Building second packed binary for polymorphism check..."
& $packerExe pack $inputPath -o $outputPath2 | Out-Null

$h1 = (Get-FileHash -Algorithm SHA256 -LiteralPath $outputPath).Hash
$h2 = (Get-FileHash -Algorithm SHA256 -LiteralPath $outputPath2).Hash
if ($h1 -eq $h2) {
    Write-Error "polymorphism check FAILED: identical SHA256 across builds ($h1)"
    exit 8
}
Write-Host "[e2e] Poly:    SHA256 A=$($h1.Substring(0,16))..."
Write-Host "[e2e]          SHA256 B=$($h2.Substring(0,16))... (differ ✓)"

Remove-Item -LiteralPath $outputPath, $outputPath2 -ErrorAction SilentlyContinue

Write-Host "[e2e] PASSED"
exit 0
