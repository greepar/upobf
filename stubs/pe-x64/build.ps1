# upobf PE x64 stub builder
#
# Compiles each source under src/ separately into a relocatable COFF
# object. The Rust-side stub linker (`upobf-core::stub_link`) consumes
# all .obj files, resolves cross-object references, and splices them
# into the packed image.
#
# We deliberately avoid producing a single combined .obj here:
# `clang -c` with multiple inputs already requires one output per
# input, and `lld-link` cannot emit a relocatable object in this
# milestone. Stub_link does the cross-object linking itself.

param(
    [switch]$Clean,
    [switch]$Verbose,
    # Optional path to upobf-passes.dll (the IR-level obfuscation
    # plugin built by tools/obfuscator-passes/build.ps1). When set,
    # every C TU other than lzma_dec.c is processed through a
    # `clang -emit-llvm` -> `opt --load-pass-plugin` -> `llc -filetype=obj`
    # pipeline. When empty, the legacy single-step `clang -c` path is
    # used; this keeps the build green on machines without the LLVM
    # dev SDK and makes Phase A1 strictly opt-in.
    [string]$PassPlugin = '',
    # Master seed for the IR passes. Each TU mixes this seed with its
    # own filename, so the same value still gives reproducible output
    # while different files diverge from each other.
    [uint32]$PassSeed = 0
)

$ErrorActionPreference = 'Stop'

$root     = Split-Path -Parent $PSCommandPath
$srcDir   = Join-Path $root 'src'
$incDir   = Join-Path $root 'include'
$buildDir = Join-Path $root 'build'

if ($Clean -and (Test-Path -LiteralPath $buildDir)) {
    Remove-Item -LiteralPath $buildDir -Recurse -Force
}

if (-not (Test-Path -LiteralPath $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

if (-not (Test-Path -LiteralPath $srcDir)) {
    Write-Host "stub src dir missing: $srcDir"
    exit 1
}

$sources = @(Get-ChildItem -LiteralPath $srcDir -Recurse -Include *.c, *.S -File)

if ($sources.Count -eq 0) {
    Write-Host "no stub sources under $srcDir"
    exit 1
}

$flags = @(
    '-target', 'x86_64-pc-windows-msvc',
    '-ffreestanding',
    '-nostdlib',
    '-fno-stack-protector',
    '-fno-asynchronous-unwind-tables',
    '-fno-builtin',
    '-fno-exceptions',
    # Note: -fPIC is unsupported on x86_64-pc-windows-msvc; PE code is
    # always relocatable via the .reloc directory.
    # Note: -flto would emit LLVM bitcode for .c inputs; the Rust-side
    # stub_link expects native COFF, so LTO is left off here.
    '-Os',
    "-I$incDir"
)

# LzmaDec.c is vendored from the public-domain LZMA SDK; it triggers a
# handful of conformance warnings that are not actionable for us. Silence
# them only for that one translation unit.
$lzmaExtraFlags = @(
    '-Wno-everything'
)

# IR-level obfuscation pipeline (Phase A1). Activated when -PassPlugin
# is supplied and the path resolves. We keep the prebuilt LLVM dev SDK
# tooling alongside the plugin so plugin and `opt` / `llc` versions
# agree.
$useIRPipeline = $false
$opt = $null
$llc = $null
if ($PassPlugin -and (Test-Path -LiteralPath $PassPlugin)) {
    $devSdk = Resolve-Path -LiteralPath (Join-Path $root '..\..\.tools\clang+llvm-21.1.0-x86_64-pc-windows-msvc') -ErrorAction SilentlyContinue
    if ($devSdk) {
        $optCandidate = Join-Path $devSdk.Path 'bin\opt.exe'
        $llcCandidate = Join-Path $devSdk.Path 'bin\llc.exe'
        if ((Test-Path -LiteralPath $optCandidate) -and (Test-Path -LiteralPath $llcCandidate)) {
            $opt = $optCandidate
            $llc = $llcCandidate
            $useIRPipeline = $true
        }
    }
    if (-not $useIRPipeline) {
        Write-Host "[stub-build] WARN: -PassPlugin set but opt.exe/llc.exe not found alongside it; falling back to single-step clang."
    }
}

# Files that bypass the IR pipeline. lzma_dec.c is vendored and big;
# transforming it doubles its size for negligible RE benefit. The
# files listed here go through the legacy `clang -c` step regardless
# of -PassPlugin.
$bypassIRPipeline = @('lzma_dec')

if ($useIRPipeline -and $Verbose) {
    Write-Host "[stub-build] IR pipeline ENABLED"
    Write-Host "[stub-build]   plugin: $PassPlugin"
    Write-Host "[stub-build]   opt:    $opt"
    Write-Host "[stub-build]   llc:    $llc"
    Write-Host "[stub-build]   seed:   $PassSeed"
} elseif ($Verbose) {
    Write-Host "[stub-build] IR pipeline disabled (legacy clang -c path)"
}

$produced = @()

foreach ($src in $sources) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($src.Name)
    $out  = Join-Path $buildDir ($base + '.obj')

    $perFile = @()
    if ($base -ieq 'lzma_dec') {
        $perFile = $lzmaExtraFlags
    }

    $isAsm = $src.Extension -ieq '.S'
    $bypass = ($bypassIRPipeline -contains $base) -or $isAsm
    $useIRForThis = $useIRPipeline -and (-not $bypass)

    if (-not $useIRForThis) {
        # Legacy single-step path: clang -c source -> obj.
        $cmd = @('-c', $src.FullName, '-o', $out) + $flags + $perFile
        if ($Verbose) {
            Write-Host "[stub-build] clang $($cmd -join ' ')"
        } else {
            Write-Host "[stub-build] compile $($src.Name) -> $([System.IO.Path]::GetFileName($out))"
        }
        & clang @cmd
        if ($LASTEXITCODE -ne 0) {
            throw "stub clang build failed for $($src.FullName) (exit $LASTEXITCODE)"
        }
        $produced += $out
        continue
    }

    # IR pipeline: clang -emit-llvm -c -> *.bc (optimised at -Os).
    # Then opt with the upobf passes -> *.opt.bc. Then llc -filetype=obj
    # at the same -O level so codegen matches the legacy path's
    # quality.
    $bc    = Join-Path $buildDir ($base + '.bc')
    $optBc = Join-Path $buildDir ($base + '.opt.bc')

    # Mix the master seed with a per-file salt so each TU gets a
    # different PRNG stream even with the same -PassSeed.
    # Hash seed: sum of ASCII codes (cheap, deterministic, no crypto
    # quality needed).
    $perFileSalt = 0
    foreach ($ch in [char[]]$base) { $perFileSalt = ($perFileSalt + [int]$ch) -band 0xFFFF }
    $mbaSeed = [uint32]($PassSeed -bxor ($perFileSalt + 0xC0FFEE))
    $bcfSeed = [uint32]($PassSeed -bxor ($perFileSalt + 0xBADC0DE))

    $cmd1 = @('-c', '-emit-llvm', $src.FullName, '-o', $bc) + $flags + $perFile
    if ($Verbose) {
        Write-Host "[stub-build] clang -emit-llvm $($src.Name) -> $([System.IO.Path]::GetFileName($bc))"
    } else {
        Write-Host "[stub-build] llvm-ir $($src.Name) -> $([System.IO.Path]::GetFileName($bc))"
    }
    & clang @cmd1
    if ($LASTEXITCODE -ne 0) {
        throw "stub clang -emit-llvm failed for $($src.FullName) (exit $LASTEXITCODE)"
    }

    $passes = "upobf-bcf<seed=$bcfSeed>,upobf-mba<seed=$mbaSeed>"
    $cmd2 = @('--load-pass-plugin', $PassPlugin, '--passes', $passes, $bc, '-o', $optBc)
    if ($Verbose) {
        Write-Host "[stub-build] opt $($cmd2 -join ' ')"
    } else {
        Write-Host "[stub-build] obfusc $([System.IO.Path]::GetFileName($bc)) -> $([System.IO.Path]::GetFileName($optBc))"
    }
    & $opt @cmd2
    # opt.exe in the LLVM 21.1.0 prebuilt has a known Windows-only
    # shutdown-time crash when a plugin DLL is loaded: the bitcode
    # output is written and flushed correctly, but `opt`'s static
    # destructor chain trips an STATUS_ILLEGAL_INSTRUCTION (0xC000001D)
    # while tearing down a global registry. The exit code therefore
    # cannot be trusted as a signal of pass success. We instead
    # validate by checking the output file exists and is non-empty.
    if (-not (Test-Path -LiteralPath $optBc) -or (Get-Item -LiteralPath $optBc).Length -eq 0) {
        throw "stub opt pass failed for $($src.FullName) (no output bitcode produced; exit $LASTEXITCODE)"
    }
    if ($LASTEXITCODE -ne 0 -and $Verbose) {
        Write-Host "[stub-build] (note) opt returned $LASTEXITCODE on shutdown; bitcode written OK."
    }

    $cmd3 = @('-filetype=obj', '-O2', $optBc, '-o', $out)
    if ($Verbose) {
        Write-Host "[stub-build] llc $($cmd3 -join ' ')"
    } else {
        Write-Host "[stub-build] codegen $([System.IO.Path]::GetFileName($optBc)) -> $([System.IO.Path]::GetFileName($out))"
    }
    & $llc @cmd3
    if ($LASTEXITCODE -ne 0) {
        throw "stub llc codegen failed for $($src.FullName) (exit $LASTEXITCODE)"
    }

    $produced += $out
}

Write-Host ""
Write-Host "[stub-build] produced $($produced.Count) object(s):"
foreach ($p in $produced) {
    $bytes = (Get-Item -LiteralPath $p).Length
    Write-Host ("  {0,-32} {1,8} bytes" -f ([System.IO.Path]::GetFileName($p)), $bytes)
}
