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
    [switch]$Verbose
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

$produced = @()

foreach ($src in $sources) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($src.Name)
    $out  = Join-Path $buildDir ($base + '.obj')

    $perFile = @()
    if ($base -ieq 'lzma_dec') {
        $perFile = $lzmaExtraFlags
    }

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
}

Write-Host ""
Write-Host "[stub-build] produced $($produced.Count) object(s):"
foreach ($p in $produced) {
    $bytes = (Get-Item -LiteralPath $p).Length
    Write-Host ("  {0,-32} {1,8} bytes" -f ([System.IO.Path]::GetFileName($p)), $bytes)
}
