# upobf-passes build driver.
#
# Configures CMake against the in-tree LLVM 21.1.0 dev SDK and builds
# `upobf-passes.dll` in Release mode. Output lands in
# tools/obfuscator-passes/build/Release/upobf-passes.dll, which is
# what the stub builder consumes.
#
# Prerequisites:
#   - .tools/clang+llvm-21.1.0-x86_64-pc-windows-msvc/ extracted
#     (download script in build.ps1's bootstrap section)
#   - Visual Studio 2022 / 2026 Build Tools or Community installed
#     (provides cl.exe + Windows SDK + linker that CMake's MSVC
#     generator expects)
#
# Defaults:
#   - Generator: "Ninja Multi-Config" if ninja.exe is on PATH, else
#     fall back to the Visual Studio generator.
#   - Build type: Release.
#
# Pass `-Clean` to wipe the build directory before configuring.

param(
    [switch]$Clean,
    [switch]$Verbose
)

$ErrorActionPreference = 'Stop'

$root      = Split-Path -Parent $PSCommandPath
$repoRoot  = Resolve-Path -LiteralPath (Join-Path $root '..\..') | Select-Object -ExpandProperty Path
$llvmRoot  = Join-Path $repoRoot '.tools\clang+llvm-21.1.0-x86_64-pc-windows-msvc'
$llvmCMake = Join-Path $llvmRoot 'lib\cmake\llvm'
$buildDir  = Join-Path $root 'build'

if (-not (Test-Path -LiteralPath $llvmCMake)) {
    Write-Host "[passes-build] LLVM dev SDK not found at:"
    Write-Host "  $llvmRoot"
    Write-Host "Run the bootstrap step first (see README)."
    exit 1
}

if ($Clean -and (Test-Path -LiteralPath $buildDir)) {
    Remove-Item -LiteralPath $buildDir -Recurse -Force
}

if (-not (Test-Path -LiteralPath $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

# Locate cmake. Prefer the one bundled with VS 2022/2026 because it's
# already wired up to the toolchain we want to use.
$cmake = $null
$vsRoot = $null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path -LiteralPath $vswhere) {
    $vsRoot = & $vswhere -latest -property installationPath 2>$null
    if ($vsRoot) {
        $candidate = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
        if (Test-Path -LiteralPath $candidate) {
            $cmake = $candidate
        }
    }
}
if (-not $cmake) {
    $cmake = (Get-Command cmake -ErrorAction SilentlyContinue).Source
}
if (-not $cmake) {
    Write-Host "[passes-build] cmake not found. Install VS Build Tools or add cmake to PATH."
    exit 1
}

# Locate ninja the same way.
$ninja = $null
if ($vsRoot) {
    $candidate = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
    if (Test-Path -LiteralPath $candidate) {
        $ninja = $candidate
    }
}

# Activate the MSVC build environment (vcvars64) so cmake picks up
# cl.exe + MS linker. The LLVM 21 dev libs in `.tools/...` are built
# with MSVC; mixing in clang-cl here works but mixing in MinGW would
# cause ABI mismatches that surface as obscure linker errors. We
# therefore prefer cl.exe explicitly.
if ($vsRoot) {
    $vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
    if (Test-Path -LiteralPath $vcvars) {
        # Note: vcvars64.bat does its own banner output; piping it to
        # `>nul` truncates the very env var dump we depend on. We
        # instead let it print and filter the captured lines for the
        # `KEY=VALUE` shape via the regex below.
        $envDump = & cmd.exe /c "`"$vcvars`" && set" 2>&1
        $appliedCount = 0
        foreach ($line in $envDump) {
            if ($line -match '^([^=]+)=(.*)$') {
                $name = $Matches[1]; $value = $Matches[2]
                # Avoid clobbering a few PowerShell-specific vars.
                if ($name -in @('PATH','INCLUDE','LIB','LIBPATH','VCINSTALLDIR','VCToolsInstallDir','WindowsSdkDir','UCRTVersion','VSCMD_VER','WindowsLibPath','WindowsSdkBinPath','WindowsSdkVerBinPath','UniversalCRTSdkDir')) {
                    Set-Item -Path "Env:$name" -Value $value
                    $appliedCount++
                }
            }
        }
        if ($Verbose) {
            Write-Host "[passes-build] vcvars64 applied: $appliedCount vars"
            Write-Host "[passes-build] INCLUDE length: $(if($env:INCLUDE){$env:INCLUDE.Length}else{0})"
        }
    }
}

# Pick a generator. Ninja Multi-Config is the most predictable for our
# needs and matches what LLVM's own buildbots use.
$generator = 'Ninja Multi-Config'
if (-not $ninja) {
    $generator = 'Visual Studio 17 2022'
}

$configureArgs = @(
    '-S', $root,
    '-B', $buildDir,
    '-G', $generator,
    "-DLLVM_DIR=$llvmCMake",
    '-DCMAKE_BUILD_TYPE=Release',
    '-DCMAKE_C_COMPILER=cl',
    '-DCMAKE_CXX_COMPILER=cl'
)
if ($ninja) {
    $configureArgs += "-DCMAKE_MAKE_PROGRAM=$ninja"
}
# When using the VS generator we want x64.
if ($generator -like 'Visual Studio*') {
    $configureArgs += @('-A', 'x64')
}

Write-Host "[passes-build] cmake $($configureArgs -join ' ')"
& $cmake @configureArgs
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }

Write-Host "[passes-build] cmake --build $buildDir --config Release"
& $cmake --build $buildDir --config Release
if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }

# Where the DLL ends up depends on the generator. Try both.
$candidates = @(
    (Join-Path $buildDir 'Release\upobf-passes.dll'),
    (Join-Path $buildDir 'upobf-passes.dll'),
    (Join-Path $buildDir 'Debug\upobf-passes.dll')
)
$dll = $null
foreach ($c in $candidates) {
    if (Test-Path -LiteralPath $c) { $dll = $c; break }
}
if (-not $dll) {
    Write-Host "[passes-build] FAILED: upobf-passes.dll not produced"
    Write-Host "Build dir contents:"
    Get-ChildItem -LiteralPath $buildDir -Recurse -Filter "*.dll" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.FullName)" }
    exit 1
}

$bytes = (Get-Item -LiteralPath $dll).Length
Write-Host ""
Write-Host ("[passes-build] produced {0} ({1} bytes)" -f $dll, $bytes)
Write-Host "[passes-build] OK"
