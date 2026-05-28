#!/usr/bin/env bash
# upobf-passes Linux build driver.
#
# Configures CMake against the system LLVM-21 dev SDK
# (apt install llvm-21-dev) and builds `upobf-passes.so` in Release mode.
# Output lands in tools/obfuscator-passes/build/upobf-passes.so, which
# is what the stub builder consumes.
#
# Prerequisites:
#   sudo apt install llvm-21-dev cmake ninja-build clang-21
#
# Usage:
#   ./tools/obfuscator-passes/build.sh           # configure + build
#   ./tools/obfuscator-passes/build.sh --clean   # wipe build/ first
#
# Defaults:
#   - Generator: Ninja
#   - Build type: Release
#   - C/CXX compiler: clang-21 (matches the LLVM dev libs ABI)

set -euo pipefail

CLEAN=0
for arg in "$@"; do
    case "$arg" in
        --clean) CLEAN=1 ;;
        -h|--help)
            echo "Usage: $0 [--clean]"
            exit 0
            ;;
        *)
            echo "[passes-build] unknown arg: $arg" >&2
            exit 1
            ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LLVM_CMAKE="/usr/lib/llvm-21/lib/cmake/llvm"
BUILD_DIR="${ROOT}/build"

if [ ! -d "$LLVM_CMAKE" ]; then
    echo "[passes-build] LLVM-21 dev SDK not found at: $LLVM_CMAKE" >&2
    echo "  Install with: sudo apt install llvm-21-dev" >&2
    exit 1
fi
if ! command -v cmake >/dev/null; then
    echo "[passes-build] cmake not found. apt install cmake" >&2
    exit 1
fi
if ! command -v ninja >/dev/null; then
    echo "[passes-build] ninja not found. apt install ninja-build" >&2
    exit 1
fi
if ! command -v clang-21 >/dev/null; then
    echo "[passes-build] clang-21 not found. apt install clang-21" >&2
    exit 1
fi

if [ $CLEAN -eq 1 ] && [ -d "$BUILD_DIR" ]; then
    echo "[passes-build] cleaning $BUILD_DIR"
    rm -rf "$BUILD_DIR"
fi
mkdir -p "$BUILD_DIR"

CONFIGURE_ARGS=(
    -S "$ROOT"
    -B "$BUILD_DIR"
    -G Ninja
    "-DLLVM_DIR=$LLVM_CMAKE"
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_C_COMPILER=clang-21
    -DCMAKE_CXX_COMPILER=clang++-21
)

echo "[passes-build] cmake ${CONFIGURE_ARGS[*]}"
cmake "${CONFIGURE_ARGS[@]}"

echo "[passes-build] cmake --build $BUILD_DIR"
cmake --build "$BUILD_DIR"

# Locate the produced .so. Linux + PREFIX="" + Ninja single-config -> build/upobf-passes.so
CANDIDATES=(
    "${BUILD_DIR}/upobf-passes.so"
    "${BUILD_DIR}/Release/upobf-passes.so"
)
SO=""
for c in "${CANDIDATES[@]}"; do
    if [ -f "$c" ]; then SO="$c"; break; fi
done
if [ -z "$SO" ]; then
    echo "[passes-build] FAILED: upobf-passes.so not produced" >&2
    echo "Build dir contents:" >&2
    find "$BUILD_DIR" -maxdepth 3 -name "*.so" -print >&2 || true
    exit 1
fi

BYTES=$(stat -c %s "$SO")
echo
echo "[passes-build] produced $SO ($BYTES bytes)"
echo "[passes-build] OK"
