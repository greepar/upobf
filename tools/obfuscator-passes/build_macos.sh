#!/usr/bin/env bash
# upobf-passes macOS build driver.
#
# Configures CMake against Homebrew's LLVM-21 dev SDK and builds
# `upobf-passes.dylib` in Release mode.
#
# Prerequisites:
#   brew install llvm@21 cmake ninja
#
# Usage:
#   ./tools/obfuscator-passes/build_macos.sh           # configure + build
#   ./tools/obfuscator-passes/build_macos.sh --clean   # wipe build/ first
#
# Output:
#   tools/obfuscator-passes/build/upobf-passes.dylib

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
            echo "[passes-build-macos] unknown arg: $arg" >&2
            exit 1
            ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${ROOT}/build"

# Find LLVM. Try llvm@21 first, then llvm@18, then unversioned.
LLVM_PREFIX=""
for candidate in \
    "$(brew --prefix llvm@21 2>/dev/null || true)" \
    "$(brew --prefix llvm 2>/dev/null || true)" \
    "/opt/homebrew/opt/llvm@21" \
    "/opt/homebrew/opt/llvm"; do
    if [[ -n "$candidate" && -d "$candidate/lib/cmake/llvm" ]]; then
        LLVM_PREFIX="$candidate"
        break
    fi
done

if [[ -z "$LLVM_PREFIX" ]]; then
    echo "[passes-build-macos] LLVM not found via Homebrew." >&2
    echo "  Install with: brew install llvm@21" >&2
    echo "  Or: brew install llvm" >&2
    exit 1
fi

LLVM_CMAKE="$LLVM_PREFIX/lib/cmake/llvm"
CLANG="$LLVM_PREFIX/bin/clang"
CLANGXX="$LLVM_PREFIX/bin/clang++"

echo "[passes-build-macos] Using LLVM at: $LLVM_PREFIX"

if ! command -v cmake >/dev/null; then
    echo "[passes-build-macos] cmake not found. brew install cmake" >&2
    exit 1
fi
if ! command -v ninja >/dev/null; then
    echo "[passes-build-macos] ninja not found. brew install ninja" >&2
    exit 1
fi

if [[ $CLEAN -eq 1 ]] && [[ -d "$BUILD_DIR" ]]; then
    echo "[passes-build-macos] cleaning $BUILD_DIR"
    rm -rf "$BUILD_DIR"
fi
mkdir -p "$BUILD_DIR"

CONFIGURE_ARGS=(
    -S "$ROOT"
    -B "$BUILD_DIR"
    -G Ninja
    "-DLLVM_DIR=$LLVM_CMAKE"
    -DCMAKE_BUILD_TYPE=Release
    "-DCMAKE_C_COMPILER=$CLANG"
    "-DCMAKE_CXX_COMPILER=$CLANGXX"
)

echo "[passes-build-macos] cmake ${CONFIGURE_ARGS[*]}"
cmake "${CONFIGURE_ARGS[@]}"

echo "[passes-build-macos] cmake --build $BUILD_DIR"
cmake --build "$BUILD_DIR"

# Locate the produced .dylib.
CANDIDATES=(
    "${BUILD_DIR}/upobf-passes.dylib"
    "${BUILD_DIR}/Release/upobf-passes.dylib"
    "${BUILD_DIR}/libupobf-passes.dylib"
)
DYLIB=""
for c in "${CANDIDATES[@]}"; do
    if [[ -f "$c" ]]; then DYLIB="$c"; break; fi
done
if [[ -z "$DYLIB" ]]; then
    echo "[passes-build-macos] FAILED: upobf-passes.dylib not produced" >&2
    echo "Build dir contents:" >&2
    find "$BUILD_DIR" -maxdepth 3 -name "*.dylib" -print >&2 || true
    exit 1
fi

BYTES=$(stat -f%z "$DYLIB")
echo
echo "[passes-build-macos] produced $DYLIB ($BYTES bytes)"
echo "[passes-build-macos] OK"
