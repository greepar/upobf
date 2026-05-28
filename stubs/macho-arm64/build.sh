#!/usr/bin/env bash
# upobf macOS arm64 stub builder.
#
# Compiles each source under src/ into a relocatable object, then links
# them into a single Mach-O dylib (stub.dylib) whose __TEXT section is
# the stub blob the packer embeds into __UPOBF0.
#
# Usage:
#   ./build.sh [--pass-plugin <path>] [--pass-seed <hex>]
#
# Requirements:
#   - Apple clang (Xcode Command Line Tools) or LLVM clang
#   - macOS arm64 host (no cross-compilation)
#
# Output:
#   build/stub.dylib  — the stub blob for the packer
#   build/stub.bin    — raw __TEXT,__text bytes extracted (alternative embed)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
INC_DIR="$SCRIPT_DIR/include"
BUILD_DIR="$SCRIPT_DIR/build"

# Parse optional arguments.
PASS_PLUGIN=""
PASS_SEED=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pass-plugin) PASS_PLUGIN="$2"; shift 2 ;;
        --pass-seed)   PASS_SEED="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Compiler settings.
CC="${CC:-clang}"
TARGET="arm64-apple-macos11.0"
MIN_OS="11.0"

CFLAGS=(
    -target "$TARGET"
    -ffreestanding
    -fno-builtin
    -fPIC
    -fvisibility=hidden
    -Os
    -fno-asynchronous-unwind-tables
    -fno-exceptions
    -fno-rtti
    -fno-stack-protector
    -fno-common
    -mno-implicit-float
    -I "$INC_DIR"
)

# Optional IR obfuscation passes.
if [[ -n "$PASS_PLUGIN" ]]; then
    CFLAGS+=(-fpass-plugin="$PASS_PLUGIN")
    if [[ -n "$PASS_SEED" ]]; then
        CFLAGS+=(-mllvm -upobf-seed="$PASS_SEED")
    fi
fi

# Clean and create build dir.
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "[*] Compiling stub sources..."

OBJECTS=()
for src in "$SRC_DIR"/*.c; do
    obj="$BUILD_DIR/$(basename "${src%.c}.o")"
    echo "    CC $src -> $obj"
    "$CC" "${CFLAGS[@]}" -c "$src" -o "$obj"
    OBJECTS+=("$obj")
done

echo "[*] Linking stub as static executable (no GOT, direct PC-relative access)..."

# Link as a static PIE executable:
#   - No dynamic linker needed (all symbols resolved at link time)
#   - No GOT (global variables accessed directly via ADRP+ADD/LDR)
#   - Export key symbols for the packer to find offsets
#   - Use -undefined dynamic_lookup for dyld API symbols (resolved at runtime)
SDK_PATH="$(xcrun --show-sdk-path)"
ld -arch arm64 \
   -dylib \
   -platform_version macos "$MIN_OS" "$MIN_OS" \
   -dead_strip \
   -no_uuid \
   -no_data_const \
   -exported_symbol _upobf_entry_trampoline \
   -exported_symbol _upobf_stub_init \
   -exported_symbol _g_payload_vaddr \
   -exported_symbol _g_image_base_rva \
   -exported_symbol _g_image_base_anchor \
   -exported_symbol _g_original_entryoff \
   -L "${SDK_PATH}/usr/lib" \
   -lSystem \
   "${OBJECTS[@]}" \
   -o "$BUILD_DIR/stub.dylib"

echo "[*] Stub built: $BUILD_DIR/stub.dylib"

# Show segment layout for verification.
echo ""
echo "[*] Segment layout:"
otool -l "$BUILD_DIR/stub.dylib" | grep -A4 "cmd LC_SEGMENT_64" || true

# Show size.
STUB_SIZE=$(stat -f%z "$BUILD_DIR/stub.dylib" 2>/dev/null || stat --printf="%s" "$BUILD_DIR/stub.dylib" 2>/dev/null)
echo ""
echo "[*] Stub size: $STUB_SIZE bytes"

echo "[*] Done."
