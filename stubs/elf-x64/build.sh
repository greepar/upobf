#!/usr/bin/env bash
# upobf ELF x64 stub builder.
#
# Compiles each source under src/ separately into a relocatable ELF
# object, then links them with `ld.lld -r` into a single relocatable
# object whose `.text` section is the stub blob the packer
# embeds into `.upobf0`.
#
# Compared to the Windows side, we do *not* run a custom Rust linker
# on the result; lld already produces a clean PIC blob with no
# external symbol references when the source code is freestanding
# and uses RIP-relative addressing exclusively.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
INC_DIR="$SCRIPT_DIR/include"
BUILD_DIR="$SCRIPT_DIR/build"

CLANG="${CLANG:-clang-21}"
LLD="${LLD:-ld.lld-21}"

CLEAN=0
VERBOSE=0
for arg in "$@"; do
    case "$arg" in
        --clean) CLEAN=1 ;;
        --verbose) VERBOSE=1 ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

if [ "$CLEAN" -eq 1 ] && [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi
mkdir -p "$BUILD_DIR"

# --- Compile flags -----------------------------------------------------
#
# `-fPIC -ffreestanding -nostdlib` ensures we don't pull in libc.
# `-fno-stack-protector` matches the PE side; we have no canary
# infrastructure in a freestanding stub.
# `-fvisibility=hidden` keeps every symbol local so the final
# `.so`-style blob has no DT_NEEDED-style references.
# `-fno-asynchronous-unwind-tables -fno-exceptions` keep the .text
# section free of `.eh_frame` entries we'd otherwise have to drop.
CFLAGS=(
    -target x86_64-linux-gnu
    -fPIC
    -ffreestanding
    -nostdlib
    -fno-stack-protector
    -fno-builtin
    -fno-asynchronous-unwind-tables
    -fno-exceptions
    -fvisibility=hidden
    -Os
    "-I$INC_DIR"
)

# Quiet the LZMA SDK's vendored warnings (mirrors PE side).
LZMA_FLAGS=(-Wno-everything)

# --- Compile each TU ---------------------------------------------------
SRC_LIST=()
while IFS= read -r -d '' f; do
    SRC_LIST+=("$f")
done < <(find "$SRC_DIR" -name '*.c' -print0)

if [ ${#SRC_LIST[@]} -eq 0 ]; then
    echo "no stub sources under $SRC_DIR" >&2
    exit 1
fi

OBJS=()
for src in "${SRC_LIST[@]}"; do
    base="$(basename "$src" .c)"
    out="$BUILD_DIR/$base.o"

    flags=("${CFLAGS[@]}")
    if [ "$base" = "lzma_dec" ]; then
        flags+=("${LZMA_FLAGS[@]}")
    fi

    if [ "$VERBOSE" -eq 1 ]; then
        echo "[stub-build] $CLANG ${flags[*]} -c $src -o $out"
    else
        echo "[stub-build] compile $(basename "$src") -> $(basename "$out")"
    fi
    "$CLANG" "${flags[@]}" -c "$src" -o "$out"
    OBJS+=("$out")
done

# --- Link relocatable & shared object -----------------------------------
#
# We produce two outputs:
#   stub.o:  combined relocatable (`ld.lld -r`). Useful for code-size
#            inspection but otherwise unused at runtime.
#   stub.so: PIE shared object (`-shared -Bsymbolic --no-undefined`)
#            with **zero relocations** thanks to `--gc-sections` +
#            `-Bsymbolic` resolving every internal call. The Rust
#            packer slurps `stub.so` and flattens its LOAD segments
#            into a single byte buffer (see `stub_loader.rs`).

LINKED="$BUILD_DIR/stub.o"
if [ "$VERBOSE" -eq 1 ]; then
    echo "[stub-build] $LLD -r ${OBJS[*]} -o $LINKED"
else
    echo "[stub-build] link -r -> $(basename "$LINKED")"
fi
"$LLD" -r "${OBJS[@]}" -o "$LINKED"

SO="$BUILD_DIR/stub.so"
if [ "$VERBOSE" -eq 1 ]; then
    echo "[stub-build] $LLD -shared -Bsymbolic --no-undefined --no-dynamic-linker --gc-sections -nostdlib -e upobf_stub_init ${OBJS[*]} -o $SO"
else
    echo "[stub-build] link -shared -> $(basename "$SO")"
fi
"$LLD" -shared -Bsymbolic --no-undefined --no-dynamic-linker --gc-sections \
    -nostdlib -e upobf_stub_init "${OBJS[@]}" -o "$SO"

# --- Report -----------------------------------------------------------
echo ""
echo "[stub-build] produced:"
for o in "${OBJS[@]}"; do
    sz=$(wc -c < "$o")
    printf "  %-32s %8d bytes\n" "$(basename "$o")" "$sz"
done
sz=$(wc -c < "$LINKED")
printf "  %-32s %8d bytes (relocatable)\n" "$(basename "$LINKED")" "$sz"
sz=$(wc -c < "$SO")
printf "  %-32s %8d bytes (PIE shared object — packer input)\n" "$(basename "$SO")" "$sz"
