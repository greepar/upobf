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
#
# IR pipeline (Phase H mirror):
#   --pass-plugin <path-to-upobf-passes.so>  enable upobf-cff/bcf/mba
#   --pass-seed   <uint32>                   master seed for PRNG
#
# When --pass-plugin is set we run a 3-step pipeline per TU:
#   1) clang -emit-llvm -c       -> .bc
#   2) opt-21 --load-pass-plugin -> .opt.bc
#   3) llc-21 -filetype=obj      -> .o
# Bypass policy mirrors stubs/pe-x64/build.ps1:
#   - lzma_dec       : full bypass (vendored, hot, IR-pass blowup)
#   - chacha20/bcj_x86: skip CFF (tight inner loop), keep BCF+MBA

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
INC_DIR="$SCRIPT_DIR/include"
BUILD_DIR="$SCRIPT_DIR/build"

CLANG="${CLANG:-clang-21}"
LLD="${LLD:-ld.lld-21}"
OPT="${OPT:-opt-21}"
LLC="${LLC:-llc-21}"

CLEAN=0
VERBOSE=0
PASS_PLUGIN=""
PASS_SEED=0
while [ $# -gt 0 ]; do
    case "$1" in
        --clean) CLEAN=1; shift ;;
        --verbose) VERBOSE=1; shift ;;
        --pass-plugin) PASS_PLUGIN="$2"; shift 2 ;;
        --pass-plugin=*) PASS_PLUGIN="${1#*=}"; shift ;;
        --pass-seed) PASS_SEED="$2"; shift 2 ;;
        --pass-seed=*) PASS_SEED="${1#*=}"; shift ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
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

# --- IR pipeline gating ------------------------------------------------
USE_IR_PIPELINE=0
if [ -n "$PASS_PLUGIN" ]; then
    if [ ! -f "$PASS_PLUGIN" ]; then
        echo "[stub-build] ERROR: --pass-plugin path not found: $PASS_PLUGIN" >&2
        exit 1
    fi
    if ! command -v "$OPT" >/dev/null; then
        echo "[stub-build] WARN: --pass-plugin set but $OPT not on PATH; falling back to legacy clang -c" >&2
    elif ! command -v "$LLC" >/dev/null; then
        echo "[stub-build] WARN: --pass-plugin set but $LLC not on PATH; falling back to legacy clang -c" >&2
    else
        USE_IR_PIPELINE=1
    fi
fi

# Files that bypass the IR pipeline entirely.
BYPASS_IR=("lzma_dec")
# Files that go through IR but skip CFF (tight inner loops).
BYPASS_CFF=("chacha20" "bcj_x86")

if [ "$USE_IR_PIPELINE" -eq 1 ]; then
    echo "[stub-build] IR pipeline ENABLED"
    if [ "$VERBOSE" -eq 1 ]; then
        echo "[stub-build]   plugin: $PASS_PLUGIN"
        echo "[stub-build]   opt:    $OPT"
        echo "[stub-build]   llc:    $LLC"
        printf '[stub-build]   seed:   0x%08x\n' "$PASS_SEED"
    fi
fi

# --- Helpers -----------------------------------------------------------
contains() {
    local needle="$1"; shift
    for x in "$@"; do
        [ "$x" = "$needle" ] && return 0
    done
    return 1
}

# Sum of ASCII codes mod 0x10000 — cheap deterministic per-file salt.
ascii_salt() {
    local s="$1"
    local total=0 i ch
    for (( i=0; i<${#s}; i++ )); do
        ch="${s:i:1}"
        total=$(( total + $(printf '%d' "'$ch") ))
    done
    echo $(( total & 0xFFFF ))
}

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

    legacy_path=1
    if [ "$USE_IR_PIPELINE" -eq 1 ] && ! contains "$base" "${BYPASS_IR[@]}"; then
        legacy_path=0
    fi

    if [ "$legacy_path" -eq 1 ]; then
        if [ "$VERBOSE" -eq 1 ]; then
            echo "[stub-build] $CLANG ${flags[*]} -c $src -o $out"
        else
            echo "[stub-build] compile $(basename "$src") -> $(basename "$out")"
        fi
        "$CLANG" "${flags[@]}" -c "$src" -o "$out"
        OBJS+=("$out")
        continue
    fi

    # IR pipeline path: clang -emit-llvm -> opt --load-pass-plugin -> llc -filetype=obj.
    bc="$BUILD_DIR/$base.bc"
    optbc="$BUILD_DIR/$base.opt.bc"

    salt=$(ascii_salt "$base")
    # XOR master seed with per-file salt + per-pass constant. Mask to
    # 32 bits to mirror the PowerShell uint32 cast.
    mba_seed=$(( (PASS_SEED ^ (salt + 0xC0FFEE))   & 0xFFFFFFFF ))
    bcf_seed=$(( (PASS_SEED ^ (salt + 0xBADC0DE))  & 0xFFFFFFFF ))
    cff_seed=$(( (PASS_SEED ^ (salt + 0xCAFEFACE)) & 0xFFFFFFFF ))

    # Pass ordering matches PE: cff,bcf,mba (with cff bypass for hot loops).
    if contains "$base" "${BYPASS_CFF[@]}"; then
        passes="upobf-bcf<seed=$bcf_seed>,upobf-mba<seed=$mba_seed>"
    else
        passes="upobf-cff<seed=$cff_seed>,upobf-bcf<seed=$bcf_seed>,upobf-mba<seed=$mba_seed>"
    fi

    # Step 1: clang -emit-llvm -c
    if [ "$VERBOSE" -eq 1 ]; then
        echo "[stub-build] $CLANG ${flags[*]} -emit-llvm -c $src -o $bc"
    else
        echo "[stub-build] llvm-ir  $(basename "$src") -> $(basename "$bc")"
    fi
    "$CLANG" "${flags[@]}" -emit-llvm -c "$src" -o "$bc"

    # Step 2: opt --load-pass-plugin --passes
    if [ "$VERBOSE" -eq 1 ]; then
        echo "[stub-build] $OPT --load-pass-plugin $PASS_PLUGIN --passes '$passes' $bc -o $optbc"
    else
        echo "[stub-build] obfusc   $(basename "$bc") -> $(basename "$optbc")  ($passes)"
    fi
    # opt may exit non-zero on shutdown when a plugin is loaded (see PE
    # build.ps1 commentary). Trust output existence + non-empty as
    # success signal, mirroring the PE behaviour.
    set +e
    "$OPT" --load-pass-plugin "$PASS_PLUGIN" --passes "$passes" "$bc" -o "$optbc"
    rc=$?
    set -e
    if [ ! -s "$optbc" ]; then
        echo "[stub-build] ERROR: opt produced no bitcode for $src (exit $rc)" >&2
        exit 1
    fi
    if [ $rc -ne 0 ] && [ "$VERBOSE" -eq 1 ]; then
        echo "[stub-build] (note) opt returned $rc on shutdown; bitcode written OK"
    fi

    # Step 3: llc -filetype=obj
    if [ "$VERBOSE" -eq 1 ]; then
        echo "[stub-build] $LLC -filetype=obj -O2 -relocation-model=pic $optbc -o $out"
    else
        echo "[stub-build] codegen  $(basename "$optbc") -> $(basename "$out")"
    fi
    "$LLC" -filetype=obj -O2 -relocation-model=pic "$optbc" -o "$out"

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
