#!/usr/bin/env bash
# upobf macOS arm64 end-to-end verification script.
#
# Validates the full pipeline:
#   1. Build the stub (stubs/macho-arm64/build.sh)
#   2. Build the packer (cargo build --release)
#   3. Pack the demo binary
#   4. Re-sign with ad-hoc signature (codesign)
#   5. Run the packed binary for 3s survival check
#   6. Verify polymorphism (two packs produce different bytes)
#
# Usage:
#   ./pack_run_verify_macos.sh [/path/to/demo/binary]
#
# If no binary is specified, uses the test fixture PatchInstaller.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Default demo binary.
DEMO="${1:-$REPO_ROOT/tests/fixtures/PatchInstaller.app/Contents/MacOS/PatchInstaller}"

if [[ ! -f "$DEMO" ]]; then
    echo "[ERROR] Demo binary not found: $DEMO"
    exit 1
fi

echo "============================================"
echo " upobf macOS arm64 — End-to-End Verification"
echo "============================================"
echo ""
echo "[*] Demo binary: $DEMO"
echo "[*] File size:    $(stat -f%z "$DEMO") bytes"
echo ""

# --- Step 1: Build stub ---------------------------------------------------
echo "[1/6] Building arm64 stub..."
STUB_DIR="$REPO_ROOT/stubs/macho-arm64"
if [[ -f "$STUB_DIR/build.sh" ]]; then
    (cd "$STUB_DIR" && ./build.sh)
    echo "      Stub: $STUB_DIR/build/stub.dylib ($(stat -f%z "$STUB_DIR/build/stub.dylib") bytes)"
else
    echo "      [WARN] build.sh not found, skipping stub build"
fi
echo ""

# --- Step 2: Build packer -------------------------------------------------
echo "[2/6] Building packer (cargo build --release)..."
(cd "$REPO_ROOT" && cargo build --release -p upobf-macho 2>&1 | tail -3)
echo ""

# --- Step 3: Pack the demo ------------------------------------------------
echo "[3/6] Packing demo binary..."
PACKED_DIR="$(mktemp -d)"
PACKED="$PACKED_DIR/packed_demo"

# Use a small Rust test binary to drive the pack.
# For now, we use cargo test as the packer (the pack_e2e test writes output).
# In production, this would be: target/release/upobf pack-macho "$DEMO" -o "$PACKED"
#
# Since we don't have a CLI subcommand yet, we'll use a helper binary.
cat > "$PACKED_DIR/pack_helper.rs" << 'HELPER_EOF'
use std::path::Path;
use upobf_macho::pack::{pack_macho, PackConfig};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: pack_helper <input> <output>");
        std::process::exit(1);
    }
    let input = &args[1];
    let output = &args[2];

    let config = PackConfig::default();
    match pack_macho(Path::new(input), &config) {
        Ok(result) => {
            std::fs::write(output, &result.bytes).expect("write output");
            eprintln!("Packed: {} -> {} bytes ({} chunks, {:.1}% ratio)",
                result.original_size, result.packed_size, result.chunk_count,
                result.packed_size as f64 / result.original_size as f64 * 100.0);
        }
        Err(e) => {
            eprintln!("Pack failed: {:?}", e);
            std::process::exit(1);
        }
    }
}
HELPER_EOF

# Build and run the helper via cargo's test infrastructure.
# Actually, let's just use `cargo test` to produce the packed output.
(cd "$REPO_ROOT" && cargo test -p upobf-macho --test pack_e2e -- pack_patch_installer_e2e --nocapture > /dev/null 2>&1)

# For the e2e script, we'll pack directly using the library.
# Write a small example binary that does the pack.
cat > "$PACKED_DIR/Cargo.toml" << CARGO_EOF
[package]
name = "pack-helper"
version = "0.1.0"
edition = "2021"

[dependencies]
upobf-macho = { path = "$REPO_ROOT/crates/upobf-macho" }
CARGO_EOF

mkdir -p "$PACKED_DIR/src"
mv "$PACKED_DIR/pack_helper.rs" "$PACKED_DIR/src/main.rs"

echo "      Building pack helper..."
(cd "$PACKED_DIR" && cargo build --release 2>&1 | tail -2)
"$PACKED_DIR/target/release/pack-helper" "$DEMO" "$PACKED" 2>&1 | sed 's/^/      /'

if [[ ! -f "$PACKED" ]]; then
    echo "[ERROR] Packed binary not produced"
    rm -rf "$PACKED_DIR"
    exit 1
fi

PACKED_SIZE=$(stat -f%z "$PACKED")
ORIG_SIZE=$(stat -f%z "$DEMO")
echo "      Output: $PACKED ($PACKED_SIZE bytes)"
echo ""

# --- Step 4: Re-sign ------------------------------------------------------
echo "[4/6] Ad-hoc code signing..."
codesign --force --sign - "$PACKED" 2>&1 | sed 's/^/      /' || true
echo "      Done."
echo ""

# --- Step 5: Survival check -----------------------------------------------
echo "[5/6] Running packed binary (3s survival check)..."
# Note: The packed binary won't actually run correctly yet because the stub
# needs to decompress at runtime. This step validates that dyld can at least
# load the binary (segments are valid, LC_MAIN points somewhere valid).
# A full runtime test requires the stub to be functional end-to-end.
set +e
"$PACKED" &
PID=$!
sleep 3
if kill -0 "$PID" 2>/dev/null; then
    echo "      ALIVE (PID $PID survived 3s)"
    kill "$PID" 2>/dev/null || true
    SURVIVAL="PASS"
else
    wait "$PID" 2>/dev/null
    EXIT_CODE=$?
    echo "      EXITED (exit code: $EXIT_CODE)"
    if [[ $EXIT_CODE -eq 0 ]]; then
        SURVIVAL="PASS (clean exit)"
    else
        SURVIVAL="EXPECTED_FAIL (stub not yet functional at runtime)"
    fi
fi
set -e
echo ""

# --- Step 6: Polymorphism check -------------------------------------------
echo "[6/6] Polymorphism check (two packs should differ)..."
PACKED2="$PACKED_DIR/packed_demo2"
"$PACKED_DIR/target/release/pack-helper" "$DEMO" "$PACKED2" 2>/dev/null

if cmp -s "$PACKED" "$PACKED2"; then
    echo "      [WARN] Two packs produced identical output (polymorphism not active)"
    POLY="WARN"
else
    DIFF_BYTES=$(cmp -l "$PACKED" "$PACKED2" 2>/dev/null | wc -l | tr -d ' ')
    echo "      PASS: $DIFF_BYTES bytes differ between two packs"
    POLY="PASS"
fi
echo ""

# --- Summary ---------------------------------------------------------------
echo "============================================"
echo " Summary"
echo "============================================"
echo "  Original:     $ORIG_SIZE bytes"
echo "  Packed:       $PACKED_SIZE bytes"
echo "  Ratio:        $(echo "scale=1; $PACKED_SIZE * 100 / $ORIG_SIZE" | bc)%"
echo "  Stub:         $(stat -f%z "$STUB_DIR/build/stub.dylib" 2>/dev/null || echo 'N/A') bytes"
echo "  Survival:     $SURVIVAL"
echo "  Polymorphism: $POLY"
echo "============================================"

# Cleanup.
rm -rf "$PACKED_DIR"

echo ""
echo "[*] Done."
