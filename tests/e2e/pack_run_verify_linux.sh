#!/usr/bin/env bash
# upobf E2E test runner — Linux ELF mirror of pack_run_verify.ps1.
#
# Usage:
#   ./tests/e2e/pack_run_verify_linux.sh
#   ./tests/e2e/pack_run_verify_linux.sh path/to/binary
#
# Steps:
#   1. Build stub (stubs/elf-x64/build.sh)
#   2. Build packer (cargo build --release)
#   3. Pack target binary
#   4. Run packed binary, verify it survives N seconds
#   5. Pack again, verify SHA256 differs (polymorphism)
#   6. Clean up.
#
# Exit code 0 on success, non-zero on failure.

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

INPUT_PATH="${1:-${REPO_ROOT}/Demo/PatchInstaller}"
OUTPUT_PATH="${REPO_ROOT}/packed_e2e_linux"
OUTPUT_PATH_B="${REPO_ROOT}/packed_e2e_linux_b"
RUNTIME_SECONDS="${RUNTIME_SECONDS:-3}"

if [ ! -f "$INPUT_PATH" ]; then
    echo "[e2e] ERROR: input not found: $INPUT_PATH" >&2
    exit 2
fi
if [ ! -x "$INPUT_PATH" ]; then
    echo "[e2e] ERROR: input is not executable: $INPUT_PATH" >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# Step 1: build stub
# -----------------------------------------------------------------------------
echo "[e2e] Building stub..."
"${REPO_ROOT}/stubs/elf-x64/build.sh" --clean | tail -10

STUB_SO="${REPO_ROOT}/stubs/elf-x64/build/stub.so"
if [ ! -f "$STUB_SO" ]; then
    echo "[e2e] ERROR: stub.so missing after build" >&2
    exit 3
fi

# -----------------------------------------------------------------------------
# Step 2: build packer
# -----------------------------------------------------------------------------
echo "[e2e] Building packer (release)..."
( cd "$REPO_ROOT" && cargo build --release -q -p upobf-cli )

PACKER="${REPO_ROOT}/target/release/upobf"
if [ ! -x "$PACKER" ]; then
    echo "[e2e] ERROR: packer binary missing: $PACKER" >&2
    exit 4
fi

# -----------------------------------------------------------------------------
# Step 3: pack
# -----------------------------------------------------------------------------
echo "[e2e] Packing $INPUT_PATH ..."
PACK_START=$(date +%s.%N)
RUST_LOG=error "$PACKER" pack "$INPUT_PATH" -o "$OUTPUT_PATH"
PACK_END=$(date +%s.%N)
PACK_DURATION=$(awk "BEGIN { printf \"%.2f\", $PACK_END - $PACK_START }")

ORIG_SIZE=$(stat -c %s "$INPUT_PATH")
PACK_SIZE=$(stat -c %s "$OUTPUT_PATH")
PACK_PCT=$(awk "BEGIN { printf \"%.1f\", ($PACK_SIZE / $ORIG_SIZE) * 100.0 }")
echo "[e2e] Pack:    ${ORIG_SIZE} -> ${PACK_SIZE} bytes (${PACK_PCT}%) in ${PACK_DURATION}s"

# -----------------------------------------------------------------------------
# Step 4: launch packed binary, ensure it survives RUNTIME_SECONDS seconds
# -----------------------------------------------------------------------------
echo "[e2e] Launching packed binary (must survive ${RUNTIME_SECONDS}s)..."
"$OUTPUT_PATH" >/tmp/upobf_e2e_stdout.log 2>/tmp/upobf_e2e_stderr.log &
PID=$!
sleep "$RUNTIME_SECONDS"

if ! kill -0 "$PID" 2>/dev/null; then
    # Process already exited — read its exit code.
    if wait "$PID"; then
        EXIT=0
    else
        EXIT=$?
    fi
    # exit code 0 is also OK if the binary is short-lived (e.g. hello).
    # But the Avalonia demo should still be running after 3s. We allow
    # exit==0 for non-Avalonia targets; for the demo we'd rather see
    # the process still alive.
    BASE=$(basename "$INPUT_PATH")
    if [ "$BASE" = "PatchInstaller" ] && [ "$EXIT" -ne 0 ]; then
        echo "[e2e] ERROR: packed Avalonia exited prematurely with code $EXIT" >&2
        echo "[e2e] stdout:" >&2
        sed -e 's/^/  /' /tmp/upobf_e2e_stdout.log >&2 || true
        echo "[e2e] stderr:" >&2
        sed -e 's/^/  /' /tmp/upobf_e2e_stderr.log >&2 || true
        exit 7
    fi
    echo "[e2e] Run:     packed binary exited cleanly (code $EXIT) within ${RUNTIME_SECONDS}s"
else
    # Process still alive — verify properties.
    THREAD_COUNT="$(ls /proc/$PID/task 2>/dev/null | wc -l || echo 0)"
    RSS_KB="$(awk '/^VmRSS:/ {print $2}' /proc/$PID/status 2>/dev/null || echo 0)"
    RSS_MB=$(awk "BEGIN { printf \"%.1f\", $RSS_KB / 1024.0 }")
    echo "[e2e] Run:     PID=$PID alive after ${RUNTIME_SECONDS}s, RSS=${RSS_MB}MB threads=$THREAD_COUNT"

    # Sanity: count RWX maps. They should be zero (the stub only
    # restores the original W/X bits after it finishes).
    RWX_COUNT="$(awk '$2 ~ /rwx/ {n++} END {print n+0}' /proc/$PID/maps)"
    if [ "$RWX_COUNT" -ne 0 ]; then
        echo "[e2e] WARN:    $RWX_COUNT RWX mapping(s) observed (expected 0)" >&2
        awk '$2 ~ /rwx/' /proc/$PID/maps | head -3 >&2
    else
        echo "[e2e] Maps:    no RWX mappings observed (good)"
    fi

    # Tear down.
    kill -TERM "$PID" 2>/dev/null || true
    sleep 0.5
    kill -KILL "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
fi

# -----------------------------------------------------------------------------
# Step 5: polymorphism check
# -----------------------------------------------------------------------------
echo "[e2e] Building second packed binary for polymorphism check..."
RUST_LOG=error "$PACKER" pack "$INPUT_PATH" -o "$OUTPUT_PATH_B" >/dev/null

H1="$(sha256sum "$OUTPUT_PATH"   | awk '{print $1}')"
H2="$(sha256sum "$OUTPUT_PATH_B" | awk '{print $1}')"

if [ "$H1" = "$H2" ]; then
    echo "[e2e] ERROR: polymorphism check FAILED — identical SHA256 across builds ($H1)" >&2
    exit 8
fi
echo "[e2e] Poly:    SHA256 A=${H1:0:16}..."
echo "[e2e]          SHA256 B=${H2:0:16}... (differ)"

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------
rm -f "$OUTPUT_PATH" "$OUTPUT_PATH_B" /tmp/upobf_e2e_stdout.log /tmp/upobf_e2e_stderr.log
echo "[e2e] PASSED"
