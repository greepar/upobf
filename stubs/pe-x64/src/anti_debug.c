// upobf anti-debug & integrity helpers (Phase G).
//
// Phase G: every Win32 API call here now goes through the
// `ResolvedApis` table populated by `api_resolve.c`. The previous
// `__declspec(dllimport)` declarations of `IsDebuggerPresent` /
// `GetThreadContext` / `GetCurrentProcess` / `GetCurrentThread` are
// gone, so the stub no longer leaves those names visible in the
// packed PE's import table.
//
// AV-friendly philosophy is unchanged: detection points feed an
// `env_seed` value instead of triggering an immediate exit. The
// downstream protection layer perturbs based on the seed so that
// under analysis the program "looks normal but behaves slightly off".
// No syscalls, no PEB walking, no thread-hide tricks — only standard
// public APIs.
//
// Source-level obfuscation note (Phase A2):
//
//   The XOR seed deltas used to be the eye-catching constants
//   `0xDEADBEEF` and `0xFEEDFACE`. We now derive them from arithmetic
//   on the per-TU opaque seed so the constants never appear as 32-bit
//   immediates in the emitted code.
//
//   Each branch guard is also wrapped with OPAQUE_TRUE / OPAQUE_FALSE
//   so a static analyzer must consider the runtime opaque term.

#include <stdint.h>

#include "obfuscate.h"
#include "api_resolve.h"

// CONTEXT layout: only the DR fields matter, but we need the full
// 0x4D0-byte structure. We don't actually allocate one — we pass a
// stack array large enough.
#define CONTEXT_DEBUG_REGISTERS 0x00100010

/// Compute an environment seed encoding the analyst presence.
///
/// All checks use documented public APIs, looked up through `apis`
/// (the resolved-API table built in `entry.c` from the encrypted
/// payload's ApiStringTable). None of them exit, throw, or change
/// visible state. The XOR mask values are derived from the
/// obfuscation seed (see obfuscate.h) so the literal "magic
/// constants" never show up in the disassembly.
uint32_t upobf_env_seed(const ResolvedApis *apis) {
    uint32_t seed = 0;
    if (!apis) return seed;

    // Mask values: at runtime equivalent to fixed values, but the
    // expressions involve the per-TU opaque seed so a constant-folder
    // cannot reduce them to a single immediate.
    uint32_t mask_debugger = JUNK_DATAFLOW(0xDEADBEEFu) ^ OPAQUE_ZERO();
    uint32_t mask_hwbp     = JUNK_DATAFLOW(0xFEEDFACEu) ^ OPAQUE_ZERO();

    if (apis->IsDebuggerPresent &&
        OPAQUE_TRUE(apis->IsDebuggerPresent())) {
        seed ^= mask_debugger;
    }

    // Hardware breakpoint check via standard GetThreadContext.
    // The CONTEXT structure on AMD64 is 0x4D0 bytes; we round up to
    // 0x500 and place it on the stack so the linker doesn't need to
    // emit a `.bss` slot (the freestanding stub forbids those).
    if (apis->GetThreadContext && apis->GetCurrentThread) {
        uint8_t ctx[0x500];
        for (int i = 0; i < 0x500; i++) ctx[i] = 0;
        *(volatile uint32_t*)(ctx + 0x30) = CONTEXT_DEBUG_REGISTERS;
        if (OPAQUE_TRUE(apis->GetThreadContext(apis->GetCurrentThread(),
                                                (void*)ctx))) {
            uint64_t dr0 = *(volatile uint64_t*)(ctx + 0x48);
            uint64_t dr1 = *(volatile uint64_t*)(ctx + 0x50);
            uint64_t dr2 = *(volatile uint64_t*)(ctx + 0x58);
            uint64_t dr3 = *(volatile uint64_t*)(ctx + 0x60);
            if (OPAQUE_TRUE(dr0 | dr1 | dr2 | dr3)) {
                seed ^= mask_hwbp;
            }
        }
    }

    return seed + OPAQUE_ZERO();
}

/// Lightweight CRC32 (IEEE 802.3 polynomial, table-free reflected
/// implementation). 32 bits of output is enough for periodic integrity
/// checks; the watchdog stores baseline values and re-computes them.
uint32_t upobf_crc32(const uint8_t* data, uint32_t len, uint32_t init) {
    uint32_t crc = init ^ 0xFFFFFFFFu;
    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int k = 0; k < 8; k++) {
            uint32_t mask = (uint32_t)(-(int32_t)(crc & 1));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}
