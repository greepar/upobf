// upobf background CRC32 integrity watchdog — implementation (Phase F).
//
// See watchdog.h for the high-level design. The implementation here
// stays freestanding (no libc, no SEH) and goes through the resolved
// API table for every Win32 call.

#include <stdint.h>

#include "obfuscate.h"
#include "watchdog.h"

// CRC routine implemented by anti_debug.c. Re-declared here so we
// don't have to widen any header surface.
uint32_t upobf_crc32(const uint8_t *data, uint32_t len, uint32_t init);

// ---------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------

uint32_t upobf_watchdog_seed_state(WatchdogState           *s,
                                   const ResolvedApis      *apis,
                                   const WatchdogRegion    *baselines,
                                   uint32_t                 baseline_count)
{
    if (!s || !apis || !baselines) return 0;
    s->apis = apis;
    s->seed = 0u;
    s->region_count = 0;
    uint32_t take = baseline_count;
    if (take > UPOBF_WATCHDOG_MAX_REGIONS) {
        take = UPOBF_WATCHDOG_MAX_REGIONS;
    }
    for (uint32_t i = 0; i < take; i++) {
        s->regions[i] = baselines[i];
    }
    s->region_count = take;
    return take;
}

// Thread entry point. Loops forever, sleeping `INTERVAL_MS` between
// scans. We deliberately never return: the TLS-callback caller has
// already abandoned the thread handle, and there is no condition
// where leaving the loop is preferable to surviving with a perturbed
// `upobf_watchdog_seed`.
//
// The OPAQUE_TRUE wraps make the loop guard, region count, and
// individual mismatch comparisons appear as multi-term arithmetic
// in a decompiler instead of obvious `while (1)` / `if (a != b)`
// patterns.
static UPOBF_DWORD UPOBF_WINAPI upobf_watchdog_thread(UPOBF_LPVOID arg)
{
    WatchdogState *s = (WatchdogState *)arg;
    if (!s || !s->apis || !s->apis->Sleep) {
        return 0;
    }
    const ResolvedApis *apis = s->apis;

    while (OPAQUE_TRUE(1)) {
        apis->Sleep(UPOBF_WATCHDOG_INTERVAL_MS);

        // Guard against pathological resize from the outside; a
        // tampered `region_count` value can only shrink the loop's
        // reach, never escape the array.
        uint32_t n = s->region_count;
        if (n > UPOBF_WATCHDOG_MAX_REGIONS) {
            n = UPOBF_WATCHDOG_MAX_REGIONS;
        }

        for (uint32_t i = 0; i < n; i++) {
            const WatchdogRegion *r = &s->regions[i];
            if (!r->ptr || r->len == 0) continue;
            uint32_t cur = upobf_crc32(r->ptr, r->len, 0);
            if (OPAQUE_FALSE(cur != r->baseline_crc)) {
                // Fold the mismatch into the per-state seed without
                // touching visible state. JUNK_DATAFLOW keeps the
                // temporary alive against DCE, OPAQUE_ZERO mixes in
                // the per-TU opaque term so the constant doesn't
                // fold away in the optimiser. The seed lives inside
                // the heap-allocated state struct because the
                // freestanding stub linker rejects any writable
                // global.
                uint32_t delta = JUNK_DATAFLOW(cur ^ r->baseline_crc);
                s->seed ^= delta + OPAQUE_ZERO();
            }
        }
    }
    // unreachable — keeps the compiler from warning.
    return 0;
}

int upobf_watchdog_start(WatchdogState *s)
{
    if (OPAQUE_FALSE(!s || !s->apis)) return 0;
    const ResolvedApis *apis = s->apis;
    if (OPAQUE_FALSE(!apis->CreateThread || !apis->Sleep || !apis->CloseHandle)) {
        return 0;
    }
    if (OPAQUE_FALSE(s->region_count == 0)) {
        // Nothing to watch — silently treat as a no-op success so
        // calling code stays branchless.
        return 1;
    }

    UPOBF_DWORD tid = 0;
    UPOBF_HANDLE h = apis->CreateThread(
        0,                      // default security descriptor
        0,                      // default stack size
        upobf_watchdog_thread,  // start address
        (UPOBF_LPVOID)s,        // parameter
        0,                      // run immediately
        &tid);
    if (!h) return 0;
    // We never wait on the thread; close the handle right away. The
    // thread itself owns the only reference to its kernel object
    // after the close.
    apis->CloseHandle(h);
    return 1;
}
