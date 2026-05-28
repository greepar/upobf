// upobf background CRC32 integrity watchdog — implementation
// (Phase F, ELF flavour).
//
// See watchdog.h for the high-level design. The implementation here
// stays freestanding (no libc, no signal handlers) and goes through
// the resolved API table for every libc call. CRC32 is computed
// in-line so the TU has no external link beyond ResolvedApis.

#include <stdint.h>

#include "obfuscate.h"
#include "watchdog.h"

// ---------------------------------------------------------------------
// CRC32 (IEEE 802.3 polynomial 0xEDB88320). init/final XOR with ~0u
// matches the PE side's `upobf_crc32` so any future cross-platform
// integrity assert produces identical values.
//
// Implemented as a slice-by-1 table with the table generated lazily
// on first call. The table itself lives in a function-local static
// volatile array so it ends up in .data (writable) — but the stub
// rejects writable globals. Workaround: build the table on every
// call; CRC32 is invoked once per scan, dwarfed by the 30 s sleep.
// ---------------------------------------------------------------------

static uint32_t crc32_step(uint32_t c, uint8_t b) {
    c ^= b;
    for (int i = 0; i < 8; i++) {
        c = (c >> 1) ^ (0xEDB88320u & -(int32_t)(c & 1u));
    }
    return c;
}

uint32_t upobf_crc32(const uint8_t *data, uint32_t len, uint32_t init) {
    uint32_t c = ~init;
    for (uint32_t i = 0; i < len; i++) {
        c = crc32_step(c, data[i]);
    }
    return ~c;
}

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

// pthread start routine. Loops forever, sleeping `INTERVAL_NS`
// between scans. We deliberately never return: the .init_array caller
// has already detached the thread, and there is no condition where
// leaving the loop is preferable to surviving with a perturbed
// `s->seed`.
//
// OPAQUE_TRUE / OPAQUE_FALSE wrap the loop guard, region count, and
// individual mismatch comparisons so a decompiler sees multi-term
// arithmetic instead of obvious `while (1)` / `if (a != b)`
// patterns.
static void *upobf_watchdog_thread(void *arg) {
    WatchdogState *s = (WatchdogState *)arg;
    if (!s || !s->apis || !s->apis->nanosleep) {
        return 0;
    }
    const ResolvedApis *apis = s->apis;

    while (OPAQUE_TRUE(1)) {
        struct upobf_timespec_t req = {
            .tv_sec  = (upobf_time_t)UPOBF_WATCHDOG_INTERVAL_S,
            .tv_nsec = 0,
        };
        struct upobf_timespec_t rem = { 0, 0 };
        // nanosleep returns -1/EINTR if a signal arrives. We don't
        // care; the next loop iteration will sleep again from the
        // top. Avoiding a retry-on-EINTR loop also keeps the
        // emitted code short.
        apis->nanosleep(&req, &rem);

        // Guard against a tampered region_count.
        uint32_t n = s->region_count;
        if (n > UPOBF_WATCHDOG_MAX_REGIONS) {
            n = UPOBF_WATCHDOG_MAX_REGIONS;
        }

        for (uint32_t i = 0; i < n; i++) {
            const WatchdogRegion *r = &s->regions[i];
            if (!r->ptr || r->len == 0) continue;
            uint32_t cur = upobf_crc32(r->ptr, r->len, 0);
            if (OPAQUE_FALSE(cur != r->baseline_crc)) {
                uint32_t delta = JUNK_DATAFLOW(cur ^ r->baseline_crc);
                s->seed ^= delta + OPAQUE_ZERO();
            }
        }
    }
    // unreachable.
    return 0;
}

int upobf_watchdog_start(WatchdogState *s) {
    if (OPAQUE_FALSE(!s || !s->apis)) return 0;
    const ResolvedApis *apis = s->apis;
    if (OPAQUE_FALSE(!apis->pthread_create ||
                     !apis->pthread_detach ||
                     !apis->nanosleep)) {
        return 0;
    }
    if (OPAQUE_FALSE(s->region_count == 0)) {
        // Nothing to watch — silently treat as a no-op success so
        // calling code stays branchless.
        return 1;
    }

    upobf_pthread_t tid = 0;
    int rc = apis->pthread_create(&tid, 0,
                                  upobf_watchdog_thread,
                                  (void *)s);
    if (rc != 0) return 0;

    // Detach so glibc reaps the thread on exit; we never join.
    apis->pthread_detach(tid);
    return 1;
}
