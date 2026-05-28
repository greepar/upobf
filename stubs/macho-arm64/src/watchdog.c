// upobf macOS arm64 CRC32 watchdog (Phase F).
//
// Identical logic to the ELF version:
//   - Spawns a detached pthread.
//   - Every 30s, re-CRC32 all decoded regions.
//   - Mismatches are folded into a volatile seed (no crash, no signal).
//
// All API calls go through the resolved function pointers in
// WatchdogState.apis (from Phase G).

#include <stdint.h>
#include <stddef.h>

#include "stub_runtime.h"
#include "watchdog.h"

// --- CRC32 (IEEE 802.3, same as ELF/PE) ---------------------------------
uint32_t upobf_crc32(const uint8_t *data, uint32_t len, uint32_t init) {
    uint32_t crc = ~init;
    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320u;
            else
                crc >>= 1;
        }
    }
    return ~crc;
}

// --- Watchdog thread entry -----------------------------------------------
static void *watchdog_thread(void *arg) {
    WatchdogState *ws = (WatchdogState *)arg;
    const ResolvedApis *apis = ws->apis;

    struct upobf_timespec_t sleep_req;
    sleep_req.tv_sec = UPOBF_WATCHDOG_INTERVAL_S;
    sleep_req.tv_nsec = 0;

    for (;;) {
        if (apis->nanosleep) {
            apis->nanosleep(&sleep_req, 0);
        }

        for (uint32_t i = 0; i < ws->region_count; i++) {
            const WatchdogRegion *r = &ws->regions[i];
            uint32_t current = upobf_crc32(r->ptr, r->len, 0u);
            if (current != r->baseline_crc) {
                ws->seed ^= (current ^ r->baseline_crc);
            }
        }
    }

    return 0; // unreachable
}

// --- Seed state ----------------------------------------------------------
uint32_t upobf_watchdog_seed_state(WatchdogState        *s,
                                   const ResolvedApis   *apis,
                                   const WatchdogRegion *baselines,
                                   uint32_t              baseline_count) {
    s->apis = apis;
    s->seed = 0;
    s->region_count = 0;

    for (uint32_t i = 0; i < baseline_count && i < UPOBF_WATCHDOG_MAX_REGIONS; i++) {
        s->regions[i] = baselines[i];
        s->region_count++;
    }

    return s->region_count;
}

// --- Start watchdog thread -----------------------------------------------
int upobf_watchdog_start(WatchdogState *s) {
    if (!s->apis || !s->apis->pthread_create || !s->apis->pthread_detach)
        return 0;

    upobf_pthread_t tid = 0;
    int rc = s->apis->pthread_create(&tid, 0, watchdog_thread, s);
    if (rc != 0) return 0;

    s->apis->pthread_detach(tid);
    return 1;
}
