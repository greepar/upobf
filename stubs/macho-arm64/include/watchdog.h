// upobf background CRC32 integrity watchdog (Phase F) — macOS flavour.
//
// Identical logic to the ELF version: spawns a detached pthread that
// periodically CRC32-checks all decoded regions. Differences from ELF:
//   - Uses resolved pthread_create/pthread_detach/nanosleep from
//     libSystem (no raw syscalls).
//   - Same IEEE 802.3 polynomial, same 30s interval.

#ifndef UPOBF_WATCHDOG_H
#define UPOBF_WATCHDOG_H

#include <stdint.h>

#include "api_resolve.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UPOBF_WATCHDOG_MAX_REGIONS 64u
#define UPOBF_WATCHDOG_INTERVAL_NS 30000000000ull
#define UPOBF_WATCHDOG_INTERVAL_S  30u

typedef struct WatchdogRegion {
    const uint8_t *ptr;
    uint32_t       len;
    uint32_t       baseline_crc;
} WatchdogRegion;

typedef struct WatchdogState {
    const ResolvedApis *apis;
    volatile uint32_t   seed;
    uint32_t            region_count;
    WatchdogRegion      regions[UPOBF_WATCHDOG_MAX_REGIONS];
} WatchdogState;

uint32_t upobf_watchdog_seed_state(WatchdogState           *s,
                                   const ResolvedApis      *apis,
                                   const WatchdogRegion    *baselines,
                                   uint32_t                 baseline_count);

int upobf_watchdog_start(WatchdogState *s);

uint32_t upobf_crc32(const uint8_t *data, uint32_t len, uint32_t init);

#ifdef __cplusplus
}
#endif

#endif // UPOBF_WATCHDOG_H
