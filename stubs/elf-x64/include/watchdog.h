// upobf background CRC32 integrity watchdog (Phase F) — ELF flavour.
//
// After the .init_array stub finishes unpacking, it spawns a single
// background pthread that periodically rechecks the CRC32 of every
// region the stub wrote. The thread:
//
//   - never exits the host process,
//   - never raises a signal,
//   - never calls anything other than the resolved nanosleep / CRC32
//     helpers,
//   - folds any mismatch into a single volatile field instead of
//     reacting visibly. Casual dump-and-modify still produces a
//     *running* program; the mismatch quietly perturbs a value an
//     integrator could later consume.
//
// The watchdog is opt-in via the regular Phase F wiring: entry.c
// calls `upobf_watchdog_start` after a successful unpack + Phase G
// resolve.

#ifndef UPOBF_WATCHDOG_H
#define UPOBF_WATCHDOG_H

#include <stdint.h>

#include "api_resolve.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Maximum number of regions the watchdog will track. Sized to the
/// protocol's `UPOBF_MAX_CHUNK_COUNT`.
#define UPOBF_WATCHDOG_MAX_REGIONS 64u

/// Period between consecutive scans, expressed in nanoseconds for
/// `nanosleep`. 30 s mirrors the PE side; low enough to catch a
/// patcher within a couple of minutes, high enough to be invisible
/// in CPU profiles.
#define UPOBF_WATCHDOG_INTERVAL_NS 30000000000ull
#define UPOBF_WATCHDOG_INTERVAL_S  30u

/// One monitored region. `ptr` lives in the host's address space (not
/// inside the watchdog thread's heap), so the watchdog only reads it.
typedef struct WatchdogRegion {
    const uint8_t *ptr;
    uint32_t       len;
    uint32_t       baseline_crc;
} WatchdogRegion;

/// Boot-time configuration for the watchdog. The thread takes a
/// pointer to this struct and stays alive for the rest of the
/// process's lifetime; the struct itself is allocated by the caller
/// from the `apis->mmap` heap so it survives the .init_array
/// callback returning.
typedef struct WatchdogState {
    const ResolvedApis *apis;
    /// Mismatch sink. The watchdog xors `current_crc ^ baseline_crc`
    /// into this field every time it observes a tamper. Lives inside
    /// the heap-allocated state (the freestanding stub policy
    /// rejects writable globals).
    volatile uint32_t   seed;
    uint32_t            region_count;
    WatchdogRegion      regions[UPOBF_WATCHDOG_MAX_REGIONS];
} WatchdogState;

/// Initialise the watchdog state in `s` with one region per chunk
/// already written by the .init_array callback. Returns the number of
/// regions populated; the caller may then pass `s` to
/// [`upobf_watchdog_start`].
uint32_t upobf_watchdog_seed_state(WatchdogState           *s,
                                   const ResolvedApis      *apis,
                                   const WatchdogRegion    *baselines,
                                   uint32_t                 baseline_count);

/// Spawn the watchdog thread via `apis->pthread_create`. Returns 1 on
/// success, 0 if any of the resolved APIs is missing or
/// `pthread_create` fails. The state struct must outlive the host
/// process; the caller must not free it. The pthread is detached so
/// no join is needed and no thread handle leaks.
int upobf_watchdog_start(WatchdogState *s);

/// CRC32 helper. Identical polynomial to the PE side
/// (IEEE 802.3, init = ~0u, final XOR = ~0u). Lives in this TU so
/// the watchdog stays self-contained on the ELF side; the PE port
/// keeps its CRC in anti_debug.c.
uint32_t upobf_crc32(const uint8_t *data, uint32_t len, uint32_t init);

#ifdef __cplusplus
}
#endif

#endif // UPOBF_WATCHDOG_H
