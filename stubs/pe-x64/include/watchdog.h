// upobf background CRC32 integrity watchdog (Phase F).
//
// After the TLS callback finishes unpacking, it spawns a single
// background thread that periodically rechecks the CRC32 of every
// region the stub wrote. The thread:
//
//   - never exits the host process,
//   - never raises an exception,
//   - never calls anything other than the resolved Sleep / CRC32
//     helpers,
//   - folds any mismatch into a single volatile global instead of
//     reacting visibly. This keeps Phase F AV-friendly: a casual
//     dump-and-modify still produces a *running* program, but the
//     mismatch quietly perturbs a value an integrator can later
//     consume (e.g. as a watermark in licence-decision branches).
//
// The watchdog is opt-in via the regular Phase F wiring: entry.c
// calls `upobf_watchdog_start` after a successful unpack. Callers
// that don't want a watchdog thread (e.g. CLI tools, future
// alternative stubs) just don't call it.

#ifndef UPOBF_WATCHDOG_H
#define UPOBF_WATCHDOG_H

#include <stdint.h>

#include "api_resolve.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Maximum number of regions the watchdog will track. Sized to the
/// protocol's `UPOBF_MAX_CHUNK_COUNT`; one CRC slot per absorbed
/// chunk is the canonical layout.
#define UPOBF_WATCHDOG_MAX_REGIONS 64u

/// Period between consecutive scans. 30 s is low enough to catch a
/// patcher within a couple of minutes and high enough to be invisible
/// in CPU profiles.
#define UPOBF_WATCHDOG_INTERVAL_MS 30000u

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
/// from the `apis->VirtualAlloc` heap so it survives the TLS
/// callback returning.
typedef struct WatchdogState {
    const ResolvedApis *apis;
    /// Mismatch sink. The watchdog xors `current_crc ^ baseline_crc`
    /// into this field every time it observes a tamper. Lives inside
    /// the heap-allocated state because the freestanding stub policy
    /// rejects any writable globals (`.bss` / `.data`); using
    /// `const volatile` in `.rdata` would survive linkage but trap on
    /// the first write at runtime since `.rdata` is OS-loader-mapped
    /// read-only.
    volatile uint32_t   seed;
    uint32_t            region_count;
    WatchdogRegion      regions[UPOBF_WATCHDOG_MAX_REGIONS];
} WatchdogState;

/// Initialise the watchdog state in `s` with one region per chunk
/// already written by the TLS callback. `apis->VirtualProtect` /
/// `VirtualAlloc` etc. must be resolved before calling. Returns the
/// number of regions populated; the caller may then pass `s` to
/// [`upobf_watchdog_start`].
uint32_t upobf_watchdog_seed_state(WatchdogState           *s,
                                   const ResolvedApis      *apis,
                                   const WatchdogRegion    *baselines,
                                   uint32_t                 baseline_count);

/// Spawn the watchdog thread. Returns 1 on success, 0 if any of the
/// resolved APIs is missing or `CreateThread` fails. The state
/// struct must outlive the host process; the caller must not free
/// it. The returned thread handle is closed inside the caller (we
/// don't care about waiting on it).
int upobf_watchdog_start(WatchdogState *s);

#ifdef __cplusplus
}
#endif

#endif // UPOBF_WATCHDOG_H
