// upobf macOS arm64 API resolver (Phase G).
//
// Resolves libSystem.B.dylib function pointers by:
//   1. Using _dyld_image_count / _dyld_get_image_header /
//      _dyld_get_image_name to enumerate loaded images.
//   2. Finding libSystem.B.dylib (or /usr/lib/system/ sub-dylibs).
//   3. Walking the LC_DYLD_EXPORTS_TRIE to resolve each function
//      by name.
//
// Unlike the ELF stub (which reads /proc/self/maps + walks GNU hash),
// macOS uses the dyld export trie — a compressed prefix tree encoding
// all exported symbols with their offsets.
//
// The stub links against _dyld_get_image_header as its single
// external symbol anchor, which forces dyld to resolve it and gives
// us the entry point into the dyld API set.

#ifndef UPOBF_API_RESOLVE_H
#define UPOBF_API_RESOLVE_H

#include <stdint.h>
#include <stddef.h>

#include "payload.h"
#include "stub_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

// --- API table slot indices are defined in payload.h --------------------
// (UPOBF_API_PTHREAD_CREATE, UPOBF_API_MMAP, etc.)

#define UPOBF_API_ANCHOR_COUNT 0u

// --- Resolved API table -------------------------------------------------

typedef struct ResolvedApis {
    PFN_pthread_create                pthread_create;    // [0]
    PFN_pthread_detach                pthread_detach;    // [1]
    PFN_nanosleep                     nanosleep;        // [2]
    PFN_mach_absolute_time            mach_absolute_time; // [3]
    PFN_mmap                          mmap;             // [4]
    PFN_mprotect                      mprotect;         // [5]
    PFN_pthread_jit_write_protect_np  jit_write_protect; // [6]
    PFN_munmap                        munmap;           // [7]
} ResolvedApis;

/// Resolve all APIs from libSystem via dyld image enumeration +
/// export trie walk. Returns 1 on success, 0 on failure.
int upobf_resolve_apis(const PayloadHeader *ph, ResolvedApis *out);

#ifdef __cplusplus
}
#endif

#endif // UPOBF_API_RESOLVE_H
