// upobf ELF API table resolver (Phase G).
//
// Resolves libc.so.6 function pointers by walking the dynamic linker
// state already in process memory. Equivalent of the PE side's
// `api_resolve.h` (`GetModuleHandleW` + `GetProcAddress` based
// resolver), adapted to ELF semantics:
//
//   1. Find libc.so.6's load base by reading /proc/self/maps with
//      raw syscalls (openat + read + close). No /proc/self/exe
//      shenanigans, no auxv parsing — just the line whose path ends
//      in "/libc.so.6".
//   2. Parse libc's program headers in-memory to find PT_DYNAMIC.
//   3. Walk the dynamic array to recover DT_GNU_HASH + DT_SYMTAB +
//      DT_STRTAB.
//   4. For every entry in the encrypted API table (decrypted in
//      place into a scratch buffer), look up the function name via
//      GNU hash (DT_HASH fallback if a future libc ships only sysv
//      hash, which is unlikely on glibc 2.34+).
//
// The resolved table is filled in by the stub's init_array callback
// before the watchdog spawns and before OEP redirect installs.

#ifndef UPOBF_API_RESOLVE_H
#define UPOBF_API_RESOLVE_H

#include <stdint.h>
#include <stddef.h>

#include "payload.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------
// Function-pointer typedefs for every resolved API. We lift just
// enough of the libc ABI to call each function — full libc headers
// are off the table because the stub is built freestanding.
// ---------------------------------------------------------------------

typedef long  upobf_pthread_t;        // pthread_t is 8 bytes on x86_64 glibc
typedef int   upobf_clockid_t;
typedef long  upobf_time_t;

struct upobf_timespec_t {
    upobf_time_t tv_sec;
    long         tv_nsec;
};

typedef int (*PFN_pthread_create)(
    upobf_pthread_t  *thread,
    const void       *attr,                 // pthread_attr_t* (NULL = default)
    void *(*start_routine)(void *),
    void             *arg);

typedef int  (*PFN_pthread_detach)(upobf_pthread_t thread);
typedef int  (*PFN_nanosleep)(const struct upobf_timespec_t *req,
                              struct upobf_timespec_t       *rem);
typedef int  (*PFN_clock_gettime)(upobf_clockid_t clk, struct upobf_timespec_t *tp);

typedef void *(*PFN_mmap)(void *addr, size_t length, int prot, int flags,
                          int fd, long offset);
typedef int   (*PFN_mprotect)(void *addr, size_t len, int prot);
typedef int   (*PFN_munmap)(void *addr, size_t length);
typedef int   (*PFN_prctl)(int option, unsigned long arg2, unsigned long arg3,
                           unsigned long arg4, unsigned long arg5);

/// Table of resolved function pointers, indexed by `UPOBF_API_*`.
/// All entries are non-NULL after a successful `upobf_resolve_apis`
/// call.
typedef struct ResolvedApis {
    PFN_pthread_create  pthread_create;   // [0]
    PFN_pthread_detach  pthread_detach;   // [1]
    PFN_nanosleep       nanosleep;        // [2]
    PFN_clock_gettime   clock_gettime;    // [3]
    PFN_mmap            mmap;             // [4]
    PFN_mprotect        mprotect;         // [5]
    PFN_munmap          munmap;           // [6]
    PFN_prctl           prctl;            // [7]
} ResolvedApis;

/// Decrypt the API string table sitting at
/// `(uint8_t*)ph + ph->api_table_offset` (in-place into a private
/// scratch buffer; the on-wire bytes stay encrypted), find libc.so.6
/// in process memory, walk its dynamic linkage, and resolve every
/// entry via GNU hash lookup.
///
/// Returns 1 on success, 0 if libc was not found, the table did not
/// decrypt to a sane shape, or any entry could not be resolved.
int upobf_resolve_apis(const PayloadHeader *ph, ResolvedApis *out);

#ifdef __cplusplus
}
#endif

#endif // UPOBF_API_RESOLVE_H
