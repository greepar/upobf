// upobf macOS arm64 stub runtime header — freestanding via libSystem.
//
// Unlike the Linux ELF stub which uses raw syscalls, macOS forbids
// direct syscall instructions. All system services go through
// libSystem.B.dylib. The stub resolves libSystem APIs at runtime
// via dyld image enumeration + export trie walking.
//
// This header provides:
//   - Type definitions matching macOS/arm64 ABI
//   - Function pointer typedefs for libSystem APIs
//   - Minimal libc-style helpers (memcpy, memset, memcmp)
//   - Constants for mmap/mprotect flags (macOS values)

#ifndef UPOBF_STUB_RUNTIME_H
#define UPOBF_STUB_RUNTIME_H

#include <stdint.h>
#include <stddef.h>

// --- macOS mmap / mprotect flags ----------------------------------------
// These match <sys/mman.h> on macOS.
#define PROT_NONE       0x00
#define PROT_READ       0x01
#define PROT_WRITE      0x02
#define PROT_EXEC       0x04

#define MAP_PRIVATE     0x0002
#define MAP_ANONYMOUS   0x1000  // macOS uses 0x1000, not 0x20 like Linux
#define MAP_JIT         0x0800  // Required for W^X on Apple Silicon
#define MAP_FAILED      ((void *)-1)

// --- Page size (arm64 macOS = 16 KB) ------------------------------------
#define UPOBF_PAGE_SIZE   0x4000ull
#define UPOBF_PAGE_MASK   (~(UPOBF_PAGE_SIZE - 1))

// --- Function pointer types for resolved libSystem APIs -----------------
// These are resolved at runtime by api_resolve.c via export trie walk.

typedef void *(*PFN_mmap)(void *addr, size_t length, int prot, int flags,
                          int fd, long offset);
typedef int   (*PFN_mprotect)(void *addr, size_t len, int prot);
typedef int   (*PFN_munmap)(void *addr, size_t length);

// pthread_jit_write_protect_np(int enabled):
//   enabled=1 → thread switches to execute-only (no write)
//   enabled=0 → thread switches to writable (no execute)
typedef void  (*PFN_pthread_jit_write_protect_np)(int enabled);

typedef long  upobf_pthread_t;  // pthread_t on macOS arm64 is a pointer (8 bytes)

typedef int (*PFN_pthread_create)(
    upobf_pthread_t *thread,
    const void      *attr,
    void *(*start_routine)(void *),
    void            *arg);
typedef int  (*PFN_pthread_detach)(upobf_pthread_t thread);

struct upobf_timespec_t {
    long tv_sec;
    long tv_nsec;
};

typedef int (*PFN_nanosleep)(const struct upobf_timespec_t *req,
                             struct upobf_timespec_t       *rem);
typedef uint64_t (*PFN_mach_absolute_time)(void);

// --- Minimal libc-style helpers (freestanding) --------------------------

static inline void *upobf_memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

static inline void *upobf_memset(void *dst, int c, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

static inline int upobf_memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *p = (const unsigned char *)a;
    const unsigned char *q = (const unsigned char *)b;
    while (n--) {
        if (*p != *q) return (int)*p - (int)*q;
        ++p; ++q;
    }
    return 0;
}

#endif // UPOBF_STUB_RUNTIME_H
