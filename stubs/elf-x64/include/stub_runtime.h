// upobf ELF x64 stub runtime header — Linux freestanding.
//
// Provides minimal type/define equivalents of <sys/types.h> and a
// few syscall wrappers used by the stub. We compile freestanding
// (-nostdlib -ffreestanding) and reach the kernel via the `syscall`
// instruction directly so libc isn't required.

#ifndef UPOBF_STUB_RUNTIME_H
#define UPOBF_STUB_RUNTIME_H

#include <stdint.h>
#include <stddef.h>

// --- Linux x86_64 syscall numbers (selected) ---------------------------
#define UPOBF_SYS_read         0
#define UPOBF_SYS_write        1
#define UPOBF_SYS_openat       257
#define UPOBF_SYS_close        3
#define UPOBF_SYS_mmap         9
#define UPOBF_SYS_mprotect     10
#define UPOBF_SYS_munmap       11
#define UPOBF_SYS_exit         60
#define UPOBF_SYS_ptrace       101
#define UPOBF_SYS_clock_gettime 228

// --- mmap / mprotect flags ---------------------------------------------
#define PROT_NONE       0x0
#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define PROT_EXEC       0x4

#define MAP_PRIVATE     0x02
#define MAP_ANONYMOUS   0x20
#define MAP_FAILED      ((void *)-1)

#define AT_FDCWD        -100
#define O_RDONLY        0

// --- ptrace requests ---------------------------------------------------
#define PTRACE_TRACEME 0

// --- Direct-syscall wrappers -------------------------------------------
//
// All wrappers live as `static inline` so each TU gets its own copy
// and there's no chance of accidental external linkage.

static inline long upobf_syscall0(long n) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(n)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long upobf_syscall1(long n, long a) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(n), "D"(a)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long upobf_syscall2(long n, long a, long b) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(n), "D"(a), "S"(b)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long upobf_syscall3(long n, long a, long b, long c) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(n), "D"(a), "S"(b), "d"(c)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long upobf_syscall4(long n, long a, long b, long c, long d) {
    long ret;
    register long r10 __asm__("r10") = d;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long upobf_syscall6(long n, long a, long b, long c,
                                  long d, long e, long f) {
    long ret;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8")  = e;
    register long r9 __asm__("r9")  = f;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(n), "D"(a), "S"(b), "d"(c),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline void *upobf_mmap(void *addr, size_t len, int prot,
                               int flags, int fd, long off) {
    long ret = upobf_syscall6(
        UPOBF_SYS_mmap,
        (long)addr, (long)len, (long)prot,
        (long)flags, (long)fd, off
    );
    return (void *)ret;
}

static inline int upobf_mprotect(void *addr, size_t len, int prot) {
    return (int)upobf_syscall3(
        UPOBF_SYS_mprotect,
        (long)addr, (long)len, (long)prot
    );
}

static inline int upobf_munmap(void *addr, size_t len) {
    return (int)upobf_syscall2(UPOBF_SYS_munmap, (long)addr, (long)len);
}

static inline long upobf_ptrace(long req, long pid, long addr, long data) {
    return upobf_syscall4(UPOBF_SYS_ptrace, req, pid, addr, data);
}

static inline int upobf_open_proc_status(void) {
    // openat(AT_FDCWD, "/proc/self/status", O_RDONLY)
    static const char path[] = "/proc/self/status";
    return (int)upobf_syscall3(UPOBF_SYS_openat, AT_FDCWD, (long)path, O_RDONLY);
}

// Generic openat(AT_FDCWD, path, O_RDONLY). Used by the API
// resolver (Phase G) to read /proc/self/maps without baking that
// exact string in this header.
static inline int upobf_openat_rdonly(const char *path) {
    return (int)upobf_syscall3(UPOBF_SYS_openat, AT_FDCWD, (long)path, O_RDONLY);
}

static inline long upobf_read(int fd, void *buf, size_t len) {
    return upobf_syscall3(UPOBF_SYS_read, fd, (long)buf, (long)len);
}

static inline int upobf_close(int fd) {
    return (int)upobf_syscall1(UPOBF_SYS_close, fd);
}

// --- Minimal libc-style helpers ----------------------------------------

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
