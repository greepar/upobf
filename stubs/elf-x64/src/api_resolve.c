// upobf ELF API table resolver — implementation (Phase G).
//
// Pipeline at runtime:
//
//   1. Read /proc/self/maps with raw openat/read syscalls until we
//      find the line whose path component ends with "/libc.so.6".
//      Take the *base* (lowest) mapping for that path so we land on
//      the file's ELF header in memory.
//
//   2. Parse the in-memory ELF header to find PT_DYNAMIC. Walk the
//      dynamic array to recover DT_GNU_HASH, DT_SYMTAB, DT_STRTAB,
//      and (optional) DT_HASH. glibc 2.34+ ships GNU hash; we treat
//      DT_HASH as a fallback only.
//
//   3. Decrypt the API string table (ChaCha20 with master_key /
//      master_nonce XOR FIXED_API_NONCE) into a private stack
//      scratch buffer. Validate the on-wire shape (count, offsets,
//      lengths). The on-wire bytes stay encrypted.
//
//   4. For each entry, NUL-terminate the function name in the
//      scratch buffer, run a GNU-hash lookup against libc's symbol
//      table, and store the resolved address in the right slot.
//
//   5. Wipe the scratch table before returning.
//
// Anchor strategy (vs. PE side):
//
//   The PE resolver uses GetModuleHandleW + GetProcAddress as
//   anchors that survive in the host's IAT. The ELF stub avoids the
//   PLT/GOT entirely so the packed binary's dynamic linkage stays
//   identical to the host's. The trade-off is that we have to
//   parse libc's hash tables ourselves, but it keeps the stub at
//   zero relocations and matches the existing direct-syscall
//   posture.

#include <stdint.h>
#include <stddef.h>

#include "api_resolve.h"
#include "stub_runtime.h"
#include "obfuscate.h"

// ---------------------------------------------------------------------
// External dependency: ChaCha20 (defined in chacha20.c).
// ---------------------------------------------------------------------
void upobf_chacha20_xor(uint8_t *buf, uint32_t len,
                        const uint8_t key[32],
                        const uint8_t nonce[12]);

// ---------------------------------------------------------------------
// ELF64 structs we need — duplicated locally to keep this TU
// independent of <elf.h> (the freestanding link doesn't pull libc
// headers).
// ---------------------------------------------------------------------

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} ElfW_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} ElfW_Phdr;

typedef struct {
    int64_t  d_tag;
    uint64_t d_un;          // d_val / d_ptr (we only need the bits)
} ElfW_Dyn;

typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} ElfW_Sym;

#define UPOBF_PT_DYNAMIC      2
#define UPOBF_DT_NULL         0
#define UPOBF_DT_HASH         4
#define UPOBF_DT_STRTAB       5
#define UPOBF_DT_SYMTAB       6
#define UPOBF_DT_STRSZ        10
#define UPOBF_DT_SYMENT       11
#define UPOBF_DT_GNU_HASH     0x6ffffef5

// ---------------------------------------------------------------------
// Tiny freestanding helpers (duplicated locally so the TU stays
// self-contained even if some of these already live in stub_runtime.h
// or another TU).
// ---------------------------------------------------------------------

static int up_strcmp_local(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return (int)(uint8_t)*a - (int)(uint8_t)*b;
}

static size_t up_strlen_local(const char *s) {
    size_t n = 0;
    while (s[n]) ++n;
    return n;
}

// Test if `hay` ends with `tail`.
static int up_endswith(const char *hay, size_t hay_len, const char *tail) {
    size_t tl = up_strlen_local(tail);
    if (tl > hay_len) return 0;
    const char *p = hay + (hay_len - tl);
    for (size_t i = 0; i < tl; i++) {
        if (p[i] != tail[i]) return 0;
    }
    return 1;
}

// Parse a hex prefix into a uint64. Stops at first non-hex char.
// Returns the parsed value via *out and returns the number of bytes
// consumed.
static size_t up_parse_hex(const char *p, size_t max, uint64_t *out) {
    uint64_t v = 0;
    size_t i = 0;
    while (i < max) {
        char c = p[i];
        uint8_t d;
        if (c >= '0' && c <= '9') d = (uint8_t)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (uint8_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (uint8_t)(c - 'A' + 10);
        else break;
        v = (v << 4) | d;
        ++i;
    }
    *out = v;
    return i;
}

// ---------------------------------------------------------------------
// /proc/self/maps walker.
//
// Each line:
//   addr-addr perms offset dev inode<spaces>path
//
// We accept only lines whose perms include 'r' and whose path ends in
// "/libc.so.6". We pick the lowest base address across all matching
// lines so the returned pointer hits the ELF header.
//
// Buffer note: we mmap a 64 KiB anonymous page rather than using a
// static BSS array. The packer wraps the entire stub .so into one
// R+X `.upobf0` PT_LOAD; static BSS lives there and writes would
// SIGSEGV. mmap handles this locally without touching writer
// invariants.
//
// `out_base` receives the lowest address seen.
// Returns 1 on success, 0 if not found.
// ---------------------------------------------------------------------

static int find_libc_base(uint64_t *out_base) {
    static const char proc_maps[] = "/proc/self/maps";
    int fd = upobf_openat_rdonly(proc_maps);
    if (fd < 0) return 0;

    enum { BUF_CAP = 65536 };
    uint8_t *buf = (uint8_t *)upobf_mmap(0, BUF_CAP,
                                         PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANONYMOUS,
                                         -1, 0);
    if (buf == MAP_FAILED) {
        upobf_close(fd);
        return 0;
    }

    size_t total = 0;
    for (;;) {
        if (total >= BUF_CAP) break;
        long n = upobf_read(fd, buf + total, BUF_CAP - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    upobf_close(fd);
    if (total == 0) {
        upobf_munmap(buf, BUF_CAP);
        return 0;
    }

    uint64_t lowest = 0;
    int found = 0;
    static const char tail[] = "/libc.so.6";

    // Walk lines.
    size_t i = 0;
    while (i < total) {
        size_t line_start = i;
        while (i < total && buf[i] != '\n') ++i;
        size_t line_end = i;
        if (i < total) ++i;  // skip '\n'

        // Parse: hex_start '-' hex_end ' ' perms ' ' ...
        uint64_t addr_start = 0, addr_end = 0;
        size_t off = line_start;
        size_t consumed = up_parse_hex((const char *)(buf + off),
                                       line_end - off, &addr_start);
        if (consumed == 0) continue;
        off += consumed;
        if (off >= line_end || buf[off] != '-') continue;
        ++off;
        consumed = up_parse_hex((const char *)(buf + off),
                                line_end - off, &addr_end);
        if (consumed == 0) continue;
        off += consumed;
        if (off >= line_end || buf[off] != ' ') continue;
        ++off;

        // perms field: 4 chars rwxp.
        if (line_end - off < 4) continue;
        if (buf[off] != 'r') continue;
        off += 4;

        // Skip remaining whitespace-delimited fields; the path is
        // whatever comes after the last run of spaces.
        // Scan back from line_end to find the path token.
        size_t path_start = line_end;
        // Skip trailing whitespace.
        while (path_start > off && buf[path_start - 1] == ' ') --path_start;
        size_t path_end = path_start;
        // Walk left until space or start of meaningful field.
        while (path_start > off && buf[path_start - 1] != ' ') {
            --path_start;
        }
        if (path_start >= path_end) continue;

        if (!up_endswith((const char *)(buf + path_start),
                         path_end - path_start, tail)) {
            continue;
        }

        if (!found || addr_start < lowest) {
            lowest = addr_start;
            found = 1;
        }
    }

    // Wipe + return the buffer.
    {
        volatile uint8_t *vb = (volatile uint8_t *)buf;
        for (size_t k = 0; k < total; k++) vb[k] = 0;
    }
    upobf_munmap(buf, BUF_CAP);

    if (!found) return 0;
    *out_base = lowest;
    return 1;
}

// ---------------------------------------------------------------------
// libc dynamic-table walker.
//
// Reads the ELF header at `base`, finds PT_DYNAMIC, then walks the
// d_tag/d_un array to fill `out_*` with the GNU hash table, the
// symbol table, and the string table. Pointers are absolute (base +
// d_ptr) since glibc tags d_ptr fields as pre-relocated.
// ---------------------------------------------------------------------

typedef struct {
    const uint32_t  *gnu_hash;     // DT_GNU_HASH
    const uint32_t  *sysv_hash;    // DT_HASH
    const ElfW_Sym  *symtab;       // DT_SYMTAB
    const char      *strtab;       // DT_STRTAB
    uint32_t         strsz;        // DT_STRSZ (best-effort cap)
} LibcTabs;

static int load_libc_tabs(uint64_t base, LibcTabs *out) {
    out->gnu_hash = 0;
    out->sysv_hash = 0;
    out->symtab = 0;
    out->strtab = 0;
    out->strsz = 0;

    const ElfW_Ehdr *eh = (const ElfW_Ehdr *)base;

    // Magic check.
    if (eh->e_ident[0] != 0x7f ||
        eh->e_ident[1] != 'E'  ||
        eh->e_ident[2] != 'L'  ||
        eh->e_ident[3] != 'F') {
        return 0;
    }

    if (eh->e_phentsize != sizeof(ElfW_Phdr)) return 0;
    if (eh->e_phnum == 0) return 0;

    const ElfW_Phdr *phdrs = (const ElfW_Phdr *)(base + eh->e_phoff);

    // libc is loaded by ld.so as ET_DYN, so PT_DYNAMIC's p_vaddr is
    // an offset from base. p_paddr is unused on Linux.
    const ElfW_Dyn *dyn = 0;
    for (uint32_t i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type == UPOBF_PT_DYNAMIC) {
            dyn = (const ElfW_Dyn *)(base + phdrs[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;

    for (; dyn->d_tag != UPOBF_DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case UPOBF_DT_GNU_HASH:
                out->gnu_hash = (const uint32_t *)dyn->d_un;
                break;
            case UPOBF_DT_HASH:
                out->sysv_hash = (const uint32_t *)dyn->d_un;
                break;
            case UPOBF_DT_SYMTAB:
                out->symtab = (const ElfW_Sym *)dyn->d_un;
                break;
            case UPOBF_DT_STRTAB:
                out->strtab = (const char *)dyn->d_un;
                break;
            case UPOBF_DT_STRSZ:
                if (dyn->d_un < 0x10000000ull) {
                    out->strsz = (uint32_t)dyn->d_un;
                }
                break;
            default:
                break;
        }
    }

    if (!out->symtab || !out->strtab) return 0;
    if (!out->gnu_hash && !out->sysv_hash) return 0;
    return 1;
}

// ---------------------------------------------------------------------
// GNU hash function. RFC: same as DT_GNU_HASH spec.
// ---------------------------------------------------------------------
static uint32_t gnu_hash_name(const char *name) {
    uint32_t h = 5381;
    for (const uint8_t *p = (const uint8_t *)name; *p; p++) {
        h = (h << 5) + h + *p;  // h * 33 + c
    }
    return h;
}

// GNU hash lookup. Returns absolute function address or 0 if not found.
//
// Layout of DT_GNU_HASH (all u32):
//   nbuckets, symoffset, bloom_size, bloom_shift,
//   bloom[bloom_size]   (uint64 on 64-bit ELF),
//   buckets[nbuckets],
//   chain[]             (indexed by symhash >> 1, see below)
static uint64_t gnu_hash_lookup(const LibcTabs *t,
                                uint64_t base,
                                const char *name) {
    if (!t->gnu_hash) return 0;

    const uint32_t *gh = t->gnu_hash;
    uint32_t nbuckets    = gh[0];
    uint32_t symoffset   = gh[1];
    uint32_t bloom_size  = gh[2];
    uint32_t bloom_shift = gh[3];
    if (nbuckets == 0 || bloom_size == 0) return 0;

    const uint64_t *bloom = (const uint64_t *)(gh + 4);
    const uint32_t *buckets = (const uint32_t *)(bloom + bloom_size);
    const uint32_t *chain = buckets + nbuckets;

    uint32_t namehash = gnu_hash_name(name);

    // Bloom filter — quick reject.
    uint64_t word = bloom[(namehash / 64) % bloom_size];
    uint64_t mask = (1ull << (namehash % 64)) |
                    (1ull << ((namehash >> bloom_shift) % 64));
    if ((word & mask) != mask) return 0;

    uint32_t sym_idx = buckets[namehash % nbuckets];
    if (sym_idx < symoffset) return 0;

    for (;;) {
        uint32_t hashval = chain[sym_idx - symoffset];
        if (((hashval ^ namehash) >> 1) == 0) {
            const ElfW_Sym *sym = &t->symtab[sym_idx];
            const char *symname = t->strtab + sym->st_name;
            if (up_strcmp_local(symname, name) == 0 &&
                sym->st_value != 0) {
                return base + sym->st_value;
            }
        }
        if (hashval & 1) break;  // end of chain
        sym_idx++;
    }
    return 0;
}

// SysV (DT_HASH) fallback. Layout:
//   nbuckets, nchain, buckets[nbuckets], chain[nchain]
//
// Used only when libc was built without GNU hash. Practically never
// reached on modern glibc.
static uint64_t sysv_hash_lookup(const LibcTabs *t,
                                 uint64_t base,
                                 const char *name) {
    if (!t->sysv_hash) return 0;

    const uint32_t *h = t->sysv_hash;
    uint32_t nbuckets = h[0];
    uint32_t nchain   = h[1];
    if (nbuckets == 0) return 0;
    const uint32_t *buckets = h + 2;
    const uint32_t *chain   = buckets + nbuckets;

    // Standard SysV ELF hash.
    uint32_t hh = 0;
    for (const uint8_t *p = (const uint8_t *)name; *p; p++) {
        hh = (hh << 4) + *p;
        uint32_t g = hh & 0xf0000000u;
        if (g) hh ^= g >> 24;
        hh &= ~g;
    }

    for (uint32_t i = buckets[hh % nbuckets]; i != 0 && i < nchain; i = chain[i]) {
        const ElfW_Sym *sym = &t->symtab[i];
        const char *symname = t->strtab + sym->st_name;
        if (up_strcmp_local(symname, name) == 0 && sym->st_value != 0) {
            return base + sym->st_value;
        }
    }
    return 0;
}

static uint64_t libc_lookup(const LibcTabs *t, uint64_t base, const char *name) {
    uint64_t addr = gnu_hash_lookup(t, base, name);
    if (addr) return addr;
    return sysv_hash_lookup(t, base, name);
}

// XOR two 12-byte nonces.
static inline void derive_nonce_local(uint8_t out[12],
                                      const uint8_t a[12],
                                      const uint8_t b[12]) {
    for (int i = 0; i < 12; i++) out[i] = a[i] ^ b[i];
}

static inline uint16_t le_u16(const uint8_t *base, uint32_t at, uint32_t end) {
    if (at + 2 > end) return 0;
    return (uint16_t)base[at] | ((uint16_t)base[at + 1] << 8);
}
static inline uint32_t le_u32(const uint8_t *base, uint32_t at, uint32_t end) {
    if (at + 4 > end) return 0;
    return  (uint32_t)base[at]
         | ((uint32_t)base[at + 1] << 8)
         | ((uint32_t)base[at + 2] << 16)
         | ((uint32_t)base[at + 3] << 24);
}

static void up_secure_zero_local(void *dst, uint32_t n) {
    volatile uint8_t *d = (volatile uint8_t *)dst;
    for (uint32_t i = 0; i < n; i++) d[i] = 0;
}
static void up_memcpy_local(void *dst, const void *src, uint32_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint32_t i = 0; i < n; i++) d[i] = s[i];
}

// ---------------------------------------------------------------------
// Public resolver.
// ---------------------------------------------------------------------

int upobf_resolve_apis(const PayloadHeader *ph, ResolvedApis *out) {
    if (OPAQUE_FALSE(!ph || !out)) return 0;
    if (OPAQUE_FALSE(ph->api_table_size == 0)) return 0;
    if (OPAQUE_FALSE(ph->api_table_size > UPOBF_MAX_API_TABLE_SIZE)) return 0;

    // Find libc base + dynamic tables.
    uint64_t libc_base = 0;
    if (!find_libc_base(&libc_base)) return 0;

    LibcTabs t;
    if (!load_libc_tabs(libc_base, &t)) return 0;

    // Decrypt API string table into a stack scratch buffer.
    #define UPOBF_RESOLVE_TBL_CAP 1024u
    if (OPAQUE_FALSE(ph->api_table_size > UPOBF_RESOLVE_TBL_CAP)) return 0;
    uint8_t tbl[UPOBF_RESOLVE_TBL_CAP];
    {
        const uint8_t *src = (const uint8_t *)ph + ph->api_table_offset;
        up_memcpy_local(tbl, src, ph->api_table_size);
    }
    {
        uint8_t nonce[12];
        uint8_t fixed_api_nonce[12];
        upobf_fixed_api_nonce_get(fixed_api_nonce);
        derive_nonce_local(nonce, ph->master_nonce, fixed_api_nonce);
        upobf_chacha20_xor(tbl, ph->api_table_size, ph->master_key, nonce);
    }

    int ok = 0;
    do {
        uint32_t table_end = ph->api_table_size;
        uint32_t count = le_u32(tbl, 0, table_end);
        if (count != UPOBF_API_COUNT) break;

        const uint32_t entries_off = 4u;
        const uint32_t entry_size  = 8u;
        if (entries_off + count * entry_size > table_end) break;

        void *slots[UPOBF_API_COUNT] = { 0 };

        int all_resolved = 1;
        for (uint32_t i = 0; i < count; i++) {
            uint32_t base = entries_off + i * entry_size;
            uint16_t mod_off = le_u16(tbl, base + 0, table_end);
            uint16_t fn_off  = le_u16(tbl, base + 2, table_end);
            uint16_t mod_len = le_u16(tbl, base + 4, table_end);
            uint16_t fn_len  = le_u16(tbl, base + 6, table_end);

            // We don't actually care about the module name at lookup
            // time — we already located libc — but we still validate
            // its bounds so a malformed table can't pass.
            if ((uint32_t)mod_off + mod_len > table_end) { all_resolved = 0; break; }
            if ((uint32_t)fn_off  + fn_len  > table_end) { all_resolved = 0; break; }
            if (mod_len >= 64 || fn_len >= 96) { all_resolved = 0; break; }

            char fn_name[96];
            up_memcpy_local(fn_name, tbl + fn_off, fn_len);
            fn_name[fn_len] = 0;

            uint64_t addr = libc_lookup(&t, libc_base, fn_name);

            up_secure_zero_local(fn_name, sizeof(fn_name));

            if (!addr) { all_resolved = 0; break; }
            slots[i] = (void *)(uintptr_t)addr;
        }

        if (!all_resolved) break;

        out->pthread_create = (PFN_pthread_create) slots[UPOBF_API_PTHREAD_CREATE];
        out->pthread_detach = (PFN_pthread_detach) slots[UPOBF_API_PTHREAD_DETACH];
        out->nanosleep      = (PFN_nanosleep)      slots[UPOBF_API_NANOSLEEP];
        out->clock_gettime  = (PFN_clock_gettime)  slots[UPOBF_API_CLOCK_GETTIME];
        out->mmap           = (PFN_mmap)           slots[UPOBF_API_MMAP];
        out->mprotect       = (PFN_mprotect)       slots[UPOBF_API_MPROTECT];
        out->munmap         = (PFN_munmap)         slots[UPOBF_API_MUNMAP];
        out->prctl          = (PFN_prctl)          slots[UPOBF_API_PRCTL];

        ok = 1;
    } while (0);

    up_secure_zero_local(tbl, ph->api_table_size);
    return ok;
}
