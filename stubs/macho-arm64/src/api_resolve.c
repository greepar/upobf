// upobf macOS arm64 API resolver — dyld image enumeration + export trie walk.
//
// Strategy:
//   1. Use _dyld_image_count / _dyld_get_image_header / _dyld_get_image_name
//      to find libSystem.B.dylib (or libsystem_*.dylib sub-libraries).
//   2. For each target image, locate LC_DYLD_EXPORTS_TRIE in its load commands.
//   3. Walk the export trie (compressed prefix tree) to resolve symbol names.
//
// The export trie format:
//   - Each node starts with a terminal size (ULEB128). If > 0, the node
//     is a terminal with flags (ULEB128) and offset (ULEB128).
//   - After the terminal info, child edges follow: count (u8), then for
//     each child: NUL-terminated edge label + child node offset (ULEB128).
//   - Matching is done by walking edges byte-by-byte from the root.

#include <stdint.h>
#include <stddef.h>

#include "stub_runtime.h"
#include "payload.h"
#include "api_resolve.h"

// --- dyld API imports (linked by dyld at load time) ---------------------
extern uint32_t _dyld_image_count(void);
extern const void *_dyld_get_image_header(uint32_t image_index);
extern const char *_dyld_get_image_name(uint32_t image_index);
extern intptr_t _dyld_get_image_vmaddr_slide(uint32_t image_index);

// --- Mach-O constants needed for in-memory parsing ----------------------
#define MH_MAGIC_64_VAL     0xFEEDFACF
#define LC_SEGMENT_64_VAL   0x19
#define LC_DYLD_EXPORTS_TRIE_VAL (0x33 | 0x80000000)
#define LC_SYMTAB_VAL       0x02

// --- ULEB128 decoder ----------------------------------------------------
static uint64_t read_uleb128(const uint8_t *p, const uint8_t *end, uint32_t *bytes_read) {
    uint64_t result = 0;
    uint32_t shift = 0;
    uint32_t count = 0;
    while (p < end) {
        uint8_t byte = *p++;
        count++;
        result |= ((uint64_t)(byte & 0x7F)) << shift;
        if ((byte & 0x80) == 0) break;
        shift += 7;
        if (shift >= 64) break;
    }
    *bytes_read = count;
    return result;
}

// --- String helpers (no libc) -------------------------------------------
static int str_ends_with(const char *str, const char *suffix) {
    const char *s = str;
    const char *f = suffix;
    // Find lengths.
    int slen = 0, flen = 0;
    while (s[slen]) slen++;
    while (f[flen]) flen++;
    if (flen > slen) return 0;
    for (int i = 0; i < flen; i++) {
        if (s[slen - flen + i] != f[i]) return 0;
    }
    return 1;
}

static int str_contains(const char *haystack, const char *needle) {
    for (const char *h = haystack; *h; h++) {
        const char *p = h;
        const char *n = needle;
        while (*n && *p == *n) { p++; n++; }
        if (!*n) return 1;
    }
    return 0;
}

static int str_eq(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
}

// --- Export trie lookup --------------------------------------------------
//
// Walks the export trie to find `symbol_name`. Returns the symbol's
// offset from the image base, or 0 on failure.
static uint64_t trie_lookup(const uint8_t *trie_start, uint32_t trie_size,
                            const char *symbol_name) {
    const uint8_t *p = trie_start;
    const uint8_t *end = trie_start + trie_size;
    const char *s = symbol_name;

    while (p < end) {
        // Read terminal info size.
        uint32_t term_bytes;
        uint64_t term_size = read_uleb128(p, end, &term_bytes);
        p += term_bytes;

        if (*s == '\0' && term_size != 0) {
            // We've matched the full symbol name and this is a terminal node.
            // Read flags and offset.
            uint32_t fb;
            uint64_t flags = read_uleb128(p, end, &fb);
            p += fb;
            uint32_t ob;
            uint64_t offset = read_uleb128(p, end, &ob);
            (void)flags;
            return offset;
        }

        // Skip terminal info if present.
        if (term_size != 0) {
            p += term_size - 0; // term_bytes already consumed the size itself
            // Actually we need to skip the terminal payload.
            // Re-read: the terminal payload is term_size bytes AFTER the size field.
            // We already advanced past the size field. The payload is term_size bytes.
            // But we already read flags+offset above only if *s=='\0'.
            // If *s != '\0', we need to skip term_size bytes.
            p = trie_start; // Reset — let's redo this properly.
            // Actually the standard approach: after reading term_size,
            // the terminal payload is the next term_size bytes.
            // Let's restart with a cleaner implementation.
            break;
        }

        // Read child count.
        if (p >= end) return 0;
        uint8_t child_count = *p++;

        // Search children for matching edge.
        int found = 0;
        for (uint8_t i = 0; i < child_count; i++) {
            // Edge label: NUL-terminated string.
            const char *edge = (const char *)p;
            while (p < end && *p != 0) p++;
            if (p >= end) return 0;
            p++; // skip NUL

            // Child node offset (ULEB128).
            uint32_t cb;
            uint64_t child_offset = read_uleb128(p, end, &cb);
            p += cb;

            // Check if edge matches current position in symbol_name.
            const char *e = edge;
            const char *ss = s;
            int match = 1;
            while (*e) {
                if (*ss != *e) { match = 0; break; }
                e++; ss++;
            }

            if (match) {
                // Advance symbol pointer and jump to child node.
                s = ss;
                p = trie_start + child_offset;
                found = 1;
                break;
            }
        }

        if (!found) return 0;
    }

    // Cleaner re-implementation of the trie walk (the above has a bug
    // in terminal skipping). Let's use a proper loop:
    return 0;
}

// Proper trie lookup implementation.
static uint64_t export_trie_lookup(const uint8_t *trie_start, uint32_t trie_size,
                                   const char *symbol_name) {
    if (!trie_start || trie_size == 0) return 0;

    const uint8_t *end = trie_start + trie_size;
    const uint8_t *node = trie_start;
    const char *s = symbol_name;

    while (node < end) {
        // Terminal info size.
        uint32_t term_bytes;
        uint64_t term_size = read_uleb128(node, end, &term_bytes);
        const uint8_t *after_term_size = node + term_bytes;

        if (*s == '\0') {
            // Full match — check if terminal.
            if (term_size == 0) return 0; // not exported
            const uint8_t *tp = after_term_size;
            uint32_t fb;
            uint64_t flags = read_uleb128(tp, end, &fb);
            tp += fb;
            (void)flags;
            uint32_t ob;
            uint64_t offset = read_uleb128(tp, end, &ob);
            return offset;
        }

        // Skip past terminal payload to reach children.
        const uint8_t *children_start = after_term_size + term_size;
        if (children_start >= end) return 0;

        uint8_t child_count = *children_start;
        const uint8_t *p = children_start + 1;

        int found = 0;
        for (uint8_t i = 0; i < child_count; i++) {
            // Edge label (NUL-terminated).
            const char *edge = (const char *)p;
            while (p < end && *p != 0) p++;
            if (p >= end) return 0;
            p++; // skip NUL

            // Child offset (ULEB128).
            uint32_t cb;
            uint64_t child_off = read_uleb128(p, end, &cb);
            p += cb;

            // Match edge against remaining symbol.
            const char *e = edge;
            const char *ss = s;
            int match = 1;
            while (*e) {
                if (*ss != *e) { match = 0; break; }
                e++; ss++;
            }

            if (match) {
                s = ss;
                node = trie_start + child_off;
                found = 1;
                break;
            }
        }

        if (!found) return 0;
    }

    return 0;
}

// --- Find export trie in a Mach-O image ---------------------------------
//
// Given a mach_header_64*, walk load commands to find LC_DYLD_EXPORTS_TRIE
// and return a pointer to the trie data + its size.
static int find_exports_trie(const uint8_t *header, intptr_t slide,
                             const uint8_t **out_trie, uint32_t *out_size) {
    // mach_header_64: magic(4) + cputype(4) + cpusubtype(4) + filetype(4)
    //                + ncmds(4) + sizeofcmds(4) + flags(4) + reserved(4) = 32
    uint32_t magic = *(const uint32_t *)header;
    if (magic != MH_MAGIC_64_VAL) return 0;

    uint32_t ncmds = *(const uint32_t *)(header + 16);
    const uint8_t *lc = header + 32; // past mach_header_64

    // We also need __LINKEDIT's file offset and vmaddr to translate
    // the trie's dataoff into a runtime pointer.
    uint64_t linkedit_vmaddr = 0;
    uint64_t linkedit_fileoff = 0;
    uint32_t trie_dataoff = 0;
    uint32_t trie_datasize = 0;

    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd = *(const uint32_t *)lc;
        uint32_t cmdsize = *(const uint32_t *)(lc + 4);

        if (cmd == LC_SEGMENT_64_VAL) {
            // segment_command_64: cmd(4)+cmdsize(4)+segname(16)+vmaddr(8)+vmsize(8)+fileoff(8)...
            const char *segname = (const char *)(lc + 8);
            if (segname[0] == '_' && segname[1] == '_' &&
                segname[2] == 'L' && segname[3] == 'I' &&
                segname[4] == 'N' && segname[5] == 'K' &&
                segname[6] == 'E' && segname[7] == 'D' &&
                segname[8] == 'I' && segname[9] == 'T') {
                linkedit_vmaddr = *(const uint64_t *)(lc + 24);
                linkedit_fileoff = *(const uint64_t *)(lc + 40);
            }
        } else if (cmd == LC_DYLD_EXPORTS_TRIE_VAL) {
            // linkedit_data_command: cmd(4)+cmdsize(4)+dataoff(4)+datasize(4)
            trie_dataoff = *(const uint32_t *)(lc + 8);
            trie_datasize = *(const uint32_t *)(lc + 12);
        }

        lc += cmdsize;
    }

    if (trie_dataoff == 0 || trie_datasize == 0 || linkedit_vmaddr == 0) return 0;

    // Runtime address of trie data:
    // trie_ptr = header + slide + linkedit_vmaddr - image_vmaddr + (trie_dataoff - linkedit_fileoff)
    // But since header IS at image_vmaddr + slide:
    // trie_ptr = (linkedit_vmaddr + slide) + (trie_dataoff - linkedit_fileoff)
    const uint8_t *linkedit_runtime = (const uint8_t *)(linkedit_vmaddr + slide);
    *out_trie = linkedit_runtime + (trie_dataoff - linkedit_fileoff);
    *out_size = trie_datasize;
    return 1;
}

// --- Public: resolve a single symbol from a specific image ---------------
void *upobf_resolve_symbol_from_image(uint32_t image_idx, const char *name) {
    const uint8_t *header = (const uint8_t *)_dyld_get_image_header(image_idx);
    intptr_t slide = _dyld_get_image_vmaddr_slide(image_idx);
    if (!header) return 0;

    const uint8_t *trie = 0;
    uint32_t trie_size = 0;
    if (!find_exports_trie(header, slide, &trie, &trie_size)) return 0;

    uint64_t offset = export_trie_lookup(trie, trie_size, name);
    if (offset == 0) return 0;

    // The offset is relative to the image's load address.
    return (void *)((uint64_t)header + offset);
}

// --- Find libSystem or sub-dylib by name --------------------------------
static int find_libsystem_image(uint32_t *out_idx) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (str_contains(name, "libSystem.B")) {
            *out_idx = i;
            return 1;
        }
    }
    // Fallback: look for libsystem_kernel or libsystem_pthread.
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (str_contains(name, "libsystem_")) {
            *out_idx = i;
            return 1;
        }
    }
    return 0;
}

// --- Resolve a symbol searching across libSystem + sub-dylibs -----------
static void *resolve_from_libsystem(const char *sym_name) {
    uint32_t count = _dyld_image_count();
    // First try libSystem.B.dylib directly.
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (str_contains(name, "libSystem.B") ||
            str_contains(name, "libsystem_kernel") ||
            str_contains(name, "libsystem_pthread") ||
            str_contains(name, "libsystem_platform") ||
            str_contains(name, "libsystem_c")) {
            void *p = upobf_resolve_symbol_from_image(i, sym_name);
            if (p) return p;
        }
    }
    return 0;
}

// --- Public: resolve full API table (Phase G) ----------------------------
int upobf_resolve_apis(const PayloadHeader *ph, ResolvedApis *out) {
    (void)ph; // API names are hardcoded for now (Phase G full uses encrypted table)

    out->pthread_create = (PFN_pthread_create)resolve_from_libsystem("_pthread_create");
    out->pthread_detach = (PFN_pthread_detach)resolve_from_libsystem("_pthread_detach");
    out->nanosleep = (PFN_nanosleep)resolve_from_libsystem("_nanosleep");
    out->mach_absolute_time = (PFN_mach_absolute_time)resolve_from_libsystem("_mach_absolute_time");
    out->mmap = (PFN_mmap)resolve_from_libsystem("_mmap");
    out->mprotect = (PFN_mprotect)resolve_from_libsystem("_mprotect");
    out->jit_write_protect = (PFN_pthread_jit_write_protect_np)
        resolve_from_libsystem("_pthread_jit_write_protect_np");
    out->munmap = (PFN_munmap)resolve_from_libsystem("_munmap");

    // Minimum required: mmap + mprotect + munmap + pthread_create.
    if (!out->mmap || !out->mprotect || !out->munmap || !out->pthread_create)
        return 0;

    return 1;
}
