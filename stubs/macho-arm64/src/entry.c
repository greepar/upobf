// upobf macOS arm64 stub — entry trampoline + stub_init.
//
// This is the main entry point for the macOS arm64 stub. The packer
// rewrites LC_MAIN.entryoff to point at `_upobf_entry_trampoline`,
// which:
//   1. Saves x0 (mach_header ptr from dyld) and lr.
//   2. Calls _upobf_stub_init (decompresses all chunks).
//   3. Restores x0 and lr.
//   4. Jumps to the original entry point.
//
// Key differences from ELF x64:
//   - No raw syscalls; all system services via libSystem (resolved
//     at runtime by api_resolve.c).
//   - MAP_JIT + pthread_jit_write_protect_np for W^X on Apple Silicon.
//   - arm64 far jump: ldr x16, [pc, #imm]; br x16 (B/BL only ±128MB).
//   - 16 KB page size.
//   - dyld passes mach_header* in x0 on entry.

#include <stdint.h>
#include <stddef.h>

#include "stub_runtime.h"
#include "payload.h"
#include "api_resolve.h"
#include "watchdog.h"

// --- Forward decls for crypto/compression/filter TUs --------------------

// chacha20.c
void upobf_chacha20_xor(uint8_t *buf, uint32_t len,
                        const uint8_t key[32],
                        const uint8_t nonce[12]);

// lzma_dec.c
int upobf_lzma_decompress_alone(const uint8_t *src, uint32_t src_len,
                                uint8_t *dst, uint32_t dst_capacity,
                                uint32_t *out_dst_size,
                                void *(*alloc_fn)(void *user, uint32_t),
                                void  (*free_fn)(void *user, void *),
                                void  *user);

// bcj_arm64.c
void upobf_bcj_arm64_backward(uint8_t *buf, uint32_t len, uint32_t base);

// --- LZMA arena allocator -----------------------------------------------

typedef struct {
    uint8_t *base;
    uint32_t cursor;
    uint32_t capacity;
} LzmaArena;

static void *lzma_arena_alloc(void *user, uint32_t size) {
    LzmaArena *a = (LzmaArena *)user;
    a->cursor = (a->cursor + 15u) & ~15u;
    if (a->cursor + size > a->capacity) return 0;
    void *p = a->base + a->cursor;
    a->cursor += size;
    return p;
}

static void lzma_arena_free(void *user, void *p) {
    (void)user; (void)p;
}

// --- Packer-fixed-up data slots -----------------------------------------
//
// The packer patches these at embed time. Sentinels ensure the stub
// fails cleanly if the packer didn't fix them up.

__attribute__((aligned(16)))
volatile uint64_t g_payload_vaddr = 0xDEADBEEFCAFEBABEull;

__attribute__((aligned(16)))
volatile uint64_t g_image_base_rva = 0xDEADBEEF00000000ull;

__attribute__((aligned(16)))
volatile uint8_t g_image_base_anchor = 0;

// Original LC_MAIN.entryoff (relative to __TEXT vmaddr = mach_header).
__attribute__((aligned(16)))
volatile uint64_t g_original_entryoff = 0xDEADBEEFE0000001ull;

// GOT RVA slots: the packer writes the RVA of the host binary's GOT
// entries for mmap/mprotect/munmap here. At runtime, the stub reads
// the already-resolved function pointer from image_base + got_rva.
// Sentinel 0 means "not available".
__attribute__((aligned(16)))
volatile uint64_t g_got_mmap_rva = 0;

__attribute__((aligned(16)))
volatile uint64_t g_got_mprotect_rva = 0;

__attribute__((aligned(16)))
volatile uint64_t g_got_munmap_rva = 0;

// --- Resolved API function pointers (filled by libSystem bootstrap) -----
// We need mmap/mprotect/munmap + pthread_jit_write_protect_np before
// Phase G runs. These are resolved via a minimal bootstrap that uses
// the dyld anchor symbol.

// dyld API anchor — this is the ONLY external symbol the stub imports.
// dyld resolves it at load time, giving us access to the dyld image API.
extern uint32_t _dyld_image_count(void);
extern const void *_dyld_get_image_header(uint32_t image_index);
extern const char *_dyld_get_image_name(uint32_t image_index);
extern intptr_t _dyld_get_image_vmaddr_slide(uint32_t image_index);

// --- libSystem bootstrap (minimal, before Phase G) ----------------------
// We resolve mmap/mprotect/munmap/pthread_jit_write_protect_np from
// libSystem using the export trie. This is needed for the decompression
// loop itself.

// Forward decl — implemented in api_resolve.c
void *upobf_resolve_symbol_from_image(uint32_t image_idx, const char *name);

// NOTE: s_mmap/s_mprotect/s_munmap/s_jit_wp are NO LONGER static globals.
// They are passed as parameters or used as locals in upobf_stub_init()
// to avoid writing to the stub's __DATA segment (which is mapped R-X
// when embedded as a flat blob in __UPOBF0).

// bootstrap_libsystem is only used for Phase G (watchdog) after the
// initial decompression. It writes to a caller-provided struct.
typedef struct {
    PFN_mmap mmap;
    PFN_mprotect mprotect;
    PFN_munmap munmap;
    PFN_pthread_jit_write_protect_np jit_wp;
} BootstrapApis;

static int bootstrap_libsystem(BootstrapApis *out) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        // Look for libSystem.B.dylib
        int found = 0;
        for (const char *p = name; *p; p++) {
            if (p[0] == 'l' && p[1] == 'i' && p[2] == 'b' &&
                p[3] == 'S' && p[4] == 'y' && p[5] == 's' &&
                p[6] == 't' && p[7] == 'e' && p[8] == 'm') {
                found = 1;
                break;
            }
        }
        if (!found) continue;

        out->mmap = (PFN_mmap)upobf_resolve_symbol_from_image(i, "_mmap");
        out->mprotect = (PFN_mprotect)upobf_resolve_symbol_from_image(i, "_mprotect");
        out->munmap = (PFN_munmap)upobf_resolve_symbol_from_image(i, "_munmap");
        out->jit_wp = (PFN_pthread_jit_write_protect_np)
            upobf_resolve_symbol_from_image(i, "_pthread_jit_write_protect_np");

        if (out->mmap && out->mprotect && out->munmap) return 1;
    }
    return 0;
}

// --- Decode pipeline ----------------------------------------------------

static int decode_chunk(const ChunkEntry *ce, const PayloadHeader *ph,
                        uint8_t *target_va,
                        uint8_t *scratch, size_t scratch_len,
                        LzmaArena *arena) {
    if (ce->data_size > scratch_len) return -1;

    const uint8_t *enc =
        (const uint8_t *)ph + ph->data_offset + ce->data_offset;

    // Step 1: copy ciphertext into scratch.
    upobf_memcpy(scratch, enc, ce->data_size);

    // Step 2: ChaCha20 decrypt.
    if (ce->flags & UPOBF_FLAG_CHACHA20) {
        uint8_t nonce[12];
        for (int i = 0; i < 12; i++) {
            nonce[i] = ph->master_nonce[i] ^ ce->sub_nonce[i];
        }
        upobf_chacha20_xor(scratch, ce->data_size, ph->master_key, nonce);
    }

    // Step 3: LZMA decompress.
    if (ce->flags & UPOBF_FLAG_LZMA) {
        uint32_t produced = 0;
        arena->cursor = 0;
        int rc = upobf_lzma_decompress_alone(
            scratch, ce->data_size,
            target_va, ce->virtual_size, &produced,
            lzma_arena_alloc, lzma_arena_free, arena);
        if (rc != 0 || produced != ce->virtual_size) return -2;
    } else {
        if (ce->data_size != ce->virtual_size) return -3;
        upobf_memcpy(target_va, scratch, ce->data_size);
    }

    // Step 4: BCJ arm64 reverse filter.
    if (ce->flags & UPOBF_FLAG_BCJ_ARM64) {
        upobf_bcj_arm64_backward(target_va, ce->virtual_size, ce->bcj_base);
    }

    return 0;
}

// --- Page protection helpers (via resolved libSystem) --------------------

static int protect_range(PFN_mprotect fn_mprotect, uint8_t *va, size_t len, int prot) {
    if (!fn_mprotect) return -1;
    uint64_t base = (uint64_t)va & UPOBF_PAGE_MASK;
    uint64_t end  = ((uint64_t)va + len + UPOBF_PAGE_SIZE - 1) & UPOBF_PAGE_MASK;
    return fn_mprotect((void *)base, (size_t)(end - base), prot);
}

// --- Main stub init -----------------------------------------------------

void upobf_stub_init(void);

__attribute__((used, visibility("default")))
void upobf_stub_init(void) {
    // Check sentinels FIRST — before calling any external functions.
    // If the packer didn't fix up our slots, bail immediately.
    // This avoids calling dyld APIs (which require lazy binding that
    // doesn't work when the stub is embedded as a raw blob).
    uint64_t anchor_rva = g_image_base_rva;
    if (anchor_rva == 0xDEADBEEF00000000ull) return;

    uint64_t pl_rva = g_payload_vaddr;
    if (pl_rva == 0xDEADBEEFCAFEBABEull || pl_rva == 0) return;

    // Recover image base using the anchor trick.
    uint64_t anchor_va = (uint64_t)&g_image_base_anchor;
    uint64_t image_base = anchor_va - anchor_rva;

    // Resolve mmap/mprotect/munmap from host's GOT (already resolved by dyld).
    // The packer patched the GOT RVAs into our slots.
    // Use stack-local function pointers to avoid writing to __DATA.
    if (g_got_mmap_rva == 0 || g_got_mprotect_rva == 0 || g_got_munmap_rva == 0)
        return;

    PFN_mmap local_mmap = *(PFN_mmap *)(image_base + g_got_mmap_rva);
    PFN_mprotect local_mprotect = *(PFN_mprotect *)(image_base + g_got_mprotect_rva);
    PFN_munmap local_munmap = *(PFN_munmap *)(image_base + g_got_munmap_rva);

    if (!local_mmap || !local_mprotect || !local_munmap) return;

    const PayloadHeader *ph = (const PayloadHeader *)(pl_rva + image_base);
    if (ph->magic != UPOBF_PAYLOAD_MAGIC ||
        ph->version != UPOBF_PAYLOAD_VERSION) {
        return;
    }
    if (ph->chunk_count > UPOBF_MAX_CHUNK_COUNT) return;

    const ChunkEntry *chunks =
        (const ChunkEntry *)((const uint8_t *)ph + ph->chunks_offset);

    // Find max data_size for scratch allocation.
    uint32_t max_data = 0;
    for (uint32_t i = 0; i < ph->chunk_count; i++) {
        if (chunks[i].data_size > max_data) max_data = chunks[i].data_size;
    }

    // Allocate scratch (MAP_JIT not needed here, just R+W anon).
    size_t scratch_len = (max_data + UPOBF_PAGE_SIZE - 1) & ~(UPOBF_PAGE_SIZE - 1);
    if (scratch_len == 0) scratch_len = UPOBF_PAGE_SIZE;
    void *scratch = local_mmap(0, scratch_len, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (scratch == MAP_FAILED) return;

    // Allocate LZMA arena.
    uint32_t arena_capacity = 0;
    for (uint32_t i = 0; i < ph->chunk_count; i++) {
        if (chunks[i].virtual_size > arena_capacity)
            arena_capacity = chunks[i].virtual_size;
    }
    arena_capacity += 256u * 1024u;
    size_t arena_len = (arena_capacity + UPOBF_PAGE_SIZE - 1) & ~(UPOBF_PAGE_SIZE - 1);
    void *arena_base = local_mmap(0, arena_len, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena_base == MAP_FAILED) {
        local_munmap(scratch, scratch_len);
        return;
    }
    LzmaArena arena = {
        .base = (uint8_t *)arena_base,
        .cursor = 0,
        .capacity = arena_capacity,
    };

    // Walk chunks: for each, make target writable, decode, restore prot.
    for (uint32_t i = 0; i < ph->chunk_count; i++) {
        const ChunkEntry *ce = &chunks[i];
        uint8_t *dst = (uint8_t *)image_base + ce->target_rva;

        // On Apple Silicon with hardened runtime, we need W^X dance:
        // 1. mprotect target to RW (drop X)
        // 2. Write data
        // 3. Restore original protection
        if (protect_range(local_mprotect, dst, ce->virtual_size, PROT_READ | PROT_WRITE) != 0) {
            continue;
        }

        if (decode_chunk(ce, ph, dst, (uint8_t *)scratch, scratch_len, &arena) != 0) {
            // Restore protection even on failure.
            protect_range(local_mprotect, dst, ce->virtual_size, (int)ce->original_protect);
            continue;
        }

        // Restore original protection.
        protect_range(local_mprotect, dst, ce->virtual_size, (int)ce->original_protect);
    }

    local_munmap(arena_base, arena_len);
    local_munmap(scratch, scratch_len);

    // Phase G: resolve full API table for watchdog.
    // NOTE: This requires dyld APIs (_dyld_image_count etc.) which are
    // resolved via lazy binding. When the stub is embedded as a raw blob,
    // lazy binding doesn't work (dyld_stub_binder is not available).
    // Skip watchdog until we implement GOT-based dyld API resolution.
#if 0
    ResolvedApis apis = {0};
    if (upobf_resolve_apis(ph, &apis)) {
        // Phase F: spawn watchdog.
        WatchdogRegion baselines[UPOBF_WATCHDOG_MAX_REGIONS];
        uint32_t baseline_count = 0;
        for (uint32_t i = 0; i < ph->chunk_count; i++) {
            if (baseline_count >= UPOBF_WATCHDOG_MAX_REGIONS) break;
            const ChunkEntry *ce = &chunks[i];
            const uint8_t *region = (const uint8_t *)image_base + ce->target_rva;
            baselines[baseline_count].ptr = region;
            baselines[baseline_count].len = ce->virtual_size;
            baselines[baseline_count].baseline_crc =
                upobf_crc32(region, ce->virtual_size, 0u);
            baseline_count++;
        }

        // Allocate heap for watchdog state.
        PFN_mmap wd_mmap = apis.mmap ? apis.mmap : local_mmap;
        size_t st_len = sizeof(WatchdogState);
        size_t api_len = sizeof(ResolvedApis);
        size_t total = (st_len + api_len + UPOBF_PAGE_SIZE - 1) & ~(UPOBF_PAGE_SIZE - 1);
        void *heap = wd_mmap(0, total, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (heap != MAP_FAILED) {
            ResolvedApis *apis_copy = (ResolvedApis *)heap;
            WatchdogState *ws = (WatchdogState *)((uint8_t *)heap + api_len);
            for (size_t k = 0; k < api_len; k++) {
                ((volatile uint8_t *)apis_copy)[k] = ((const uint8_t *)&apis)[k];
            }
            upobf_watchdog_seed_state(ws, apis_copy, baselines, baseline_count);
            (void)upobf_watchdog_start(ws);
        }

        // Wipe local baselines.
        volatile uint8_t *zb = (volatile uint8_t *)baselines;
        for (size_t k = 0; k < sizeof(baselines); k++) zb[k] = 0;
    }

    // Wipe local apis.
    volatile uint8_t *za = (volatile uint8_t *)&apis;
    for (size_t k = 0; k < sizeof(apis); k++) za[k] = 0;
#endif
}

// --- Entry trampoline (arm64) -------------------------------------------
//
// For LC_MAIN style entry, dyld calls us as:
//   main(int argc, char *argv[], char *envp[], char *apple[])
// So x0=argc, x1=argv, x2=envp, x3=apple. NOT mach_header!
//
// We must:
//   1. Save all 4 args + lr
//   2. Call upobf_stub_init (decompresses all chunks)
//   3. Restore all 4 args + lr
//   4. Compute original entry address using g_image_base_anchor trick
//   5. Jump to original entry with args intact

__attribute__((naked, used, visibility("default"), section("__TEXT,__stub_entry")))
void upobf_entry_trampoline(void) {
    __asm__ volatile (
        // Save x0-x3 (argc, argv, envp, apple) and lr.
        // Use 32 bytes: x0,x1 at [sp], x2,x3 at [sp+16], lr at [sp+32]
        "stp x0, x1, [sp, #-48]!\n\t"
        "stp x2, x3, [sp, #16]\n\t"
        "str lr, [sp, #32]\n\t"

        // Call upobf_stub_init.
        "bl _upobf_stub_init\n\t"

        // Restore args and lr.
        "ldr lr, [sp, #32]\n\t"
        "ldp x2, x3, [sp, #16]\n\t"
        "ldp x0, x1, [sp], #48\n\t"

        // Compute original entry address:
        //   image_base = &g_image_base_anchor - g_image_base_rva
        //   original_entry = image_base + g_original_entryoff
        // Use x16, x17 as scratch (intra-procedure-call scratch registers).
        "adrp x16, _g_image_base_anchor@PAGE\n\t"
        "add x16, x16, _g_image_base_anchor@PAGEOFF\n\t"  // x16 = &anchor (runtime)
        "adrp x17, _g_image_base_rva@PAGE\n\t"
        "ldr x17, [x17, _g_image_base_rva@PAGEOFF]\n\t"   // x17 = anchor_rva
        "sub x16, x16, x17\n\t"                            // x16 = image_base (runtime)
        "adrp x17, _g_original_entryoff@PAGE\n\t"
        "ldr x17, [x17, _g_original_entryoff@PAGEOFF]\n\t" // x17 = original_entryoff
        "add x16, x16, x17\n\t"                            // x16 = original entry VA
        "br x16\n\t"
    );
}
