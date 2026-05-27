// upobf ELF x64 stub — Linux freestanding (M2L baseline).
//
// Single-TU implementation deliberately keeps everything inlined or
// `static` so the compiled `.text` section ends up as one
// position-independent blob with no external symbol references that
// the upobf packer would need to fix up.
//
// Responsibilities (M2L scope — Phase G/E/F/I deferred to M4L):
//
//   1. Run as a `.init_array` callback before the host's main().
//   2. Locate the payload blob via a packer-fixed-up vaddr slot
//      (RIP-relative).
//   3. Validate magic / version of the payload header.
//   4. For each chunk: copy → ChaCha20 decrypt → LZMA decompress →
//      BCJ-x86 reverse → write to the target RVA after `mprotect(RW)`.
//   5. Restore the original mprotect bits.
//   6. Return; ld.so continues to the next .init_array entry, which
//      is the host's original first init.
//
// Anti-debug / OEP redirect / watchdog land in M4L. We embed empty
// hooks now so the entry layout stays stable.

#include <stdint.h>
#include <stddef.h>

#include "stub_runtime.h"
#include "payload.h"

// ---------------------------------------------------------------------
// Forward decls of the cross-platform crypto / compression / filter
// routines we link with at the .o stage. These are defined in their
// own TUs (chacha20.c / lzma_dec.c / bcj_x86.c) shared with the PE
// stub. Each routine is self-contained and avoids global state.
// ---------------------------------------------------------------------

// chacha20.c
void upobf_chacha20_xor(uint8_t *buf, uint32_t len,
                        const uint8_t key[32],
                        const uint8_t nonce[12]);

// lzma_dec.c — alone-format decoder. Signature mirrors PE side.
int upobf_lzma_decompress_alone(const uint8_t *src, uint32_t src_len,
                                uint8_t *dst, uint32_t dst_capacity,
                                uint32_t *out_dst_size);

// bcj_x86.c
void upobf_bcj_x86_backward(uint8_t *buf, uint32_t len, uint32_t base);

// ---------------------------------------------------------------------
// Packer-fixed-up data slot.
//
// The packer writes:
//   * `g_payload_vaddr`   = link-time vaddr of the payload header
//                           (slid by ld.so via R_X86_64_RELATIVE).
//   * `g_image_base_rva`  = RVA of `g_image_base_anchor` itself, so
//                           the stub can compute the runtime image
//                           base by `&g_image_base_anchor - rva`.
//
// Both slots are populated with sentinels at compile time so the
// stub fails cleanly when the packer didn't fix them up.
// ---------------------------------------------------------------------

// The packer fills these via byte patching in the stub blob (M3L).
__attribute__((aligned(16)))
volatile uint64_t g_payload_vaddr = 0xDEADBEEFCAFEBABEull;

__attribute__((aligned(16)))
volatile uint64_t g_image_base_rva = 0xDEADBEEF00000000ull;

// Anchor symbol used to derive the load slide at runtime. We take
// its address, subtract the static RVA the packer baked in, and the
// result is the load slide ld.so picked.
__attribute__((aligned(16)))
volatile uint8_t g_image_base_anchor = 0;

// ---------------------------------------------------------------------
// Decode pipeline
// ---------------------------------------------------------------------

static int decode_chunk(const ChunkEntry *ce,
                        const PayloadHeader *ph,
                        uint8_t *target_va,
                        uint8_t *scratch,
                        size_t scratch_len) {
    if (ce->data_size > scratch_len) return -1;

    // Working pointers into the encrypted blob.
    const uint8_t *enc =
        (const uint8_t *)ph + ph->data_offset + ce->data_offset;

    // Step 1: copy ciphertext into scratch.
    upobf_memcpy(scratch, enc, ce->data_size);

    // Step 2: ChaCha20 decrypt with derived nonce =
    // master_nonce XOR sub_nonce.
    if (ce->flags & UPOBF_FLAG_CHACHA20) {
        uint8_t nonce[12];
        for (int i = 0; i < 12; i++) {
            nonce[i] = ph->master_nonce[i] ^ ce->sub_nonce[i];
        }
        upobf_chacha20_xor(scratch, ce->data_size, ph->master_key, nonce);
    }

    // Step 3: LZMA decompress directly into target VA. The target
    // pages must be writable; the caller arranges that.
    if (ce->flags & UPOBF_FLAG_LZMA) {
        uint32_t produced = 0;
        int rc = upobf_lzma_decompress_alone(
            scratch, ce->data_size,
            target_va, ce->virtual_size, &produced);
        if (rc != 0 || produced != ce->virtual_size) return -2;
    } else {
        if (ce->data_size != ce->virtual_size) return -3;
        upobf_memcpy(target_va, scratch, ce->data_size);
    }

    // Step 4: BCJ x86 reverse.
    if (ce->flags & UPOBF_FLAG_BCJ_X86) {
        upobf_bcj_x86_backward(target_va, ce->virtual_size, ce->bcj_base);
    }

    return 0;
}

// ---------------------------------------------------------------------
// Page-protection helpers
// ---------------------------------------------------------------------

#define PAGE_SIZE 0x1000ull
#define PAGE_MASK (~(PAGE_SIZE - 1))

static int protect_range(uint8_t *va, size_t len, int prot) {
    uint64_t base = (uint64_t)va & PAGE_MASK;
    uint64_t end  = ((uint64_t)va + len + PAGE_SIZE - 1) & PAGE_MASK;
    return upobf_mprotect((void *)base, (size_t)(end - base), prot);
}

// ---------------------------------------------------------------------
// Init-array entry
//
// ld.so calls every entry in `.init_array` as a `void(int argc,
// char **argv, char **envp)` — but with a freestanding stub we
// can declare it `(void)` since we don't read those args.
// ---------------------------------------------------------------------

void upobf_stub_init(void);

// Force the symbol to be exported and pinned at the very start of
// the stub `.text` section so the packer's `stub_init_offset`
// stays at 0.
__attribute__((used, section(".text.upobf_init")))
void upobf_stub_init(void) {
    // Recover the load slide. The packer fixes up
    // `g_image_base_rva` with the link-time RVA of the
    // `g_image_base_anchor` byte; the difference between the
    // anchor's runtime VA and that RVA is the slide ld.so picked.
    uint64_t anchor_va  = (uint64_t)&g_image_base_anchor;
    uint64_t anchor_rva = g_image_base_rva;
    if (anchor_rva == 0xDEADBEEF00000000ull) {
        // Sentinel intact ⇒ packer didn't fix us up. Bail silently.
        return;
    }
    uint64_t image_base = anchor_va - anchor_rva;

    // Locate the payload via the packer-fixed vaddr slot. The slot
    // holds the *link-time* RVA of the payload header; we add the
    // load slide here. Sentinel is intentionally non-canonical so
    // failure is obvious.
    uint64_t pl_rva = g_payload_vaddr;
    if (pl_rva == 0xDEADBEEFCAFEBABEull || pl_rva == 0) {
        return;
    }

    const PayloadHeader *ph = (const PayloadHeader *)(pl_rva + image_base);
    if (ph->magic != UPOBF_PAYLOAD_MAGIC ||
        ph->version != UPOBF_PAYLOAD_VERSION) {
        return;
    }

    // Sanity-cap chunk count so a corrupted payload header can't
    // make us walk off the end of memory.
    if (ph->chunk_count > UPOBF_MAX_CHUNK_COUNT) {
        return;
    }

    // Allocate a scratch page big enough for the largest chunk's
    // ciphertext. Find the maximum data_size first.
    const ChunkEntry *chunks =
        (const ChunkEntry *)((const uint8_t *)ph + ph->chunks_offset);

    uint32_t max_data = 0;
    for (uint32_t i = 0; i < ph->chunk_count; i++) {
        if (chunks[i].data_size > max_data) max_data = chunks[i].data_size;
    }

    // Round up to a page; anonymous mmap.
    size_t scratch_len = (max_data + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    if (scratch_len == 0) scratch_len = PAGE_SIZE;
    void *scratch = upobf_mmap(0, scratch_len,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS,
                               -1, 0);
    if (scratch == MAP_FAILED) return;

    // Walk chunks.
    for (uint32_t i = 0; i < ph->chunk_count; i++) {
        const ChunkEntry *ce = &chunks[i];
        uint8_t *dst = (uint8_t *)image_base + ce->target_rva;

        // Make target writable.
        if (protect_range(dst, ce->virtual_size, PROT_READ | PROT_WRITE) != 0) {
            // mprotect failed — abort but keep the program runnable.
            // (Skipping the chunk leaves zeros at target_rva, which is
            //  what ld.so already mapped. Hosts that don't actually
            //  use this RVA will keep working; ones that do will
            //  crash later — failing fast here would be marginally
            //  better but obscures the diagnostic in production.)
            continue;
        }

        if (decode_chunk(ce, ph, dst, (uint8_t *)scratch, scratch_len) != 0) {
            // Same fail-soft posture.
            continue;
        }

        // Restore original protection.
        protect_range(dst, ce->virtual_size, (int)ce->original_protect);
    }

    upobf_munmap(scratch, scratch_len);
}
