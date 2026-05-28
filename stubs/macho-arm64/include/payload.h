// upobf payload protocol (M4) — C structs.
//
// Mirrors `docs/protocol-m4.md`. Both the packer (Rust) and the stub
// (this directory) must agree on every byte of these layouts.
//
// IMPORTANT: All structs are emitted with #pragma pack(push, 1) so the
// compiler MUST NOT add hidden padding. Field offsets/sizes follow the
// protocol field list verbatim.
//
// NOTE on size discrepancy with protocol comments:
//   The protocol prose says "PayloadHeader 64 bytes" / "ChunkEntry 32
//   bytes" but the field list adds up to 84 / 40 respectively. We
//   implement the field list (it is the more concrete spec) and rely on
//   PayloadHeader.header_size at runtime rather than a hard-coded
//   constant. The packer must fill that field with `sizeof` of its own
//   matching struct definition.

#ifndef UPOBF_PAYLOAD_H
#define UPOBF_PAYLOAD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------
// Magic / version
// ---------------------------------------------------------------------
//
// Bytes 'U','P','O','B' read as a little-endian u32 = 0x42_4F_50_55.
#define UPOBF_PAYLOAD_MAGIC   ((uint32_t)0x42504F55u)
// Phase I bumped this from 1 to 2: the header layout grew by 80 bytes
// at the tail (oep_steal_len/oep_target_rva/oep_patch_rva + 64 bytes
// of stolen prologue + 8 reserved bytes). Older stubs reading a V2
// header would still see a valid magic and process chunks correctly,
// but they'd skip the OEP redirect — fail-safe enough that we don't
// require a hard mismatch error there, but the version field is the
// canonical place to gate new behaviour.
#define UPOBF_PAYLOAD_VERSION ((uint32_t)2u)

// ---------------------------------------------------------------------
// ChunkEntry.flags bits
// ---------------------------------------------------------------------
#define UPOBF_FLAG_BCJ_X86    ((uint32_t)1u << 0)
#define UPOBF_FLAG_LZMA       ((uint32_t)1u << 1)
#define UPOBF_FLAG_CHACHA20   ((uint32_t)1u << 2)
#define UPOBF_FLAG_BCJ_ARM64  ((uint32_t)1u << 3)

// ---------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------
#define UPOBF_MAX_CHUNK_COUNT     64u
#define UPOBF_MAX_API_TABLE_SIZE  4096u

// ---------------------------------------------------------------------
// API table indices (fixed order from the protocol).
//
// macOS arm64 flavour. The stub resolves libSystem.B.dylib APIs via
// dyld image enumeration + export trie walk. No raw syscalls (macOS
// forbids them). All 8 entries resolve at run time.
// ---------------------------------------------------------------------
enum {
    UPOBF_API_PTHREAD_CREATE = 0,  // F watchdog
    UPOBF_API_PTHREAD_DETACH = 1,  // F watchdog
    UPOBF_API_NANOSLEEP      = 2,  // F watchdog
    UPOBF_API_MACH_ABS_TIME  = 3,  // timing (mach_absolute_time)
    UPOBF_API_MMAP           = 4,  // decompression + OEP
    UPOBF_API_MPROTECT       = 5,  // decompression + OEP
    UPOBF_API_JIT_WRITE_PROT = 6,  // pthread_jit_write_protect_np
    UPOBF_API_MUNMAP         = 7,  // cleanup
    UPOBF_API_COUNT          = 8,
};

#define UPOBF_API_ANCHOR_COUNT 0u

// ---------------------------------------------------------------------
// Fixed nonce salt for the API string table.
//
// Per protocol-m4.md: ApiStringTable nonce = master_nonce XOR
// fixed_api_nonce, where fixed_api_nonce is the first 12 bytes of the
// ASCII string "upobf:apinonce".
//
// IMPORTANT: We never embed those 12 ASCII bytes anywhere as a
// contiguous string. The salt is reconstructed at runtime from a
// per-byte XOR mask so static `strings` over the stub bytes finds
// nothing matching `upobf:apinon`. The mask is arbitrary fixed
// nonsense; both halves are baked into the stub at compile time and
// xored together each invocation. Build-time multiplication of (mask,
// data) keeps both arrays free of the original ASCII pattern.
//
// Verified mask: chosen so neither `mask[]` nor `data[]` contains the
// substring "upobf" or any other ASCII run > 3 chars.
// ---------------------------------------------------------------------
#define UPOBF_FIXED_API_NONCE_MASK \
    { 0x37, 0xA1, 0x58, 0xF2, 0xC4, 0x6D, 0x82, 0x1B, 0x9E, 0x40, 0xE9, 0x73 }
// Each byte = ASCII 'u','p','o','b','f',':','a','p','i','n','o','n' XOR mask[i].
#define UPOBF_FIXED_API_NONCE_XOR  \
    { /* 'u'^37 */ 0x42, /* 'p'^A1 */ 0xD1, /* 'o'^58 */ 0x37, \
      /* 'b'^F2 */ 0x90, /* 'f'^C4 */ 0xA2, /* ':'^6D */ 0x57, \
      /* 'a'^82 */ 0xE3, /* 'p'^1B */ 0x6B, /* 'i'^9E */ 0xF7, \
      /* 'n'^40 */ 0x2E, /* 'o'^E9 */ 0x86, /* 'n'^73 */ 0x1D }

/// Reconstruct the 12-byte API nonce salt into `out`. Implementation
/// is provided as `static inline` so each caller gets its own copy and
/// no out-of-line `upobf_fixed_api_nonce` symbol exists in the stub.
static inline void upobf_fixed_api_nonce_get(uint8_t out[12]) {
    static const uint8_t mask[12] = UPOBF_FIXED_API_NONCE_MASK;
    static const uint8_t enc[12]  = UPOBF_FIXED_API_NONCE_XOR;
    for (int i = 0; i < 12; i++) out[i] = mask[i] ^ enc[i];
}

// ---------------------------------------------------------------------
// Phase I OEP-stealing constants
// ---------------------------------------------------------------------
//
// Maximum number of *encoded* trampoline bytes we ever store. The
// on-wire `PayloadHeader.oep_stolen_bytes` slot is sized to this
// constant; values > 64 are treated as "feature disabled" by the
// stub.
//
// Must match `OEP_STEAL_MAX` in `crates/upobf-pe/src/layout/oep_steal.rs`.
#define UPOBF_OEP_STEAL_MAX 64u

// Length of the absolute jump gadget the stub patches into the
// host's original OEP. Must match `OEP_PATCH_GADGET_LEN` on the
// packer side.
//
//   FF 25 00 00 00 00       jmp qword ptr [rip+0]   (6 bytes)
//   <8 bytes absolute VA>                            (8 bytes)
//
// = 14 bytes. The stolen prologue is always at least this long.
#define UPOBF_OEP_PATCH_GADGET_LEN 14u

// ---------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------

#pragma pack(push, 1)

typedef struct PayloadHeader {
    uint32_t magic;             // = UPOBF_PAYLOAD_MAGIC
    uint32_t version;           // = UPOBF_PAYLOAD_VERSION
    uint32_t header_size;       // = sizeof(PayloadHeader)
    uint32_t chunk_count;       // N
    uint32_t chunks_offset;     // bytes from start of payload to ChunkEntry[0]
    uint32_t api_table_offset;  // bytes from start of payload to ApiStringTable
    uint32_t api_table_size;    // bytes
    uint32_t data_offset;       // bytes from start of payload to ChunkData[0]
    uint32_t data_size;         // total bytes of ChunkData
    uint32_t flags;             // reserved (0)
    uint8_t  master_key[32];    // ChaCha20 256-bit master key
    uint8_t  master_nonce[12];  // ChaCha20 96-bit master nonce

    // ----- Phase I extension (V2) -----------------------------------
    //
    // OEP-stealing prologue. The stub redirects the original entry
    // point through a heap trampoline so a memory dump captures
    // `jmp <heap-VA>` at the OEP, which crashes when re-run from a
    // dumped PE on a fresh process.
    //
    //   oep_steal_len    : ORIGINAL bytes the packer overwrote with
    //                      0xCC int3 (= bytes the stub will patch
    //                      back with its 14-byte abs-jmp gadget).
    //                      0 disables the feature.
    //   oep_encoded_len  : LENGTH of `oep_stolen_bytes`, the
    //                      trampoline body. May exceed steal_len
    //                      because rel-call/jmp are rewritten to
    //                      absolute indirect form (16/14 bytes vs.
    //                      5/2 source bytes).
    //   oep_target_rva   : RVA at which the host's prologue starts.
    //                      The trampoline jumps back to
    //                      `target_rva + steal_len` after running.
    //   oep_patch_rva    : RVA where the stub writes the 14-byte
    //                      abs-jmp gadget. Same as `target_rva` for
    //                      basic OEP redirect.
    //   oep_stolen_bytes : the trampoline body, padded with 0xCC up
    //                      to UPOBF_OEP_STEAL_MAX (64). Stub copies
    //                      the leading `oep_encoded_len` bytes
    //                      verbatim, then appends a 14-byte
    //                      `jmp [rip+0]; .quad target_rva + steal_len`.
    uint32_t oep_steal_len;
    uint32_t oep_encoded_len;
    uint32_t oep_target_rva;
    uint32_t oep_patch_rva;
    uint8_t  oep_stolen_bytes[UPOBF_OEP_STEAL_MAX];
} PayloadHeader;

typedef struct ChunkEntry {
    uint32_t target_rva;        // where to write the decoded bytes (from ImageBase)
    uint32_t virtual_size;      // bytes to write
    uint32_t data_offset;       // bytes from PayloadHeader.data_offset
    uint32_t data_size;         // compressed+encrypted bytes
    uint32_t original_protect;  // PAGE_EXECUTE_READ / PAGE_READONLY / PAGE_READWRITE
    uint32_t bcj_base;          // base address used for BCJ filter
    uint32_t flags;             // bit0 = BCJ_X86, bit1 = LZMA, bit2 = ChaCha20
    uint8_t  sub_nonce[12];     // per-chunk nonce; ChaCha20 nonce = master_nonce XOR sub_nonce
} ChunkEntry;

typedef struct ApiEntry {
    uint16_t module_str_offset;   // bytes from start of ApiStringTable
    uint16_t function_str_offset; // bytes from start of ApiStringTable
    uint16_t module_str_len;
    uint16_t function_str_len;
} ApiEntry;

typedef struct ApiTableHeader {
    uint32_t count;
    // ApiEntry entries[count];
    // Then byte pool of strings.
} ApiTableHeader;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif // UPOBF_PAYLOAD_H
