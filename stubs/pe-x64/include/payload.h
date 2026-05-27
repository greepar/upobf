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
#define UPOBF_PAYLOAD_VERSION ((uint32_t)1u)

// ---------------------------------------------------------------------
// ChunkEntry.flags bits
// ---------------------------------------------------------------------
#define UPOBF_FLAG_BCJ_X86  ((uint32_t)1u << 0)
#define UPOBF_FLAG_LZMA     ((uint32_t)1u << 1)
#define UPOBF_FLAG_CHACHA20 ((uint32_t)1u << 2)

// ---------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------
#define UPOBF_MAX_CHUNK_COUNT     64u
#define UPOBF_MAX_API_TABLE_SIZE  4096u

// ---------------------------------------------------------------------
// API table indices (fixed order from the protocol).
// ---------------------------------------------------------------------
enum {
    UPOBF_API_GET_MODULE_HANDLE_A = 0,
    UPOBF_API_LOAD_LIBRARY_A      = 1,
    UPOBF_API_GET_PROC_ADDRESS    = 2,
    UPOBF_API_VIRTUAL_PROTECT     = 3,
    UPOBF_API_VIRTUAL_ALLOC       = 4,
    UPOBF_API_VIRTUAL_FREE        = 5,
    UPOBF_API_COUNT               = 6,
};

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
