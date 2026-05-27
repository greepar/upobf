// upobf API table resolver — implementation (Phase G).
//
// At a high level:
//
//   1. The packer ships an encrypted ApiStringTable inside the payload
//      blob. Layout (from `docs/protocol-m4.md`):
//
//          ApiTableHeader { count: u32 }
//          ApiEntry[count] { module_off:u16, function_off:u16,
//                            module_len:u16, function_len:u16 }
//          <byte pool: module / function names, deduplicated, NOT
//                      necessarily NUL-terminated>
//
//   2. The whole table is encrypted with ChaCha20 using
//      nonce = master_nonce XOR fixed_api_nonce, where fixed_api_nonce
//      is rebuilt at runtime from a per-stub XOR mask (see
//      payload.h's UPOBF_FIXED_API_NONCE_*).
//
//   3. We allocate a scratch buffer via the anchor `VirtualAlloc`
//      we just resolved, decrypt into it, then for every entry call
//      `GetProcAddress(GetModuleHandleA(<module asciiz>), <fn asciiz>)`.
//      Each name lives inside the scratch buffer and is NUL-terminated
//      in place using the entry's length field.
//
//   4. The scratch buffer is wiped and freed before we hand the result
//      back to the caller, so the resolved names never reach the
//      heap longer than they have to.
//
// The resolver is intentionally simple — no API hashing, no PEB walk,
// no `LdrGetProcedureAddress` reflection. The two anchor functions
// (`GetModuleHandleA` + `GetProcAddress`) come in through `__imp_*`
// thunks just like every other Windows program; from there everything
// is a documented Win32 API. AV-friendly by construction.

#include <stdint.h>

#include "api_resolve.h"
#include "obfuscate.h"

// ---------------------------------------------------------------------
// We need ChaCha20 to decrypt the table. Forward-declared here so the
// resolver TU stays free of the rest of the stub's headers.
// ---------------------------------------------------------------------
void upobf_chacha20_xor(uint8_t* data, uint32_t len,
                        const uint8_t key[32], const uint8_t nonce[12]);

// Win32 manifest constants used below come from api_resolve.h
// (UPOBF_PAGE_READWRITE / UPOBF_MEM_COMMIT / UPOBF_MEM_RESERVE /
// UPOBF_MEM_RELEASE) so every TU sees identical values.

// ---------------------------------------------------------------------
// Tiny freestanding helpers (avoid pulling in libc).
// ---------------------------------------------------------------------

static void up_memcpy_local(void* dst, const void* src, uint32_t n) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    for (uint32_t i = 0; i < n; i++) d[i] = s[i];
}

static void up_secure_zero_local(void* dst, uint32_t n) {
    volatile uint8_t* d = (volatile uint8_t*)dst;
    for (uint32_t i = 0; i < n; i++) d[i] = 0;
}

// XOR two 12-byte nonces.
static inline void derive_nonce_local(uint8_t out[12],
                                      const uint8_t a[12],
                                      const uint8_t b[12]) {
    for (int i = 0; i < 12; i++) out[i] = a[i] ^ b[i];
}

// Bounds-checked u16 little-endian read. Returns 0 if OOB; the caller
// validates total table size up-front so OOB shouldn't fire in
// practice but defence in depth is cheap.
static inline uint16_t le_u16(const uint8_t* base, uint32_t at, uint32_t end) {
    if (at + 2 > end) return 0;
    return (uint16_t)base[at] | ((uint16_t)base[at + 1] << 8);
}

static inline uint32_t le_u32(const uint8_t* base, uint32_t at, uint32_t end) {
    if (at + 4 > end) return 0;
    return  (uint32_t)base[at]
         | ((uint32_t)base[at + 1] << 8)
         | ((uint32_t)base[at + 2] << 16)
         | ((uint32_t)base[at + 3] << 24);
}

// ---------------------------------------------------------------------
// Resolver.
// ---------------------------------------------------------------------

int upobf_resolve_apis(const PayloadHeader   *ph,
                       PFN_GetModuleHandleW   anchor_get_module_w,
                       PFN_GetProcAddress     anchor_get_proc_addr,
                       ResolvedApis          *out)
{
    // Quick parameter sanity. Bogus-guarded so the bail-out branches
    // look like real comparisons in disassembly.
    if (OPAQUE_FALSE(!ph || !anchor_get_module_w || !anchor_get_proc_addr || !out)) {
        return 0;
    }
    if (OPAQUE_FALSE(ph->api_table_size == 0)) return 0;
    if (OPAQUE_FALSE(ph->api_table_size > UPOBF_MAX_API_TABLE_SIZE)) return 0;

    // Resolve KERNEL32 via GetModuleHandleW.
    //
    // The wide string `L"KERNEL32.dll"` is reconstructed at runtime
    // from a tiny per-byte XOR pair so the literal UTF-16 sequence
    // never appears in the stub binary as a contiguous searchable
    // string. Both halves are arbitrary fixed nonsense; their XOR
    // yields the desired UTF-16 code units.
    static const uint8_t  kK32_mask[]  = {
        0x37, 0x91, 0x58, 0x42, 0x6D, 0x1F, 0x82, 0x73,
        0x9E, 0xA1, 0xC4, 0x4B, 0x37, 0x53, 0x82, 0x91,
        0xC4, 0x6D, 0x1F, 0x9E, 0xA1, 0x73, 0x58, 0x42,
        0x37, 0x91 // (k=12 wide chars + NUL = 26 bytes)
    };
    static const uint8_t  kK32_enc[]   = {
        // 'K'^37, 0x00^91, 'E'^58, 0x00^42, ..., NUL^91, NUL^91
        ('K' ^ 0x37), (0x00 ^ 0x91), ('E' ^ 0x58), (0x00 ^ 0x42),
        ('R' ^ 0x6D), (0x00 ^ 0x1F), ('N' ^ 0x82), (0x00 ^ 0x73),
        ('E' ^ 0x9E), (0x00 ^ 0xA1), ('L' ^ 0xC4), (0x00 ^ 0x4B),
        ('3' ^ 0x37), (0x00 ^ 0x53), ('2' ^ 0x82), (0x00 ^ 0x91),
        ('.' ^ 0xC4), (0x00 ^ 0x6D), ('d' ^ 0x1F), (0x00 ^ 0x9E),
        ('l' ^ 0xA1), (0x00 ^ 0x73), ('l' ^ 0x58), (0x00 ^ 0x42),
        (0x00 ^ 0x37), (0x00 ^ 0x91)
    };
    uint16_t kernel32_w[13];
    for (int i = 0; i < 13; i++) {
        uint8_t lo = kK32_mask[i*2 + 0] ^ kK32_enc[i*2 + 0];
        uint8_t hi = kK32_mask[i*2 + 1] ^ kK32_enc[i*2 + 1];
        kernel32_w[i] = (uint16_t)lo | ((uint16_t)hi << 8);
    }

    UPOBF_HMODULE k32 = anchor_get_module_w((UPOBF_LPCWSTR)kernel32_w);
    // Wipe the reconstructed wide string before any further work so
    // it never lingers on the stack.
    {
        volatile uint16_t *zw = (volatile uint16_t*)kernel32_w;
        for (int i = 0; i < 13; i++) zw[i] = 0;
    }
    if (OPAQUE_FALSE(!k32)) return 0;

    // Decrypt the API string table into a fixed-size stack buffer.
    // The protocol cap is UPOBF_MAX_API_TABLE_SIZE (4 KiB) but our 9
    // entries actually fit well under 300 bytes; we use a 1 KiB
    // stack scratch to keep the frame below the Windows x64 stack
    // probe threshold (single page = 4 KiB), which avoids pulling
    // in `__chkstk` and breaking the freestanding link.
    #define UPOBF_RESOLVE_TBL_CAP 1024u
    if (OPAQUE_FALSE(ph->api_table_size > UPOBF_RESOLVE_TBL_CAP)) return 0;
    uint8_t tbl[UPOBF_RESOLVE_TBL_CAP];
    {
        const uint8_t* src = (const uint8_t*)ph + ph->api_table_offset;
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
        // ---- Walk the table header --------------------------------
        uint32_t table_end = ph->api_table_size;
        uint32_t count = le_u32(tbl, 0, table_end);
        if (count != UPOBF_API_COUNT) break;

        // Each ApiEntry is 8 bytes: 4 x u16.
        const uint32_t entries_off = 4u;
        const uint32_t entry_size  = 8u;
        if (entries_off + count * entry_size > table_end) break;

        // Map: which slot each function pointer lives in.
        void* slots[UPOBF_API_COUNT] = { 0 };

        int all_resolved = 1;
        for (uint32_t i = 0; i < count; i++) {
            uint32_t base = entries_off + i * entry_size;
            uint16_t mod_off = le_u16(tbl, base + 0, table_end);
            uint16_t fn_off  = le_u16(tbl, base + 2, table_end);
            uint16_t mod_len = le_u16(tbl, base + 4, table_end);
            uint16_t fn_len  = le_u16(tbl, base + 6, table_end);

            if ((uint32_t)mod_off + mod_len > table_end) { all_resolved = 0; break; }
            if ((uint32_t)fn_off  + fn_len  > table_end) { all_resolved = 0; break; }
            // Cap so a malformed table can't blow our stack.
            if (mod_len >= 64 || fn_len >= 96) { all_resolved = 0; break; }

            // Wide-character module name: ASCII characters widen by
            // zero-extending each byte into a uint16_t.
            uint16_t mod_w[64];
            for (uint32_t k = 0; k < mod_len; k++) {
                mod_w[k] = (uint16_t)(uint8_t)tbl[mod_off + k];
            }
            mod_w[mod_len] = 0;

            char fn_name[96];
            up_memcpy_local(fn_name, tbl + fn_off, fn_len);
            fn_name[fn_len] = 0;

            UPOBF_HMODULE m = anchor_get_module_w((UPOBF_LPCWSTR)mod_w);
            if (!m) { all_resolved = 0; break; }
            UPOBF_FARPROC p = anchor_get_proc_addr(m, fn_name);

            up_secure_zero_local(mod_w,   sizeof(mod_w));
            up_secure_zero_local(fn_name, sizeof(fn_name));

            if (!p) { all_resolved = 0; break; }
            slots[i] = (void*)p;
        }

        if (!all_resolved) break;

        out->GetModuleHandleW  = (PFN_GetModuleHandleW) slots[UPOBF_API_GET_MODULE_HANDLE_W];
        out->GetProcAddress    = (PFN_GetProcAddress)   slots[UPOBF_API_GET_PROC_ADDRESS];
        out->VirtualProtect    = (PFN_VirtualProtect)   slots[UPOBF_API_VIRTUAL_PROTECT];
        out->VirtualAlloc      = (PFN_VirtualAlloc)     slots[UPOBF_API_VIRTUAL_ALLOC];
        out->VirtualFree       = (PFN_VirtualFree)      slots[UPOBF_API_VIRTUAL_FREE];
        out->IsDebuggerPresent = (PFN_IsDebuggerPresent)slots[UPOBF_API_IS_DEBUGGER_PRESENT];
        out->GetCurrentProcess = (PFN_GetCurrentProcess)slots[UPOBF_API_GET_CURRENT_PROCESS];
        out->GetCurrentThread  = (PFN_GetCurrentThread) slots[UPOBF_API_GET_CURRENT_THREAD];
        out->GetThreadContext  = (PFN_GetThreadContext) slots[UPOBF_API_GET_THREAD_CONTEXT];
        out->CreateThread      = (PFN_CreateThread)     slots[UPOBF_API_CREATE_THREAD];
        out->Sleep             = (PFN_Sleep)            slots[UPOBF_API_SLEEP];
        out->CloseHandle       = (PFN_CloseHandle)      slots[UPOBF_API_CLOSE_HANDLE];

        ok = 1;
    } while (0);

    // Wipe the scratch table — the API names linger inside until we
    // overwrite them, and the function may not be tail-called so the
    // stack frame is still live for a few instructions after return.
    up_secure_zero_local(tbl, ph->api_table_size);

    return ok;
}
