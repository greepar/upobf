// upobf PE x64 stub entry — Phase G (dynamic API resolution).
//
// Phase G change:
//
//   The stub used to declare every Win32 API it called as
//   `__declspec(dllimport)`, leaving 9 KERNEL32 names visible in the
//   packed PE's import table (or, more precisely, leaving the stub's
//   `__imp_*` references resolvable against host IAT slots, which a
//   static analyser can still trace back to API names through
//   `IMAGE_THUNK_DATA -> IMAGE_IMPORT_BY_NAME`).
//
//   Now, the stub keeps only TWO anchor APIs in its IAT references:
//
//       - GetModuleHandleA
//       - GetProcAddress
//
//   Everything else (`VirtualProtect`, `VirtualAlloc`, `VirtualFree`,
//   `IsDebuggerPresent`, `GetCurrentProcess`, `GetCurrentThread`,
//   `GetThreadContext`) is looked up from the encrypted
//   `ApiStringTable` at runtime via the resolver in
//   `api_resolve.c`. Their names never appear as static strings in
//   the packed PE outside the encrypted blob.
//
// Runs as a TLS callback before the host's OEP. Responsibilities:
//   1. locate the payload blob via a packer-fixed-up pointer slot;
//   2. validate magic/version;
//   3. decrypt the API table and resolve all 9 function pointers;
//   4. decrypt + decompress + BCJ-reverse every chunk back to its
//      original RVA inside the host image;
//   5. invoke the original TLS callback if one was registered;
//   6. return so the OS Loader continues to OEP.
//
// On any error past the magic check we still call the original TLS
// callback (if any) and return — same silent-failure policy as M4.

#include <stdint.h>

#include "payload.h"
#include "obfuscate.h"
#include "api_resolve.h"

// ---------------------------------------------------------------------
// Windows types & API surface (no <windows.h>; we keep this minimal so
// the stub stays freestanding).
//
// We re-declare the typedefs here separately from the api_resolve.h
// versions because entry.c historically used the bare names. Using
// distinct typedef names avoids any UPOBF_*-prefixed leakage into the
// surrounding code.
// ---------------------------------------------------------------------

typedef int            BOOL;
typedef unsigned long  DWORD;
typedef DWORD         *PDWORD;
typedef void          *LPVOID;
typedef const char    *LPCSTR;
typedef void          *HMODULE;
typedef int (__stdcall *FARPROC)(void);
typedef uintptr_t      SIZE_T;
typedef void          *HINSTANCE;
typedef void          *HANDLE;

#define WINAPI __stdcall

#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40

#define MEM_COMMIT             0x00001000
#define MEM_RESERVE            0x00002000
#define MEM_RELEASE            0x00008000

#define DLL_PROCESS_ATTACH     1
#define DLL_PROCESS_DETACH     0
#define DLL_THREAD_ATTACH      2
#define DLL_THREAD_DETACH      3

// ---------------------------------------------------------------------
// Anchor imports.
//
// These are the ONLY two APIs we still pull through the import table.
// The packer arranges for both __imp_GetModuleHandleW and
// __imp_GetProcAddress to resolve to slots in the host's existing
// IAT (or, if absent, into a tiny extra import descriptor).
//
// We pick the wide-character `GetModuleHandleW` over the ASCII form
// because modern .NET NativeAOT corpora — the primary upobf target —
// already import `GetModuleHandleW` via their startup path. Picking
// the W form lets the packer satisfy the anchor through the host's
// existing IAT and avoid rewriting DataDirectory[Import], which has
// historically destabilised NativeAOT bootstrap.
//
// Every other Win32 call inside this TU goes through the
// `ResolvedApis g_apis` table populated by `upobf_resolve_apis`.
// ---------------------------------------------------------------------

__declspec(dllimport) HMODULE WINAPI GetModuleHandleW(const uint16_t*);
__declspec(dllimport) FARPROC WINAPI GetProcAddress(HMODULE, LPCSTR);

// ---------------------------------------------------------------------
// Packer-supplied fixup symbols. (Unchanged from M4.)
// ---------------------------------------------------------------------

extern volatile uint8_t  *__upobf_payload_blob;          // FixupTarget::PayloadBlobVa
extern volatile uintptr_t __upobf_stub_self_rva;         // FixupTarget::StubSelfRva (low 32 bits used)
extern volatile uintptr_t __upobf_original_tls_callback; // FixupTarget::OriginalTlsCallback

// ---------------------------------------------------------------------
// Forward decls from sibling translation units.
// ---------------------------------------------------------------------

void upobf_chacha20_xor(uint8_t* data, uint32_t len,
                        const uint8_t key[32], const uint8_t nonce[12]);

void upobf_bcj_x86_backward(uint8_t* data, uint32_t len, uint32_t base_addr);

int upobf_lzma_decompress_alone(
    const uint8_t *src, uint32_t src_len,
    uint8_t       *dst, uint32_t dst_capacity, uint32_t *out_dst_size,
    void *(*alloc_fn)(void *user, uint32_t),
    void  (*free_fn)(void *user, void *),
    void  *user);

uint32_t upobf_env_seed(const ResolvedApis *apis);
uint32_t upobf_crc32(const uint8_t* data, uint32_t len, uint32_t init);

// ---------------------------------------------------------------------
// Tiny freestanding helpers (no libc).
// ---------------------------------------------------------------------

static void up_memcpy(void* dst, const void* src, uint32_t n) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    for (uint32_t i = 0; i < n; i++) d[i] = s[i];
}

static void up_memset(void* dst, uint8_t v, uint32_t n) {
    uint8_t* d = (uint8_t*)dst;
    for (uint32_t i = 0; i < n; i++) d[i] = v;
}

static void up_secure_zero(void* dst, uint32_t n) {
    volatile uint8_t* d = (volatile uint8_t*)dst;
    for (uint32_t i = 0; i < n; i++) d[i] = 0;
}

// ---------------------------------------------------------------------
// Allocator callbacks for the LZMA decoder.
//
// The decoder needs a probability table (~14 KiB at default LZMA-6
// settings) plus a dictionary buffer (16 MiB at LZMA-6). Both come from
// the resolved `VirtualAlloc`; freed via the resolved `VirtualFree`.
// We thread the resolved-API pointer through the LZMA decoder's
// `user` parameter (Phase G extension to the SDK signature) so the
// stub stays free of writable globals — the freestanding-stub
// linker rejects any `.bss` slot.
// ---------------------------------------------------------------------

static void* lzma_alloc(void *user, uint32_t size) {
    const ResolvedApis *apis = (const ResolvedApis *)user;
    if (!apis || !apis->VirtualAlloc) return 0;
    return apis->VirtualAlloc(0, (UPOBF_SIZE_T)size,
                              UPOBF_MEM_COMMIT | UPOBF_MEM_RESERVE,
                              UPOBF_PAGE_READWRITE);
}

static void lzma_free(void *user, void *p) {
    const ResolvedApis *apis = (const ResolvedApis *)user;
    if (p && apis && apis->VirtualFree) {
        apis->VirtualFree(p, 0, UPOBF_MEM_RELEASE);
    }
}

// ---------------------------------------------------------------------
// Core flow.
// ---------------------------------------------------------------------

// XOR two 12-byte nonces into `out`.
static inline void derive_nonce(uint8_t out[12], const uint8_t a[12], const uint8_t b[12]) {
    for (int i = 0; i < 12; i++) out[i] = a[i] ^ b[i];
}

// Process one chunk: ChaCha20 decrypt -> LZMA decompress -> BCJ backward.
// Returns 1 on success, 0 on failure.
static int process_chunk(const PayloadHeader   *ph,
                         const ChunkEntry      *ce,
                         uint8_t               *image_base,
                         const ResolvedApis    *apis)
{
    uint8_t* dst = image_base + ce->target_rva;

    // The encrypted bytes live in the read-only payload section. We make
    // an RW copy because ChaCha20 is in-place.
    uint8_t* tmp = (uint8_t*)apis->VirtualAlloc(
        0, (UPOBF_SIZE_T)ce->data_size,
        UPOBF_MEM_COMMIT | UPOBF_MEM_RESERVE, UPOBF_PAGE_READWRITE);
    if (!tmp) return 0;

    const uint8_t* enc =
        (const uint8_t*)ph + ph->data_offset + ce->data_offset;
    up_memcpy(tmp, enc, ce->data_size);

    // ChaCha20: nonce = master_nonce XOR sub_nonce.
    if (OPAQUE_TRUE(ce->flags & UPOBF_FLAG_CHACHA20)) {
        uint8_t nonce[12];
        derive_nonce(nonce, ph->master_nonce, ce->sub_nonce);
        upobf_chacha20_xor(tmp, ce->data_size, ph->master_key, nonce);
    }

    // Make the destination writable.
    UPOBF_DWORD old_protect = 0;
    if (!apis->VirtualProtect(dst, (UPOBF_SIZE_T)ce->virtual_size,
                              UPOBF_PAGE_READWRITE, &old_protect)) {
        up_secure_zero(tmp, ce->data_size);
        apis->VirtualFree(tmp, 0, UPOBF_MEM_RELEASE);
        return 0;
    }

    // LZMA decompress (or verbatim copy when bit1 is clear).
    if (OPAQUE_TRUE(ce->flags & UPOBF_FLAG_LZMA)) {
        uint32_t produced = 0;
        int rc = upobf_lzma_decompress_alone(
            tmp, ce->data_size,
            dst, ce->virtual_size, &produced,
            lzma_alloc, lzma_free, (void*)apis);
        if (rc != 0) {
            up_secure_zero(tmp, ce->data_size);
            apis->VirtualFree(tmp, 0, UPOBF_MEM_RELEASE);
            // Best-effort restore of the original protect.
            UPOBF_DWORD discard;
            apis->VirtualProtect(dst, (UPOBF_SIZE_T)ce->virtual_size,
                                 ce->original_protect, &discard);
            return 0;
        }
    } else {
        // Raw copy (size mismatch is a protocol error; clamp by virtual_size).
        uint32_t copy = ce->data_size < ce->virtual_size ? ce->data_size : ce->virtual_size;
        up_memcpy(dst, tmp, copy);
        if (copy < ce->virtual_size) {
            up_memset(dst + copy, 0, ce->virtual_size - copy);
        }
    }

    // BCJ backward.
    if (OPAQUE_TRUE(ce->flags & UPOBF_FLAG_BCJ_X86)) {
        upobf_bcj_x86_backward(dst, ce->virtual_size, ce->bcj_base);
    }

    // Restore original protect.
    UPOBF_DWORD discard;
    apis->VirtualProtect(dst, (UPOBF_SIZE_T)ce->virtual_size,
                         ce->original_protect, &discard);

    // Wipe and free temp buffer.
    up_secure_zero(tmp, ce->data_size);
    apis->VirtualFree(tmp, 0, UPOBF_MEM_RELEASE);
    return 1;
}

// Look up the original TLS callback (if any) and invoke it.
static void call_original_tls(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    uintptr_t addr = __upobf_original_tls_callback;
    if (addr == 0) return;
    typedef void (WINAPI *TlsCallbackFn)(HINSTANCE, DWORD, LPVOID);
    TlsCallbackFn fn = (TlsCallbackFn)addr;
    fn(h, reason, reserved);
}

// ---------------------------------------------------------------------
// TLS callback entry point. The packer registers this in TLS Directory.
// ---------------------------------------------------------------------

__attribute__((used))
void upobf_stub_tls_callback(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    if (reason != DLL_PROCESS_ATTACH) {
        // For non-attach reasons we just forward to the original
        // callback (if any) so the host's bookkeeping still works.
        call_original_tls(h, reason, reserved);
        return;
    }

    // Resolve image base via stub-self RVA.
    uint8_t* image_base =
        (uint8_t*)&upobf_stub_tls_callback - (uintptr_t)__upobf_stub_self_rva;

    // Locate payload blob.
    PayloadHeader* ph = (PayloadHeader*)__upobf_payload_blob;
    if (!ph) {
        call_original_tls(h, reason, reserved);
        return;
    }

    // Validate magic / version. Anything off => silent passthrough.
    if (OPAQUE_FALSE(ph->magic != UPOBF_PAYLOAD_MAGIC) ||
        OPAQUE_FALSE(ph->version != UPOBF_PAYLOAD_VERSION) ||
        OPAQUE_FALSE(ph->chunk_count > UPOBF_MAX_CHUNK_COUNT)) {
        call_original_tls(h, reason, reserved);
        return;
    }

    // Resolve the full API table BEFORE we touch any chunk. Failure
    // here means we cannot safely call VirtualAlloc/Protect/Free,
    // so we passthrough silently.
    ResolvedApis apis;
    if (!upobf_resolve_apis(ph,
                            (PFN_GetModuleHandleW)GetModuleHandleW,
                            (PFN_GetProcAddress) GetProcAddress,
                            &apis)) {
        call_original_tls(h, reason, reserved);
        return;
    }

    // Anti-debug check (now that anti-debug APIs are resolved).
    volatile uint32_t env_seed = upobf_env_seed(&apis);

    // Per-chunk decode. Failures fall through to the original callback
    // without diagnostics.
    const ChunkEntry* chunks =
        (const ChunkEntry*)((const uint8_t*)ph + ph->chunks_offset);
    volatile uint32_t integrity = env_seed;
    for (uint32_t i = 0; i < ph->chunk_count; i++) {
        if (!process_chunk(ph, &chunks[i], image_base, &apis)) {
            // Keep going — partial unpack is less suspicious than hard fail.
        }
        const ChunkEntry* ce = &chunks[i];
        const uint8_t* dst = image_base + ce->target_rva;
        integrity = upobf_crc32(dst, ce->virtual_size, integrity);
        integrity ^= JUNK_DATAFLOW(i);
    }
    *(volatile uint32_t*)&env_seed = integrity;

    // Wipe the resolved table from the stack before handing control
    // to the host. The compiler honours volatile zeroing.
    up_secure_zero(&apis, (uint32_t)sizeof(apis));

    call_original_tls(h, reason, reserved);
}

// ---------------------------------------------------------------------
// IAT keep-alive.
//
// Phase G: only TWO anchor APIs survive in the import table now:
// GetModuleHandleA and GetProcAddress. Taking `&f` for a dllimport
// references the thunk symbol; the linker drops `__imp_*` if no real
// call site exists, so we still need to keep at least one call to
// each anchor live. The function is gated by `keep` so it never
// runs, and `__attribute__((used))` so it is not stripped.
// ---------------------------------------------------------------------

__attribute__((used, noinline))
static void upobf_iat_keepalive(volatile int keep) {
    if (!keep) return;
    (void)GetModuleHandleW(0);
    (void)GetProcAddress(0, 0);
}
