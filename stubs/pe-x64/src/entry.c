// upobf PE x64 stub entry — M4.
//
// Runs as a TLS callback before the host's OEP. Responsibilities:
//   1. locate the payload blob via a packer-fixed-up pointer slot;
//   2. validate magic/version;
//   3. decrypt the API string table (M5 will actually use it; M4
//      keeps the round-trip live);
//   4. decrypt + decompress + BCJ-reverse every chunk back to its
//      original RVA inside the host image;
//   5. invoke the original TLS callback if one was registered;
//   6. return so the OS Loader continues to OEP.
//
// On any error past the magic check we still call the original TLS
// callback (if any) and return. M4 deliberately keeps no failure
// reporting — that would leave string artefacts in the binary.
//
// The stub never depends on libc, never reads PEB.ImageBaseAddress
// directly (some EDRs flag it), and never spawns threads.

#include <stdint.h>

#include "payload.h"
#include "obfuscate.h"

// ---------------------------------------------------------------------
// Windows types & API surface (no <windows.h>; we keep this minimal so
// the stub stays freestanding).
// ---------------------------------------------------------------------

typedef int            BOOL;
typedef unsigned long  DWORD;
typedef DWORD         *PDWORD;
typedef void          *LPVOID;
typedef const void    *LPCVOID;
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

// Imports: declared dllimport so clang emits __imp_* references that the
// packed PE's IAT will satisfy. The packer is responsible for adding the
// matching IMAGE_IMPORT_DESCRIPTOR (KERNEL32.dll, six functions).
// Imports: declared dllimport so clang emits __imp_* references that the
// packed PE's IAT will satisfy.
//
// We deliberately use only APIs the host already imports (verified
// against the demo NativeAOT corpus) so the M4 packer can reuse the
// existing IAT slots without rewriting DataDirectory[Import].
__declspec(dllimport) FARPROC WINAPI GetProcAddress(HMODULE, LPCSTR);
__declspec(dllimport) BOOL    WINAPI VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
__declspec(dllimport) LPVOID  WINAPI VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
__declspec(dllimport) BOOL    WINAPI VirtualFree(LPVOID, SIZE_T, DWORD);
__declspec(dllimport) HMODULE WINAPI LoadLibraryA(LPCSTR);

// M5 anti-debug surface (also satisfied by host IAT).
__declspec(dllimport) BOOL    WINAPI IsDebuggerPresent(void);
__declspec(dllimport) HANDLE  WINAPI GetCurrentProcess(void);
__declspec(dllimport) HANDLE  WINAPI GetCurrentThread(void);
__declspec(dllimport) BOOL    WINAPI GetThreadContext(HANDLE, void*);

// ---------------------------------------------------------------------
// Packer-supplied fixup symbols.
//
// upobf-core/stub_link materialises an 8-byte slot for each undefined
// extern below; the PE writer fills the slot at pack time.
//
//   __upobf_payload_blob          -> absolute VA of PayloadHeader
//   __upobf_stub_self_rva         -> RVA of upobf_stub_tls_callback
//                                    (32-bit field; zero-extended into
//                                     the 8-byte slot)
//   __upobf_original_tls_callback -> absolute VA of original first TLS
//                                    callback, or 0 if none
//
// These map onto FixupTarget::PayloadBlobVa / StubSelfRva /
// OriginalTlsCallback in stub_link::relocator.
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
    void *(*alloc_fn)(uint32_t),
    void  (*free_fn)(void *));

uint32_t upobf_env_seed(void);
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
// VirtualAlloc; freed via VirtualFree.
// ---------------------------------------------------------------------

static void* lzma_alloc(uint32_t size) {
    return VirtualAlloc(0, (SIZE_T)size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static void lzma_free(void* p) {
    if (p) VirtualFree(p, 0, MEM_RELEASE);
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
static int process_chunk(const PayloadHeader* ph,
                         const ChunkEntry*    ce,
                         uint8_t*             image_base)
{
    uint8_t* dst = image_base + ce->target_rva;

    // The encrypted bytes live in the read-only payload section. We make
    // an RW copy because ChaCha20 is in-place.
    uint8_t* tmp = (uint8_t*)VirtualAlloc(
        0, (SIZE_T)ce->data_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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

    // Make the destination writable. Failure here aborts but the caller
    // will still try the original TLS callback.
    DWORD old_protect = 0;
    if (!VirtualProtect(dst, (SIZE_T)ce->virtual_size, PAGE_READWRITE, &old_protect)) {
        up_secure_zero(tmp, ce->data_size);
        VirtualFree(tmp, 0, MEM_RELEASE);
        return 0;
    }

    // LZMA decompress. If the chunk is not LZMA-flagged we copy verbatim
    // (currently unused, but cheap and keeps the protocol bit3-friendly).
    if (OPAQUE_TRUE(ce->flags & UPOBF_FLAG_LZMA)) {
        uint32_t produced = 0;
        int rc = upobf_lzma_decompress_alone(
            tmp, ce->data_size,
            dst, ce->virtual_size, &produced,
            lzma_alloc, lzma_free);
        if (rc != 0) {
            up_secure_zero(tmp, ce->data_size);
            VirtualFree(tmp, 0, MEM_RELEASE);
            // Best-effort restore of the original protect.
            DWORD discard;
            VirtualProtect(dst, (SIZE_T)ce->virtual_size, ce->original_protect, &discard);
            return 0;
        }
        // We trust ChunkEntry.virtual_size as the ground truth (per protocol).
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
    DWORD discard;
    VirtualProtect(dst, (SIZE_T)ce->virtual_size, ce->original_protect, &discard);

    // Wipe and free temp buffer.
    up_secure_zero(tmp, ce->data_size);
    VirtualFree(tmp, 0, MEM_RELEASE);
    return 1;
}

// Decrypt the API string table in place inside an RW scratch buffer.
// The table is otherwise unused in M4 but the round-trip exercises the
// ChaCha20 path and validates that nonce derivation matches the packer.
static int decrypt_api_table(const PayloadHeader* ph) {
    if (ph->api_table_size == 0) return 1;
    if (ph->api_table_size > UPOBF_MAX_API_TABLE_SIZE) return 0;

    uint8_t* tmp = (uint8_t*)VirtualAlloc(
        0, (SIZE_T)ph->api_table_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!tmp) return 0;

    const uint8_t* src = (const uint8_t*)ph + ph->api_table_offset;
    up_memcpy(tmp, src, ph->api_table_size);

    uint8_t nonce[12];
    uint8_t fixed_api_nonce[12];
    upobf_fixed_api_nonce_get(fixed_api_nonce);
    derive_nonce(nonce, ph->master_nonce, fixed_api_nonce);
    upobf_chacha20_xor(tmp, ph->api_table_size, ph->master_key, nonce);

    // M4: we do not consume the decrypted table. Just wipe and free.
    up_secure_zero(tmp, ph->api_table_size);
    VirtualFree(tmp, 0, MEM_RELEASE);
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

    // M5 anti-debug check (AV-friendly: only documented APIs, never
    // exits, just folds an analyst-presence signal into a seed). The
    // seed is consumed below to influence the integrity baseline; in
    // production builds (M5 Pro) it can additionally perturb the
    // unpack key derivation so analysing under a debugger yields
    // subtly different bytes.
    volatile uint32_t env_seed = upobf_env_seed();

    // Resolve image base via stub-self RVA.
    // We take the address of this very function and subtract its RVA
    // (filled by the packer) to recover ImageBase. This avoids reading
    // PEB.ImageBaseAddress.
    uint8_t* image_base =
        (uint8_t*)&upobf_stub_tls_callback - (uintptr_t)__upobf_stub_self_rva;

    // Locate payload blob.
    PayloadHeader* ph = (PayloadHeader*)__upobf_payload_blob;
    if (!ph) {
        call_original_tls(h, reason, reserved);
        return;
    }

    // Validate magic / version. Anything off => silent passthrough.
    // Each predicate is wrapped with OPAQUE_FALSE so the comparison
    // chain shows up as multi-term arithmetic in a decompiler instead
    // of the obvious `magic != UPOBF_PAYLOAD_MAGIC` form.
    if (OPAQUE_FALSE(ph->magic != UPOBF_PAYLOAD_MAGIC) ||
        OPAQUE_FALSE(ph->version != UPOBF_PAYLOAD_VERSION) ||
        OPAQUE_FALSE(ph->chunk_count > UPOBF_MAX_CHUNK_COUNT)) {
        call_original_tls(h, reason, reserved);
        return;
    }

    // ApiStringTable: decrypt round-trip (M4 does not consume it).
    // Bogus guard: always true at runtime, but a decompiler sees it as
    // a real branch and traces both arms.
    if (BOGUS_GUARD()) {
        decrypt_api_table(ph);
    }

    // Per-chunk decode. Failures fall through to the original callback
    // without diagnostics — see file header comment.
    const ChunkEntry* chunks =
        (const ChunkEntry*)((const uint8_t*)ph + ph->chunks_offset);
    volatile uint32_t integrity = env_seed;
    for (uint32_t i = 0; i < ph->chunk_count; i++) {
        if (!process_chunk(ph, &chunks[i], image_base)) {
            // Keep going: a partial unpack is still less suspicious than
            // a hard failure. The original TLS callback runs at the end.
        }
        // Roll an integrity hash over each decoded region. The result
        // is observable only via timing / side-channel; M6 will hook it
        // up to a real watchdog thread.
        const ChunkEntry* ce = &chunks[i];
        const uint8_t* dst = image_base + ce->target_rva;
        integrity = upobf_crc32(dst, ce->virtual_size, integrity);
        // Stir the loop counter so the trip-count stays opaque.
        integrity ^= JUNK_DATAFLOW(i);
    }
    // Sink the integrity value so the optimiser cannot drop the loop.
    *(volatile uint32_t*)&env_seed = integrity;

    call_original_tls(h, reason, reserved);
}

// ---------------------------------------------------------------------
// IAT keep-alive.
//
// Per protocol-m4.md, the packer reserves IAT slots for all six
// KERNEL32 APIs (GetModuleHandleA, LoadLibraryA, GetProcAddress,
// VirtualProtect, VirtualAlloc, VirtualFree). M4's main flow only
// invokes three of them; without the calls below clang would drop the
// other three `__imp_*` references and the packer would have no signal
// that those slots are needed.
//
// Taking `&f` for a dllimport function references the thunk symbol
// (`f`), not `__imp_f`, so an address-of table is not enough. We need
// real call instructions. They are gated by `keep` so they never run,
// and the function is `used` so the compiler cannot strip it. The
// arguments are designed to be cheap and side-effect-free if the gate
// were ever to fire.
// ---------------------------------------------------------------------

__attribute__((used, noinline))
static void upobf_iat_keepalive(volatile int keep) {
    if (!keep) return;
    (void)LoadLibraryA(0);
    (void)GetProcAddress(0, 0);
    DWORD old = 0;
    (void)VirtualProtect(0, 0, 0, &old);
    (void)VirtualAlloc(0, 0, 0, 0);
    (void)VirtualFree(0, 0, 0);
    // Anti-debug API symbols (M5).
    (void)IsDebuggerPresent();
    (void)GetCurrentProcess();
    (void)GetCurrentThread();
    (void)GetThreadContext(0, 0);
}
