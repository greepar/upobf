// upobf OEP-stealing redirect (Phase I).
//
// After the per-chunk decoder has finished restoring the host's
// `.text`, the original AddressOfEntryPoint is sitting at its
// expected RVA — except that the first `oep_steal_len` bytes there
// are now `0xCC int3` fillers (the packer replaced the real prologue
// with int3 padding before compressing the chunk).
//
// This TU builds a heap trampoline `T` and patches the host's OEP
// so the OS Loader's eventual `call AddressOfEntryPoint` lands in
// the trampoline, runs the **stolen** original prologue from the
// heap, then jumps back into the host past the patched gadget.
//
// Layout of `T`:
//
//     [stolen_prologue]      oep_steal_len bytes from PayloadHeader
//     FF 25 00 00 00 00      jmp qword ptr [rip+0]
//     <abs64>                = oep_target_va + oep_steal_len
//
// Layout written into the host's OEP (overwriting int3 padding):
//
//     FF 25 00 00 00 00      jmp qword ptr [rip+0]
//     <abs64>                = T_va
//
// Both gadgets are 14 bytes; 0xCC pad bytes after the gadget ensure
// any trailing payload-int3s remain semantically valid.
//
// Why a memory dump of the *unpacked* image cannot be re-run:
//
//   - Original OEP holds `jmp <T_va>` where `T_va` is a heap VA of
//     the running process. Heap pages are not mapped into the
//     dumped PE; on a fresh process the OS Loader places no module
//     there.
//   - The dumped exe therefore lands in unmapped memory at first
//     instruction and crashes immediately (access-violation on
//     fetch). Any tool that wants a runnable dump must additionally
//     dump the heap region containing T, locate it, splice it back
//     into a manufactured section, and rewrite the OEP gadget — a
//     non-trivial extra step beyond the one-click "dump unpacked
//     PE" workflow that pe-sieve / Scylla offer today.
//
// AV-friendliness:
//   - we never RWX-after-init: the trampoline page is allocated
//     with PAGE_READWRITE, populated, then VirtualProtect'd to
//     PAGE_EXECUTE_READ exactly once.
//   - the host's OEP page transitions only briefly through
//     PAGE_READWRITE (to write the gadget), then is restored to
//     its original protect (RX). No global RWX page exists at
//     steady state.

#include <stdint.h>

#include "payload.h"
#include "api_resolve.h"

// ---------------------------------------------------------------------
// Constants for the abs-jump gadget. Kept in sync with the packer-side
// `OEP_PATCH_GADGET_LEN` (= 14 bytes).
// ---------------------------------------------------------------------

#define UPOBF_OEP_GADGET_PREFIX 6u
#define UPOBF_OEP_GADGET_TOTAL  14u

// Forward decls — keep this TU off <windows.h> for the same
// freestanding reasons the rest of the stub honours.
#ifndef UPOBF_PAGE_EXECUTE_READ
#define UPOBF_PAGE_EXECUTE_READ 0x20u
#endif

static void up_oep_memcpy(void* dst, const void* src, uint32_t n) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    for (uint32_t i = 0; i < n; i++) d[i] = s[i];
}

// Encode the 14-byte abs-jump gadget at `dst`. `abs_target_va` is
// the absolute 64-bit VA the gadget should jump to.
static void up_oep_emit_absjmp(uint8_t* dst, uint64_t abs_target_va) {
    // FF 25 00 00 00 00     jmp qword ptr [rip+0]
    dst[0] = 0xFF;
    dst[1] = 0x25;
    dst[2] = 0x00;
    dst[3] = 0x00;
    dst[4] = 0x00;
    dst[5] = 0x00;
    // 8-byte little-endian absolute target.
    for (int i = 0; i < 8; i++) {
        dst[UPOBF_OEP_GADGET_PREFIX + i] = (uint8_t)(abs_target_va >> (8 * i));
    }
}

/// Returns 1 on success, 0 on any failure. Failure is silent —
/// the host falls through with int3-padded OEP, which is itself a
/// strong tamper signal but doesn't crash legitimate execution
/// because the OS Loader hasn't reached OEP yet (we run as TLS
/// callback). When this function returns 0 the host crashes the
/// instant control reaches OEP, which is exactly what we want when
/// somebody is stripping our protection.
__attribute__((used))
int upobf_oep_redirect_install(const PayloadHeader *ph,
                               uint8_t              *image_base,
                               const ResolvedApis   *apis)
{
    if (!ph || !image_base || !apis) return 0;
    if (ph->oep_steal_len < UPOBF_OEP_GADGET_TOTAL ||
        ph->oep_encoded_len < UPOBF_OEP_GADGET_TOTAL ||
        ph->oep_encoded_len > UPOBF_OEP_STEAL_MAX) {
        // Feature disabled (==0) or malformed — skip silently.
        return 0;
    }
    if (!apis->VirtualAlloc || !apis->VirtualProtect) return 0;

    uint8_t *oep_va     = image_base + ph->oep_target_rva;
    uint8_t *patch_va   = image_base + ph->oep_patch_rva;
    uint64_t orig_after = (uint64_t)(uintptr_t)oep_va + ph->oep_steal_len;

    // Allocate the trampoline. We reserve a full page even though
    // the body is < 80 bytes; OS Loader granularity is one page.
    uint8_t *trampoline = (uint8_t*)apis->VirtualAlloc(
        0, (UPOBF_SIZE_T)4096u,
        UPOBF_MEM_COMMIT | UPOBF_MEM_RESERVE,
        UPOBF_PAGE_READWRITE);
    if (!trampoline) return 0;

    // Copy the encoded trampoline body (PI verbatim + rewritten
    // rel-branches) followed by the 14-byte abs-jmp gadget back
    // into the host past the patched bytes.
    up_oep_memcpy(trampoline, ph->oep_stolen_bytes, ph->oep_encoded_len);
    up_oep_emit_absjmp(trampoline + ph->oep_encoded_len, orig_after);

    // Flip the trampoline to RX. We deliberately do not request
    // PAGE_EXECUTE_READWRITE — keeping a writable+executable page
    // around is exactly the AV-noisy pattern Phase I aims to avoid.
    UPOBF_DWORD prev = 0;
    if (!apis->VirtualProtect(trampoline,
                              (UPOBF_SIZE_T)4096u,
                              UPOBF_PAGE_EXECUTE_READ,
                              &prev)) {
        // Free the page on failure to keep the address space tidy.
        apis->VirtualFree(trampoline, 0, UPOBF_MEM_RELEASE);
        return 0;
    }

    // Patch the host's OEP: temporarily make the page writable,
    // overwrite the int3 padding with our 14-byte abs-jmp gadget,
    // then restore the original protect (RX for code).
    UPOBF_DWORD oep_prev = 0;
    if (!apis->VirtualProtect(patch_va,
                              (UPOBF_SIZE_T)UPOBF_OEP_GADGET_TOTAL,
                              0x40u /* PAGE_EXECUTE_READWRITE */,
                              &oep_prev)) {
        // We cannot finish the install. Leave the trampoline
        // allocated (it's harmless RX-only memory) and signal
        // failure — caller's call whether to retry or crash.
        return 0;
    }

    up_oep_emit_absjmp(patch_va, (uint64_t)(uintptr_t)trampoline);

    UPOBF_DWORD discard = 0;
    apis->VirtualProtect(patch_va,
                         (UPOBF_SIZE_T)UPOBF_OEP_GADGET_TOTAL,
                         oep_prev,
                         &discard);
    return 1;
}
