// upobf stub runtime declarations.
//
// Updated for M4: the stub no longer references `__upobf_original_oep`
// (the OS Loader keeps the original AddressOfEntryPoint and we rely on
// natural fall-through after our TLS callback returns). Instead we
// declare the three packer-supplied fixup symbols used by entry.c.

#ifndef UPOBF_STUB_RUNTIME_H
#define UPOBF_STUB_RUNTIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Pack-time fixup symbols. See `stub_link::FixupTarget` for the writer
// side. Each is materialised as an 8-byte slot in the stub blob.
extern volatile uint8_t  *__upobf_payload_blob;          // PayloadBlobVa
extern volatile uintptr_t __upobf_stub_self_rva;         // StubSelfRva
extern volatile uintptr_t __upobf_original_tls_callback; // OriginalTlsCallback

// First TLS callback emitted into the packed image.
void upobf_stub_tls_callback(void* h, unsigned long reason, void* reserved);

// PEB-based image-base helper (M3 leftover, kept for symbol stability).
uintptr_t upobf_get_image_base(void);

// Asm-only trampoline placeholder. Reserved for later milestones.
void upobf_trampoline(void);

#ifdef __cplusplus
}
#endif

#endif // UPOBF_STUB_RUNTIME_H
