// upobf x64 trampoline placeholder.
//
// M3: trivial `ret` so the symbol exists for stub_link round-tripping.
// M4 will turn this into the real jump-to-OEP trampoline.

.intel_syntax noprefix
.text
.globl upobf_trampoline
upobf_trampoline:
    ret
