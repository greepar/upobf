// upobf x64 PEB helper.
//
// Returns the current process ImageBase by reading PEB.ImageBaseAddress
// via the GS segment. This avoids any IAT dependency.

.intel_syntax noprefix
.text
.globl upobf_get_image_base
upobf_get_image_base:
    mov rax, gs:[0x60]      // TEB.ProcessEnvironmentBlock -> PEB
    mov rax, [rax + 0x10]   // PEB.ImageBaseAddress
    ret
