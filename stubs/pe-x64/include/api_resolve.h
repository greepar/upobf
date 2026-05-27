// upobf API table resolver (Phase G).
//
// Decrypts the on-wire ApiStringTable and resolves every entry to a
// callable function pointer via `GetModuleHandleA` + `GetProcAddress`.
// Only those two APIs need to live in the packed PE's import table;
// everything else (`VirtualProtect`, `VirtualAlloc`, anti-debug APIs)
// is looked up at runtime so its name never appears verbatim in the
// stub's IAT references.
//
// The resolved table is filled in by the stub TLS callback before any
// chunk is unpacked, then handed to every site that needs to call
// into KERNEL32.

#ifndef UPOBF_API_RESOLVE_H
#define UPOBF_API_RESOLVE_H

#include <stdint.h>

#include "payload.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------
// Win32 typedefs duplicated from the call sites so this header stays
// independent of <windows.h>. The stub TUs deliberately don't include
// the SDK header; we keep the surface explicit.
// ---------------------------------------------------------------------

typedef int            UPOBF_BOOL;
typedef unsigned long  UPOBF_DWORD;
typedef UPOBF_DWORD   *UPOBF_PDWORD;
typedef void          *UPOBF_LPVOID;
typedef const char    *UPOBF_LPCSTR;
// LPCWSTR is a pointer to a UTF-16 NUL-terminated string. We use
// `uint16_t` instead of `wchar_t` because the freestanding toolchain
// (`-ffreestanding -nostdlib`) does not pull in <wchar.h>, and
// Windows defines wchar_t as a 16-bit type anyway.
typedef const uint16_t *UPOBF_LPCWSTR;
typedef void          *UPOBF_HMODULE;
typedef void          *UPOBF_HANDLE;
typedef uintptr_t      UPOBF_SIZE_T;

#ifndef UPOBF_WINAPI
#define UPOBF_WINAPI __stdcall
#endif

// Win32 manifest constants the stub TUs need when calling through the
// resolved-API table. Defined here so api_resolve.c, entry.c, and any
// future TU (watchdog, etc.) all share a single source of truth and
// none of them have to redeclare the values.
#ifndef UPOBF_PAGE_READWRITE
#define UPOBF_PAGE_READWRITE 0x04u
#endif
#ifndef UPOBF_MEM_COMMIT
#define UPOBF_MEM_COMMIT     0x00001000u
#endif
#ifndef UPOBF_MEM_RESERVE
#define UPOBF_MEM_RESERVE    0x00002000u
#endif
#ifndef UPOBF_MEM_RELEASE
#define UPOBF_MEM_RELEASE    0x00008000u
#endif

typedef int (UPOBF_WINAPI *UPOBF_FARPROC)(void);

// Function-pointer typedefs for every resolved API.
typedef UPOBF_HMODULE (UPOBF_WINAPI *PFN_GetModuleHandleW)(UPOBF_LPCWSTR);
typedef UPOBF_FARPROC (UPOBF_WINAPI *PFN_GetProcAddress)(UPOBF_HMODULE, UPOBF_LPCSTR);
typedef UPOBF_BOOL    (UPOBF_WINAPI *PFN_VirtualProtect)(UPOBF_LPVOID, UPOBF_SIZE_T, UPOBF_DWORD, UPOBF_PDWORD);
typedef UPOBF_LPVOID  (UPOBF_WINAPI *PFN_VirtualAlloc)(UPOBF_LPVOID, UPOBF_SIZE_T, UPOBF_DWORD, UPOBF_DWORD);
typedef UPOBF_BOOL    (UPOBF_WINAPI *PFN_VirtualFree)(UPOBF_LPVOID, UPOBF_SIZE_T, UPOBF_DWORD);
typedef UPOBF_BOOL    (UPOBF_WINAPI *PFN_IsDebuggerPresent)(void);
typedef UPOBF_HANDLE  (UPOBF_WINAPI *PFN_GetCurrentProcess)(void);
typedef UPOBF_HANDLE  (UPOBF_WINAPI *PFN_GetCurrentThread)(void);
typedef UPOBF_BOOL    (UPOBF_WINAPI *PFN_GetThreadContext)(UPOBF_HANDLE, void*);

// Phase F watchdog APIs.
typedef UPOBF_DWORD   (UPOBF_WINAPI *PFN_ThreadStart)(UPOBF_LPVOID);
typedef UPOBF_HANDLE  (UPOBF_WINAPI *PFN_CreateThread)(
    UPOBF_LPVOID                /* lpThreadAttributes */,
    UPOBF_SIZE_T                /* dwStackSize        */,
    PFN_ThreadStart             /* lpStartAddress     */,
    UPOBF_LPVOID                /* lpParameter        */,
    UPOBF_DWORD                 /* dwCreationFlags    */,
    UPOBF_DWORD*                /* lpThreadId         */);
typedef void          (UPOBF_WINAPI *PFN_Sleep)(UPOBF_DWORD /* dwMilliseconds */);
typedef UPOBF_BOOL    (UPOBF_WINAPI *PFN_CloseHandle)(UPOBF_HANDLE);

/// Table of resolved function pointers, indexed by `UPOBF_API_*`.
/// All entries are non-NULL after a successful `upobf_resolve_apis`
/// call. Entries the resolver couldn't find are left at NULL and the
/// resolver returns 0; callers should bail in that case.
typedef struct ResolvedApis {
    PFN_GetModuleHandleW    GetModuleHandleW;     // [0]
    PFN_GetProcAddress      GetProcAddress;       // [1]
    PFN_VirtualProtect      VirtualProtect;       // [2]
    PFN_VirtualAlloc        VirtualAlloc;         // [3]
    PFN_VirtualFree         VirtualFree;          // [4]
    PFN_IsDebuggerPresent   IsDebuggerPresent;    // [5]
    PFN_GetCurrentProcess   GetCurrentProcess;    // [6]
    PFN_GetCurrentThread    GetCurrentThread;     // [7]
    PFN_GetThreadContext    GetThreadContext;     // [8]
    PFN_CreateThread        CreateThread;         // [9]
    PFN_Sleep               Sleep;                // [10]
    PFN_CloseHandle         CloseHandle;          // [11]
} ResolvedApis;

/// Decrypt the API string table sitting at
/// `(uint8_t*)ph + ph->api_table_offset` (in-place into a private
/// scratch buffer; the on-wire bytes stay encrypted), walk the
/// entries, resolve every API via the two anchor functions
/// (`GetModuleHandleW` + `GetProcAddress`) supplied via the stub's
/// IAT, and fill `out`.
///
/// `anchor_get_module_w` and `anchor_get_proc_addr` MUST be the host
/// IAT thunks for the corresponding KERNEL32 functions; the stub
/// supplies them as the only two `__imp_*` references that survive
/// Phase G.
///
/// Returns 1 on success, 0 if any entry could not be resolved (in
/// which case `out` is left in an unspecified state and the stub
/// must not call into it).
int upobf_resolve_apis(const PayloadHeader   *ph,
                       PFN_GetModuleHandleW   anchor_get_module_w,
                       PFN_GetProcAddress     anchor_get_proc_addr,
                       ResolvedApis          *out);

#ifdef __cplusplus
}
#endif

#endif // UPOBF_API_RESOLVE_H
