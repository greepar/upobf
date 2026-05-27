//! Payload blob builder (M4) — PE shim.
//!
//! The wire-format builder is now in [`upobf_core::payload`]. This
//! module re-exports the cross-platform pieces and adds the
//! PE-specific API name table that the Windows stub indexes by
//! position.

pub use upobf_core::payload::{
    build_payload, build_payload_v2, ApiNames, BuiltPayload, OepStealArgs, PayloadInput,
    CHUNK_ENTRY_SIZE, FIXED_API_NONCE, MAX_API_TABLE_SIZE, MAX_CHUNK_COUNT,
    OEP_PATCH_GADGET_LEN, OEP_STEAL_MAX, PAYLOAD_HEADER_SIZE, UPOBF_FLAG_BCJ_X86,
    UPOBF_FLAG_CHACHA20, UPOBF_FLAG_LZMA, UPOBF_PAYLOAD_MAGIC, UPOBF_PAYLOAD_VERSION,
};

/// Number of API entries in the protocol table (must match
/// `UPOBF_API_COUNT` on the PE stub side). Phase G expanded this
/// from 6 to 9; Phase F adds three more (CreateThread / Sleep /
/// CloseHandle) for the background CRC watchdog thread.
pub const API_COUNT: usize = 12;

/// Indices into the API table. The order is part of the protocol —
/// stub-side `enum` in `api_resolve.h` mirrors it 1:1.
pub const IDX_GET_MODULE_HANDLE_W: usize = 0;
pub const IDX_GET_PROC_ADDRESS: usize = 1;
pub const IDX_VIRTUAL_PROTECT: usize = 2;
pub const IDX_VIRTUAL_ALLOC: usize = 3;
pub const IDX_VIRTUAL_FREE: usize = 4;
pub const IDX_IS_DEBUGGER_PRESENT: usize = 5;
pub const IDX_GET_CURRENT_PROCESS: usize = 6;
pub const IDX_GET_CURRENT_THREAD: usize = 7;
pub const IDX_GET_THREAD_CONTEXT: usize = 8;
pub const IDX_CREATE_THREAD: usize = 9;
pub const IDX_SLEEP: usize = 10;
pub const IDX_CLOSE_HANDLE: usize = 11;

/// Fixed name list driving the API string table. The stub indexes by
/// position so this order is part of the protocol. Slots 0 and 1 are
/// "anchors" — they stay in the packed PE's IAT so the OS Loader
/// resolves them for us; everything else is GetProcAddress'd from
/// inside the stub at runtime.
///
/// We pick the wide-character `GetModuleHandleW` over the ASCII form
/// because modern .NET NativeAOT binaries — the primary upobf target —
/// already import the W variant but not the A variant. Sticking with
/// what the host already pulls in lets us avoid rewriting
/// DataDirectory[Import].
pub const API_NAMES: [(&str, &str); API_COUNT] = [
    ("KERNEL32.dll", "GetModuleHandleW"), // 0 anchor
    ("KERNEL32.dll", "GetProcAddress"),   // 1 anchor
    ("KERNEL32.dll", "VirtualProtect"),   // 2 dynamic
    ("KERNEL32.dll", "VirtualAlloc"),     // 3 dynamic
    ("KERNEL32.dll", "VirtualFree"),      // 4 dynamic
    ("KERNEL32.dll", "IsDebuggerPresent"),// 5 dynamic
    ("KERNEL32.dll", "GetCurrentProcess"),// 6 dynamic
    ("KERNEL32.dll", "GetCurrentThread"), // 7 dynamic
    ("KERNEL32.dll", "GetThreadContext"), // 8 dynamic
    ("KERNEL32.dll", "CreateThread"),     // 9 watchdog
    ("KERNEL32.dll", "Sleep"),            // 10 watchdog
    ("KERNEL32.dll", "CloseHandle"),      // 11 watchdog
];

/// Number of leading entries in [`API_NAMES`] that are anchors. Anchor
/// APIs are referenced from the stub via `__imp_*` thunks so the OS
/// Loader fills them in; the rest are resolved at runtime via
/// `GetProcAddress`. Bumping this count is the protocol-level lever
/// for trading IAT visibility for stub complexity.
pub const API_ANCHOR_COUNT: usize = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_api_names_count_matches_constant() {
        assert_eq!(API_NAMES.len(), API_COUNT);
        assert!(API_ANCHOR_COUNT <= API_COUNT);
    }
}
