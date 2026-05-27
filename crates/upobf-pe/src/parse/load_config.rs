//! IMAGE_LOAD_CONFIG_DIRECTORY64 parsing.
//!
//! The structure has grown over time (Windows 7 = 112 B, current SDK = 320+ B
//! including CFG/CHPE/XFG fields). We read the first `Size` bytes (which the
//! image self-declares) and decode the fields that exist in that span. PE32+
//! offsets per `winnt.h`:
//!
//! | Offset | Size | Field                                 |
//! |-------:|-----:|---------------------------------------|
//! |   0    | 4    | Size                                  |
//! |   4    | 4    | TimeDateStamp                         |
//! |  88    | 8    | SecurityCookie (VA)                   |
//! |  96    | 8    | SEHandlerTable (x86)                  |
//! | 104    | 8    | SEHandlerCount                        |
//! | 112    | 8    | GuardCFCheckFunctionPointer           |
//! | 120    | 8    | GuardCFDispatchFunctionPointer        |
//! | 128    | 8    | GuardCFFunctionTable                  |
//! | 136    | 8    | GuardCFFunctionCount                  |
//! | 144    | 4    | GuardFlags                            |

use anyhow::{Context, Result};
use serde::Serialize;

use super::reader as r;
use super::sections::SectionHeader;
use super::tls::rva_to_file_offset;

/// LoadConfig snapshot carrying the fields upobf actually inspects.
#[derive(Debug, Clone, Serialize)]
pub struct LoadConfig {
    /// Self-declared structure size (`directory[10].size` echoed).
    pub size: u32,
    pub time_date_stamp: u32,
    pub security_cookie_va: Option<u64>,
    pub guard_cf_check_function_pointer: Option<u64>,
    pub guard_cf_dispatch_function_pointer: Option<u64>,
    pub guard_cf_function_table: Option<u64>,
    pub guard_cf_function_count: Option<u64>,
    pub guard_flags: Option<u32>,
}

impl LoadConfig {
    /// Parse the directory pointed to by `dir_rva` with declared size
    /// `dir_size`. The image's optional header `dll_characteristics` is taken
    /// only for sanity logging at higher layers.
    pub fn parse(
        buf: &[u8],
        sections: &[SectionHeader],
        dir_rva: u32,
        dir_size: u32,
    ) -> Result<Self> {
        let off = rva_to_file_offset(sections, dir_rva)
            .with_context(|| format!("LoadConfig RVA 0x{:08X}", dir_rva))?;
        let span = dir_size as usize;
        let bytes = r::slice(buf, off, span).context("LoadConfig bytes")?;

        let size = r::u32_opt(bytes, 0).unwrap_or(dir_size);
        let time_date_stamp = r::u32_opt(bytes, 4).unwrap_or(0);
        let security_cookie_va = r::u64_opt(bytes, 88);
        let guard_cf_check_function_pointer = r::u64_opt(bytes, 112);
        let guard_cf_dispatch_function_pointer = r::u64_opt(bytes, 120);
        let guard_cf_function_table = r::u64_opt(bytes, 128);
        let guard_cf_function_count = r::u64_opt(bytes, 136);
        let guard_flags = r::u32_opt(bytes, 144);

        Ok(Self {
            size,
            time_date_stamp,
            security_cookie_va,
            guard_cf_check_function_pointer,
            guard_cf_dispatch_function_pointer,
            guard_cf_function_table,
            guard_cf_function_count,
            guard_flags,
        })
    }
}
