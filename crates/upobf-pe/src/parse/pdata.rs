//! Exception directory (.pdata / RUNTIME_FUNCTION array) summary.
//!
//! On x64, DataDirectory[3] points to a contiguous array of
//! `IMAGE_RUNTIME_FUNCTION_ENTRY` records (12 bytes each):
//!
//! | Offset | Size | Field          |
//! |-------:|-----:|----------------|
//! |   0    | 4    | BeginAddress   |
//! |   4    | 4    | EndAddress     |
//! |   8    | 4    | UnwindInfo     |
//!
//! upobf only needs to know the start/end RVA range and the entry count so the
//! packer can preserve `.pdata` verbatim at its original RVA. We deliberately
//! do not decode the unwind opcode chain.

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::reader as r;
use super::sections::SectionHeader;
use super::tls::rva_to_file_offset;

#[derive(Debug, Clone, Serialize)]
pub struct PdataInfo {
    /// Directory RVA (echo of `data_dir[3].virtual_address`).
    pub directory_rva: u32,
    /// Directory byte size (echo of `data_dir[3].size`).
    pub directory_size: u32,
    /// Number of RUNTIME_FUNCTION entries == `size / 12`.
    pub entry_count: u32,
    /// First entry's BeginAddress (RVA), if any.
    pub first_begin_rva: Option<u32>,
    /// Last entry's EndAddress (RVA), if any.
    pub last_end_rva: Option<u32>,
}

impl PdataInfo {
    pub const ENTRY_SIZE: u32 = 12;

    pub fn parse(
        buf: &[u8],
        sections: &[SectionHeader],
        dir_rva: u32,
        dir_size: u32,
    ) -> Result<Self> {
        if dir_size % Self::ENTRY_SIZE != 0 {
            bail!(
                ".pdata size {} is not a multiple of RUNTIME_FUNCTION (12 bytes)",
                dir_size
            );
        }
        let entry_count = dir_size / Self::ENTRY_SIZE;
        if entry_count == 0 {
            return Ok(Self {
                directory_rva: dir_rva,
                directory_size: dir_size,
                entry_count: 0,
                first_begin_rva: None,
                last_end_rva: None,
            });
        }

        let off = rva_to_file_offset(sections, dir_rva)
            .with_context(|| format!(".pdata RVA 0x{:08X}", dir_rva))?;
        let bytes = r::slice(buf, off, dir_size as usize).context(".pdata bytes")?;

        let first_begin_rva = r::u32_opt(bytes, 0);
        let last_off = ((entry_count - 1) * Self::ENTRY_SIZE) as usize;
        let last_end_rva = r::u32_opt(bytes, last_off + 4);

        Ok(Self {
            directory_rva: dir_rva,
            directory_size: dir_size,
            entry_count,
            first_begin_rva,
            last_end_rva,
        })
    }
}
