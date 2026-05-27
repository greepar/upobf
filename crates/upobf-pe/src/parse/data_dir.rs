//! IMAGE_DATA_DIRECTORY (8 bytes per entry, 16 entries in PE32+).

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::reader as r;

#[derive(Debug, Clone, Copy, Serialize, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirectory {
    pub const SIZE: usize = 8;

    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = r::slice(buf, off, Self::SIZE).context("DataDirectory entry")?;
        Ok(Self {
            virtual_address: r::u32(s, 0)?,
            size: r::u32(s, 4)?,
        })
    }

    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

/// PE/COFF DataDirectory index names (Microsoft order).
pub const DIRECTORY_NAMES: [&str; 16] = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Security",
    "BaseReloc",
    "Debug",
    "Architecture",
    "GlobalPtr",
    "TLS",
    "LoadConfig",
    "BoundImport",
    "IAT",
    "DelayImport",
    "CLR/COM",
    "Reserved",
];

pub const IDX_EXPORT: usize = 0;
pub const IDX_IMPORT: usize = 1;
pub const IDX_RESOURCE: usize = 2;
pub const IDX_EXCEPTION: usize = 3;
pub const IDX_SECURITY: usize = 4;
pub const IDX_BASERELOC: usize = 5;
pub const IDX_DEBUG: usize = 6;
pub const IDX_ARCHITECTURE: usize = 7;
pub const IDX_GLOBALPTR: usize = 8;
pub const IDX_TLS: usize = 9;
pub const IDX_LOADCONFIG: usize = 10;
pub const IDX_BOUNDIMPORT: usize = 11;
pub const IDX_IAT: usize = 12;
pub const IDX_DELAYIMPORT: usize = 13;
pub const IDX_CLR: usize = 14;
pub const IDX_RESERVED: usize = 15;

/// Parse the DataDirectory[16] block. PE32+ images set
/// `NumberOfRvaAndSizes == 16`; we tolerate fewer entries by zero-filling but
/// reject larger values which would indicate a malformed image.
pub fn parse(buf: &[u8], off: usize, count: u32) -> Result<[DataDirectory; 16]> {
    if count > 16 {
        bail!(
            "NumberOfRvaAndSizes={} exceeds the architectural maximum of 16",
            count
        );
    }
    let count = count as usize;
    let total = count
        .checked_mul(DataDirectory::SIZE)
        .context("data dir size overflow")?;
    if buf.len() < off.saturating_add(total) {
        bail!(
            "data directory @ 0x{:X} +{} bytes exceeds file (len={})",
            off,
            total,
            buf.len()
        );
    }
    let mut out = [DataDirectory::default(); 16];
    for i in 0..count {
        out[i] = DataDirectory::parse(buf, off + i * DataDirectory::SIZE)
            .with_context(|| format!("DataDirectory[{}] ({})", i, DIRECTORY_NAMES[i]))?;
    }
    Ok(out)
}
