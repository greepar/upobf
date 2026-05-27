//! `.dynsym` / `.dynstr` parsing.
//!
//! Each `Elf64_Sym` is 24 bytes: name(u32), info(u8), other(u8),
//! shndx(u16), value(u64), size(u64).

use anyhow::{Context, Result};
use serde::Serialize;

use super::reader;

pub const SYM_ENTRY_SIZE: usize = 24;

// `st_info` packs binding (high 4 bits) and type (low 4 bits).
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_TLS: u8 = 6;
pub const STT_GNU_IFUNC: u8 = 10;

#[derive(Debug, Clone, Serialize)]
pub struct DynSymbol {
    /// Resolved name from `.dynstr` (empty if `st_name == 0`).
    pub name: String,
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

impl DynSymbol {
    pub fn binding(&self) -> u8 {
        (self.st_info >> 4) & 0xF
    }
    pub fn sym_type(&self) -> u8 {
        self.st_info & 0xF
    }
    pub fn is_undefined(&self) -> bool {
        self.st_shndx == 0
    }
}

/// Parse `.dynsym` from `(file_off, total_size)` bytes, resolving
/// names against `dynstr`. The caller must ensure `dynstr` covers
/// the relevant strings (typically the entire `DT_STRTAB` blob).
pub fn parse_dynsym_table(
    buf: &[u8],
    file_off: u64,
    size: u64,
    dynstr: &[u8],
) -> Result<Vec<DynSymbol>> {
    if size % SYM_ENTRY_SIZE as u64 != 0 {
        anyhow::bail!(
            ".dynsym size 0x{:X} not multiple of {}",
            size,
            SYM_ENTRY_SIZE
        );
    }
    let count = (size / SYM_ENTRY_SIZE as u64) as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let entry_off = file_off as usize + i * SYM_ENTRY_SIZE;
        let s = reader::slice(buf, entry_off, SYM_ENTRY_SIZE)
            .with_context(|| format!("DynSym #{}", i))?;
        let st_name = reader::u32(s, 0)?;
        let st_info = reader::u8(s, 4)?;
        let st_other = reader::u8(s, 5)?;
        let st_shndx = reader::u16(s, 6)?;
        let st_value = reader::u64(s, 8)?;
        let st_size = reader::u64(s, 16)?;

        let name = if st_name == 0 || (st_name as usize) >= dynstr.len() {
            String::new()
        } else {
            let slice = &dynstr[st_name as usize..];
            let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
            String::from_utf8_lossy(&slice[..nul]).into_owned()
        };

        out.push(DynSymbol {
            name,
            st_name,
            st_info,
            st_other,
            st_shndx,
            st_value,
            st_size,
        });
    }
    Ok(out)
}
