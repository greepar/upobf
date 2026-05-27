//! `.rela.dyn` / `.rela.plt` parsing for x86_64 ELF64.
//!
//! Each entry is `Elf64_Rela { r_offset:u64, r_info:u64, r_addend:i64 }`.
//! `r_info` packs the symbol index in the high 32 bits and the
//! relocation type in the low 32 bits.

use anyhow::{Context, Result};
use serde::Serialize;

use super::reader;

pub const RELA_ENTRY_SIZE: usize = 24;

/// Selected x86_64 relocation type codes (see `<elf.h>`).
pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_GOT32: u32 = 3;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_COPY: u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_GOTPCREL: u32 = 9;
pub const R_X86_64_32: u32 = 10;
pub const R_X86_64_32S: u32 = 11;
pub const R_X86_64_TPOFF64: u32 = 18;
pub const R_X86_64_DTPMOD64: u32 = 16;
pub const R_X86_64_DTPOFF64: u32 = 17;
pub const R_X86_64_IRELATIVE: u32 = 37;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

impl Rela {
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, RELA_ENTRY_SIZE).context("Rela bytes")?;
        Ok(Self {
            r_offset: reader::u64(s, 0)?,
            r_info: reader::u64(s, 8)?,
            r_addend: reader::u64(s, 16)? as i64,
        })
    }

    /// Relocation type (low 32 bits of r_info).
    pub fn r_type(&self) -> u32 {
        (self.r_info & 0xFFFF_FFFF) as u32
    }

    /// Relocation symbol index (high 32 bits of r_info).
    pub fn r_sym(&self) -> u32 {
        (self.r_info >> 32) as u32
    }
}

/// Parse a contiguous .rela section.
pub fn parse_rela_table(buf: &[u8], file_off: u64, size: u64) -> Result<Vec<Rela>> {
    if size % RELA_ENTRY_SIZE as u64 != 0 {
        anyhow::bail!(
            ".rela size 0x{:X} not multiple of {}",
            size,
            RELA_ENTRY_SIZE
        );
    }
    let count = (size / RELA_ENTRY_SIZE as u64) as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = file_off as usize + i * RELA_ENTRY_SIZE;
        out.push(Rela::parse(buf, off).with_context(|| format!("Rela #{}", i))?);
    }
    Ok(out)
}

/// Counts of relocation kinds in `.rela.dyn` / `.rela.plt`. Used by
/// the inspector and to gate special-case handling in the writer
/// (e.g. `R_X86_64_RELATIVE` re-bases stub fixups; `JUMP_SLOT`
/// counts feed PLT classification).
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct RelaSummary {
    pub total: usize,
    pub relative: usize,
    pub jump_slot: usize,
    pub glob_dat: usize,
    pub abs64: usize,
    pub irelative: usize,
    pub other: usize,
}

impl RelaSummary {
    pub fn count(entries: &[Rela]) -> Self {
        let mut s = RelaSummary::default();
        for r in entries {
            s.total += 1;
            match r.r_type() {
                R_X86_64_RELATIVE => s.relative += 1,
                R_X86_64_JUMP_SLOT => s.jump_slot += 1,
                R_X86_64_GLOB_DAT => s.glob_dat += 1,
                R_X86_64_64 => s.abs64 += 1,
                R_X86_64_IRELATIVE => s.irelative += 1,
                _ => s.other += 1,
            }
        }
        s
    }
}
