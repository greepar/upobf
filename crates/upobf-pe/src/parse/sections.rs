//! IMAGE_SECTION_HEADER (40 bytes).

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::reader as r;

/// One IMAGE_SECTION_HEADER record.
#[derive(Debug, Clone, Serialize)]
pub struct SectionHeader {
    /// 8-byte name (NUL-padded). For long names (`/N` form) we keep the raw
    /// bytes; we do not currently resolve string-table references because the
    /// PEs upobf targets are all linker-stripped.
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    pub const SIZE: usize = 40;

    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = r::slice(buf, off, Self::SIZE).context("SectionHeader bytes")?;
        let name = decode_section_name(&s[0..8]);
        Ok(Self {
            name,
            virtual_size: r::u32(s, 8)?,
            virtual_address: r::u32(s, 12)?,
            size_of_raw_data: r::u32(s, 16)?,
            pointer_to_raw_data: r::u32(s, 20)?,
            pointer_to_relocations: r::u32(s, 24)?,
            pointer_to_linenumbers: r::u32(s, 28)?,
            number_of_relocations: r::u16(s, 32)?,
            number_of_linenumbers: r::u16(s, 34)?,
            characteristics: r::u32(s, 36)?,
        })
    }

    /// Decode the Characteristics bits into a compact "RWX/D" style string.
    pub fn protection_flags(&self) -> String {
        let mut s = String::new();
        if self.characteristics & 0x4000_0000 != 0 {
            s.push('R');
        }
        if self.characteristics & 0x8000_0000 != 0 {
            s.push('W');
        }
        if self.characteristics & 0x2000_0000 != 0 {
            s.push('X');
        }
        if self.characteristics & 0x0200_0000 != 0 {
            s.push_str(",DISCARD");
        }
        s
    }

    /// Test if `rva` falls inside this section's virtual range.
    pub fn contains_rva(&self, rva: u32) -> bool {
        let end = self
            .virtual_address
            .saturating_add(self.virtual_size.max(self.size_of_raw_data));
        rva >= self.virtual_address && rva < end
    }
}

/// Parse `count` consecutive section headers from `buf` starting at `off`.
pub fn parse_table(buf: &[u8], off: usize, count: usize) -> Result<Vec<SectionHeader>> {
    if count > 96 {
        // PE/COFF spec: NumberOfSections <= 96.
        bail!(
            "implausible NumberOfSections={} (> 96, refusing to parse)",
            count
        );
    }
    let total = count
        .checked_mul(SectionHeader::SIZE)
        .context("section table size overflow")?;
    if buf.len() < off.saturating_add(total) {
        bail!(
            "section table @ 0x{:X} +{} bytes exceeds file (len={})",
            off,
            total,
            buf.len()
        );
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let sec = SectionHeader::parse(buf, off + i * SectionHeader::SIZE)
            .with_context(|| format!("section #{}", i))?;
        out.push(sec);
    }
    Ok(out)
}

fn decode_section_name(bytes: &[u8]) -> String {
    let trimmed = match bytes.iter().position(|&b| b == 0) {
        Some(p) => &bytes[..p],
        None => bytes,
    };
    String::from_utf8_lossy(trimmed).into_owned()
}
