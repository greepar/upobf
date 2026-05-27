//! `.note.*` / `PT_NOTE` segment parser.
//!
//! Each note entry is `(namesz: u32, descsz: u32, type: u32)` followed
//! by `name[namesz]` (NUL-terminated, padded to 4 bytes) and
//! `desc[descsz]` (padded to 4 bytes). We only surface the metadata
//! the inspector needs (`NT_GNU_BUILD_ID`, ABI tags) for fingerprint
//! detection.

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::reader;

pub const NT_GNU_BUILD_ID: u32 = 3;
pub const NT_GNU_ABI_TAG: u32 = 1;
pub const NT_GNU_PROPERTY_TYPE_0: u32 = 5;

#[derive(Debug, Clone, Serialize)]
pub struct NoteEntry {
    /// Owner name (e.g. `"GNU"`).
    pub name: String,
    pub note_type: u32,
    /// Descriptor bytes; for build-id this is the SHA1 (or similar).
    pub desc: Vec<u8>,
}

impl NoteEntry {
    /// Hex-format the descriptor bytes (lowercase). Convenience for
    /// inspector output.
    pub fn desc_hex(&self) -> String {
        let mut out = String::with_capacity(self.desc.len() * 2);
        for b in &self.desc {
            out.push_str(&format!("{:02x}", b));
        }
        out
    }
}

/// Parse all notes from a contiguous file range.
pub fn parse_notes(buf: &[u8], file_off: u64, size: u64) -> Result<Vec<NoteEntry>> {
    let mut out: Vec<NoteEntry> = Vec::new();
    let mut walked: u64 = 0;
    while walked + 12 <= size {
        let off = file_off as usize + walked as usize;
        let namesz = reader::u32(buf, off)
            .with_context(|| format!("namesz @ 0x{:X}", off))?;
        let descsz = reader::u32(buf, off + 4)
            .with_context(|| format!("descsz @ 0x{:X}", off + 4))?;
        let ntype = reader::u32(buf, off + 8)
            .with_context(|| format!("ntype @ 0x{:X}", off + 8))?;

        let name_off = off + 12;
        let name_padded = ((namesz + 3) & !3u32) as u64;
        let desc_padded = ((descsz + 3) & !3u32) as u64;
        let total = 12 + name_padded + desc_padded;
        if walked + total > size {
            bail!(
                "note overruns segment: walked={}+{} size={}",
                walked,
                total,
                size
            );
        }

        let name_slice = reader::slice(buf, name_off, namesz as usize)
            .context("note name bytes")?;
        let nul_pos = name_slice
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_slice.len());
        let name = String::from_utf8_lossy(&name_slice[..nul_pos]).into_owned();

        let desc_off = name_off + name_padded as usize;
        let desc = reader::slice(buf, desc_off, descsz as usize)
            .context("note desc bytes")?
            .to_vec();

        out.push(NoteEntry {
            name,
            note_type: ntype,
            desc,
        });
        walked += total;
    }
    Ok(out)
}
