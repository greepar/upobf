//! `PT_DYNAMIC` / `.dynamic` section parsing.
//!
//! Walks the array of `Elf64_Dyn` entries that the dynamic linker
//! consumes. Each entry is `(d_tag: i64, d_un: u64)` — for upobf we
//! only care about a small subset of the standard tags.

use anyhow::{Context, Result};
use serde::Serialize;

use super::reader;

// d_tag values relevant to upobf (subset of <elf.h> definitions).
pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_PLTGOT: i64 = 3;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_INIT: i64 = 12;
pub const DT_FINI: i64 = 13;
pub const DT_SONAME: i64 = 14;
pub const DT_RPATH: i64 = 15;
pub const DT_SYMBOLIC: i64 = 16;
pub const DT_REL: i64 = 17;
pub const DT_RELSZ: i64 = 18;
pub const DT_RELENT: i64 = 19;
pub const DT_PLTREL: i64 = 20;
pub const DT_DEBUG: i64 = 21;
pub const DT_TEXTREL: i64 = 22;
pub const DT_JMPREL: i64 = 23;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_INIT_ARRAY: i64 = 25;
pub const DT_FINI_ARRAY: i64 = 26;
pub const DT_INIT_ARRAYSZ: i64 = 27;
pub const DT_FINI_ARRAYSZ: i64 = 28;
pub const DT_RUNPATH: i64 = 29;
pub const DT_FLAGS: i64 = 30;
pub const DT_PREINIT_ARRAY: i64 = 32;
pub const DT_PREINIT_ARRAYSZ: i64 = 33;

pub const DT_GNU_HASH: i64 = 0x6FFF_FEF5;
pub const DT_RELACOUNT: i64 = 0x6FFF_FFF9;
pub const DT_RELCOUNT: i64 = 0x6FFF_FFFA;
pub const DT_FLAGS_1: i64 = 0x6FFF_FFFB;
pub const DT_VERDEF: i64 = 0x6FFF_FFFC;
pub const DT_VERDEFNUM: i64 = 0x6FFF_FFFD;
pub const DT_VERNEED: i64 = 0x6FFF_FFFE;
pub const DT_VERNEEDNUM: i64 = 0x6FFF_FFFF;
pub const DT_VERSYM: i64 = 0x6FFF_FFF0;

pub const DT_ENTRY_SIZE: usize = 16;

/// One raw entry (`d_tag`, `d_un`) from `.dynamic`. We keep tags as
/// `i64` since the standard prescribes `Elf64_Sxword` (signed) for
/// `d_tag`.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DynamicEntry {
    pub tag: i64,
    pub val: u64,
}

/// Aggregated view of `.dynamic` for the fields upobf cares about.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DynamicInfo {
    pub raw: Vec<DynamicEntry>,
    pub needed_offsets: Vec<u64>,

    pub strtab: Option<u64>,
    pub strsz: Option<u64>,
    pub symtab: Option<u64>,
    pub syment: Option<u64>,

    pub rela: Option<u64>,
    pub relasz: Option<u64>,
    pub relaent: Option<u64>,
    pub relacount: Option<u64>,

    pub jmprel: Option<u64>,
    pub pltrelsz: Option<u64>,
    pub pltrel: Option<u64>,
    pub pltgot: Option<u64>,

    pub init: Option<u64>,
    pub fini: Option<u64>,
    pub init_array: Option<u64>,
    pub init_arraysz: Option<u64>,
    pub fini_array: Option<u64>,
    pub fini_arraysz: Option<u64>,
    pub preinit_array: Option<u64>,
    pub preinit_arraysz: Option<u64>,

    pub gnu_hash: Option<u64>,
    pub flags: Option<u64>,
    pub flags_1: Option<u64>,

    /// `(file_offset_in_buf, length_in_bytes)` of the dynamic section
    /// itself. Captured here so the writer can rewrite individual
    /// entries in place when injecting `.init_array` overrides.
    pub file_offset: u64,
    pub file_size: u64,
}

impl DynamicInfo {
    /// Parse `.dynamic` starting at `file_off` for `size` bytes.
    pub fn parse(buf: &[u8], file_off: u64, size: u64) -> Result<Self> {
        let mut info = DynamicInfo::default();
        info.file_offset = file_off;
        info.file_size = size;

        let mut walked: u64 = 0;
        while walked < size {
            let entry_off = file_off as usize + walked as usize;
            let tag = reader::u64(buf, entry_off)
                .with_context(|| format!("dynamic entry tag @ 0x{:X}", entry_off))?
                as i64;
            let val = reader::u64(buf, entry_off + 8)
                .with_context(|| format!("dynamic entry val @ 0x{:X}", entry_off + 8))?;
            info.raw.push(DynamicEntry { tag, val });
            match tag {
                DT_NULL => {
                    break;
                }
                DT_NEEDED => info.needed_offsets.push(val),
                DT_STRTAB => info.strtab = Some(val),
                DT_STRSZ => info.strsz = Some(val),
                DT_SYMTAB => info.symtab = Some(val),
                DT_SYMENT => info.syment = Some(val),
                DT_RELA => info.rela = Some(val),
                DT_RELASZ => info.relasz = Some(val),
                DT_RELAENT => info.relaent = Some(val),
                DT_RELACOUNT => info.relacount = Some(val),
                DT_JMPREL => info.jmprel = Some(val),
                DT_PLTRELSZ => info.pltrelsz = Some(val),
                DT_PLTREL => info.pltrel = Some(val),
                DT_PLTGOT => info.pltgot = Some(val),
                DT_INIT => info.init = Some(val),
                DT_FINI => info.fini = Some(val),
                DT_INIT_ARRAY => info.init_array = Some(val),
                DT_INIT_ARRAYSZ => info.init_arraysz = Some(val),
                DT_FINI_ARRAY => info.fini_array = Some(val),
                DT_FINI_ARRAYSZ => info.fini_arraysz = Some(val),
                DT_PREINIT_ARRAY => info.preinit_array = Some(val),
                DT_PREINIT_ARRAYSZ => info.preinit_arraysz = Some(val),
                DT_GNU_HASH => info.gnu_hash = Some(val),
                DT_FLAGS => info.flags = Some(val),
                DT_FLAGS_1 => info.flags_1 = Some(val),
                _ => {}
            }
            walked += DT_ENTRY_SIZE as u64;
        }
        Ok(info)
    }
}

/// Resolve a `DT_NEEDED` offset into a string by indexing into the
/// dynstr blob (already located via `DT_STRTAB`/`DT_STRSZ`).
pub fn read_needed_name(dynstr: &[u8], offset: u64) -> Result<String> {
    if offset as usize >= dynstr.len() {
        anyhow::bail!(
            "DT_NEEDED offset 0x{:X} >= .dynstr size 0x{:X}",
            offset,
            dynstr.len()
        );
    }
    let slice = &dynstr[offset as usize..];
    let nul = slice
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow::anyhow!("unterminated DT_NEEDED string @ 0x{:X}", offset))?;
    Ok(String::from_utf8_lossy(&slice[..nul]).into_owned())
}
