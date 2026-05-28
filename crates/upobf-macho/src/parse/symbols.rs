//! LC_SYMTAB and LC_DYSYMTAB parsers.
//!
//! Reference: <mach-o/loader.h> — struct symtab_command, struct dysymtab_command.
//! Reference: <mach-o/nlist.h> — struct nlist_64.

use anyhow::{Context, Result};
use serde::Serialize;

use super::reader;

// ---------------------------------------------------------------------------
// LC_SYMTAB (symtab_command: 24 bytes)
// ---------------------------------------------------------------------------

pub const SYMTAB_CMD_SIZE: usize = 24;

#[derive(Debug, Clone, Serialize)]
pub struct SymtabCmd {
    /// File offset of the symbol table (array of nlist_64).
    pub symoff: u32,
    /// Number of symbol table entries.
    pub nsyms: u32,
    /// File offset of the string table.
    pub stroff: u32,
    /// Size in bytes of the string table.
    pub strsize: u32,
}

impl SymtabCmd {
    /// Parse from the load command at `off` (pointing to cmd field).
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, SYMTAB_CMD_SIZE).context("symtab_command bytes")?;
        Ok(Self {
            symoff: reader::u32(s, 8)?,
            nsyms: reader::u32(s, 12)?,
            stroff: reader::u32(s, 16)?,
            strsize: reader::u32(s, 20)?,
        })
    }
}

// ---------------------------------------------------------------------------
// LC_DYSYMTAB (dysymtab_command: 80 bytes)
// ---------------------------------------------------------------------------

pub const DYSYMTAB_CMD_SIZE: usize = 80;

#[derive(Debug, Clone, Serialize)]
pub struct DysymtabCmd {
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

impl DysymtabCmd {
    /// Parse from the load command at `off` (pointing to cmd field).
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, DYSYMTAB_CMD_SIZE).context("dysymtab_command bytes")?;
        Ok(Self {
            ilocalsym: reader::u32(s, 8)?,
            nlocalsym: reader::u32(s, 12)?,
            iextdefsym: reader::u32(s, 16)?,
            nextdefsym: reader::u32(s, 20)?,
            iundefsym: reader::u32(s, 24)?,
            nundefsym: reader::u32(s, 28)?,
            tocoff: reader::u32(s, 32)?,
            ntoc: reader::u32(s, 36)?,
            modtaboff: reader::u32(s, 40)?,
            nmodtab: reader::u32(s, 44)?,
            extrefsymoff: reader::u32(s, 48)?,
            nextrefsyms: reader::u32(s, 52)?,
            indirectsymoff: reader::u32(s, 56)?,
            nindirectsyms: reader::u32(s, 60)?,
            extreloff: reader::u32(s, 64)?,
            nextrel: reader::u32(s, 68)?,
            locreloff: reader::u32(s, 72)?,
            nlocrel: reader::u32(s, 76)?,
        })
    }
}

// ---------------------------------------------------------------------------
// nlist_64 (16 bytes per entry)
// ---------------------------------------------------------------------------

pub const NLIST_64_SIZE: usize = 16;

// n_type masks.
pub const N_STAB: u8 = 0xE0;
pub const N_PEXT: u8 = 0x10;
pub const N_TYPE: u8 = 0x0E;
pub const N_EXT: u8 = 0x01;

// n_type values (after masking with N_TYPE).
pub const N_UNDF: u8 = 0x0;
pub const N_ABS: u8 = 0x2;
pub const N_SECT: u8 = 0xE;
pub const N_PBUD: u8 = 0xC;
pub const N_INDR: u8 = 0xA;

#[derive(Debug, Clone, Serialize)]
pub struct Nlist64 {
    /// Index into the string table.
    pub n_strx: u32,
    pub n_type: u8,
    /// Section number (1-based) or NO_SECT (0).
    pub n_sect: u8,
    pub n_desc: u16,
    /// Symbol value (address for defined symbols).
    pub n_value: u64,
    /// Resolved name from string table.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
}

impl Nlist64 {
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, NLIST_64_SIZE).context("nlist_64 bytes")?;
        Ok(Self {
            n_strx: reader::u32(s, 0)?,
            n_type: reader::u8_at(s, 4)?,
            n_sect: reader::u8_at(s, 5)?,
            n_desc: reader::u16(s, 6)?,
            n_value: reader::u64(s, 8)?,
            name: String::new(),
        })
    }

    /// Whether this is a debug/stab entry.
    pub fn is_stab(&self) -> bool {
        self.n_type & N_STAB != 0
    }

    /// Whether this symbol is external.
    pub fn is_external(&self) -> bool {
        self.n_type & N_EXT != 0
    }

    /// Whether this symbol is defined in a section.
    pub fn is_defined(&self) -> bool {
        (self.n_type & N_TYPE) == N_SECT
    }

    /// Whether this symbol is undefined (imported).
    pub fn is_undefined(&self) -> bool {
        (self.n_type & N_TYPE) == N_UNDF
    }
}

// ---------------------------------------------------------------------------
// Parsed symbol table info (aggregated)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct SymtabInfo {
    pub cmd: SymtabCmd,
    pub symbols: Vec<Nlist64>,
}

impl SymtabInfo {
    /// Parse the full symbol table given the symtab_command and the file buffer.
    pub fn from_cmd(buf: &[u8], cmd: &SymtabCmd) -> Result<Self> {
        let mut symbols = Vec::with_capacity(cmd.nsyms as usize);
        let mut off = cmd.symoff as usize;

        for i in 0..cmd.nsyms {
            let mut sym = Nlist64::parse(buf, off)
                .with_context(|| format!("nlist_64 #{}", i))?;

            // Resolve name from string table.
            let name_off = cmd.stroff as usize + sym.n_strx as usize;
            if name_off < buf.len() {
                sym.name = reader::cstring_at(buf, name_off).unwrap_or_default();
            }

            symbols.push(sym);
            off += NLIST_64_SIZE;
        }

        Ok(Self {
            cmd: cmd.clone(),
            symbols,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DysymtabInfo {
    pub cmd: DysymtabCmd,
    /// Indirect symbol table entries (array of u32 indices into symtab).
    pub indirect_syms: Vec<u32>,
}

impl DysymtabInfo {
    /// Parse the dysymtab info including the indirect symbol table.
    pub fn from_cmd(buf: &[u8], cmd: &DysymtabCmd) -> Result<Self> {
        let mut indirect_syms = Vec::with_capacity(cmd.nindirectsyms as usize);
        let mut off = cmd.indirectsymoff as usize;

        for i in 0..cmd.nindirectsyms {
            let idx = reader::u32(buf, off)
                .with_context(|| format!("indirect sym #{}", i))?;
            indirect_syms.push(idx);
            off += 4;
        }

        Ok(Self {
            cmd: cmd.clone(),
            indirect_syms,
        })
    }
}
