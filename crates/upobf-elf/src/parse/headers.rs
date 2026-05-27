//! ELF64 header parsers: Ehdr / Phdr / Shdr.
//!
//! All structures use the System V ELF64 layout (little-endian, 8-byte
//! aligned) defined in the LSB / glibc headers.

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::reader;

// ---------------------------------------------------------------------------
// Constants (e_ident / e_type / e_machine / p_type / p_flags / sh_type / sh_flags)
// ---------------------------------------------------------------------------

pub const EI_NIDENT: usize = 16;
pub const ELFMAG: [u8; 4] = [0x7F, b'E', b'L', b'F'];

pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EV_CURRENT: u8 = 1;

pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

pub const EM_X86_64: u16 = 62;

// Program header types.
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_E550;
pub const PT_GNU_STACK: u32 = 0x6474_E551;
pub const PT_GNU_RELRO: u32 = 0x6474_E552;
pub const PT_GNU_PROPERTY: u32 = 0x6474_E553;

pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

// Section header types.
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;
pub const SHT_PREINIT_ARRAY: u32 = 16;
pub const SHT_GROUP: u32 = 17;
pub const SHT_GNU_HASH: u32 = 0x6FFF_FFF6;
pub const SHT_GNU_VERDEF: u32 = 0x6FFF_FFFD;
pub const SHT_GNU_VERNEED: u32 = 0x6FFF_FFFE;
pub const SHT_GNU_VERSYM: u32 = 0x6FFF_FFFF;

pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_MERGE: u64 = 0x10;
pub const SHF_STRINGS: u64 = 0x20;
pub const SHF_INFO_LINK: u64 = 0x40;
pub const SHF_LINK_ORDER: u64 = 0x80;
pub const SHF_OS_NONCONFORMING: u64 = 0x100;
pub const SHF_GROUP: u64 = 0x200;
pub const SHF_TLS: u64 = 0x400;

// ---------------------------------------------------------------------------
// Ehdr (64 bytes for ELF64)
// ---------------------------------------------------------------------------

pub const EHDR64_SIZE: usize = 64;

#[derive(Debug, Clone, Serialize)]
pub struct Elf64Ehdr {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl Elf64Ehdr {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let s = reader::slice(buf, 0, EHDR64_SIZE).context("Ehdr bytes")?;
        if s[..4] != ELFMAG {
            bail!(
                "bad ELF magic: {:02X} {:02X} {:02X} {:02X}",
                s[0], s[1], s[2], s[3]
            );
        }
        if s[4] != ELFCLASS64 {
            bail!("unsupported ELF class: {} (expected ELFCLASS64=2)", s[4]);
        }
        if s[5] != ELFDATA2LSB {
            bail!("unsupported ELF data encoding: {} (expected ELFDATA2LSB=1)", s[5]);
        }
        let mut ident = [0u8; EI_NIDENT];
        ident.copy_from_slice(&s[..EI_NIDENT]);

        let e_type = reader::u16(s, 0x10)?;
        let e_machine = reader::u16(s, 0x12)?;
        let e_version = reader::u32(s, 0x14)?;
        let e_entry = reader::u64(s, 0x18)?;
        let e_phoff = reader::u64(s, 0x20)?;
        let e_shoff = reader::u64(s, 0x28)?;
        let e_flags = reader::u32(s, 0x30)?;
        let e_ehsize = reader::u16(s, 0x34)?;
        let e_phentsize = reader::u16(s, 0x36)?;
        let e_phnum = reader::u16(s, 0x38)?;
        let e_shentsize = reader::u16(s, 0x3A)?;
        let e_shnum = reader::u16(s, 0x3C)?;
        let e_shstrndx = reader::u16(s, 0x3E)?;

        if e_machine != EM_X86_64 {
            bail!("unsupported machine: 0x{:04X} (expected EM_X86_64=62)", e_machine);
        }
        if e_type != ET_EXEC && e_type != ET_DYN {
            bail!(
                "unsupported e_type: {} (expected ET_EXEC=2 or ET_DYN=3)",
                e_type
            );
        }
        if e_phentsize as usize != PHDR64_SIZE {
            bail!("e_phentsize {} != {}", e_phentsize, PHDR64_SIZE);
        }
        if e_shnum > 0 && e_shentsize as usize != SHDR64_SIZE {
            bail!("e_shentsize {} != {}", e_shentsize, SHDR64_SIZE);
        }

        Ok(Self {
            e_ident: ident,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        })
    }

    /// Human-readable name for `e_type`.
    pub fn type_name(&self) -> &'static str {
        match self.e_type {
            ET_NONE => "NONE",
            ET_REL => "REL",
            ET_EXEC => "EXEC",
            ET_DYN => "DYN",
            ET_CORE => "CORE",
            _ => "UNKNOWN",
        }
    }
}

// ---------------------------------------------------------------------------
// Phdr (56 bytes for ELF64)
// ---------------------------------------------------------------------------

pub const PHDR64_SIZE: usize = 56;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl Elf64Phdr {
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, PHDR64_SIZE).context("Phdr bytes")?;
        Ok(Self {
            p_type: reader::u32(s, 0)?,
            p_flags: reader::u32(s, 4)?,
            p_offset: reader::u64(s, 8)?,
            p_vaddr: reader::u64(s, 16)?,
            p_paddr: reader::u64(s, 24)?,
            p_filesz: reader::u64(s, 32)?,
            p_memsz: reader::u64(s, 40)?,
            p_align: reader::u64(s, 48)?,
        })
    }

    pub fn type_name(&self) -> &'static str {
        match self.p_type {
            PT_NULL => "NULL",
            PT_LOAD => "LOAD",
            PT_DYNAMIC => "DYNAMIC",
            PT_INTERP => "INTERP",
            PT_NOTE => "NOTE",
            PT_SHLIB => "SHLIB",
            PT_PHDR => "PHDR",
            PT_TLS => "TLS",
            PT_GNU_EH_FRAME => "GNU_EH_FRAME",
            PT_GNU_STACK => "GNU_STACK",
            PT_GNU_RELRO => "GNU_RELRO",
            PT_GNU_PROPERTY => "GNU_PROPERTY",
            _ => "OTHER",
        }
    }

    /// Symbolic flag string (e.g. `R E`, `RW`, `R`).
    pub fn flag_string(&self) -> String {
        let mut s = String::new();
        s.push(if self.p_flags & PF_R != 0 { 'R' } else { ' ' });
        s.push(if self.p_flags & PF_W != 0 { 'W' } else { ' ' });
        s.push(if self.p_flags & PF_X != 0 { 'E' } else { ' ' });
        s
    }
}

/// Parse all program-header table entries.
pub fn parse_phdr_table(buf: &[u8], off: u64, count: u16) -> Result<Vec<Elf64Phdr>> {
    let off = off as usize;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let entry_off = off
            .checked_add(i * PHDR64_SIZE)
            .ok_or_else(|| anyhow::anyhow!("phdr offset overflow at i={}", i))?;
        out.push(
            Elf64Phdr::parse(buf, entry_off)
                .with_context(|| format!("Phdr #{}", i))?,
        );
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Shdr (64 bytes for ELF64)
// ---------------------------------------------------------------------------

pub const SHDR64_SIZE: usize = 64;

#[derive(Debug, Clone, Serialize)]
pub struct Elf64Shdr {
    /// Resolved name (set after `parse_shdr_table` walks `.shstrtab`).
    /// Empty until name resolution.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

impl Elf64Shdr {
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, SHDR64_SIZE).context("Shdr bytes")?;
        Ok(Self {
            name: String::new(),
            sh_name: reader::u32(s, 0)?,
            sh_type: reader::u32(s, 4)?,
            sh_flags: reader::u64(s, 8)?,
            sh_addr: reader::u64(s, 16)?,
            sh_offset: reader::u64(s, 24)?,
            sh_size: reader::u64(s, 32)?,
            sh_link: reader::u32(s, 40)?,
            sh_info: reader::u32(s, 44)?,
            sh_addralign: reader::u64(s, 48)?,
            sh_entsize: reader::u64(s, 56)?,
        })
    }

    pub fn type_name(&self) -> &'static str {
        match self.sh_type {
            SHT_NULL => "NULL",
            SHT_PROGBITS => "PROGBITS",
            SHT_SYMTAB => "SYMTAB",
            SHT_STRTAB => "STRTAB",
            SHT_RELA => "RELA",
            SHT_HASH => "HASH",
            SHT_DYNAMIC => "DYNAMIC",
            SHT_NOTE => "NOTE",
            SHT_NOBITS => "NOBITS",
            SHT_REL => "REL",
            SHT_DYNSYM => "DYNSYM",
            SHT_INIT_ARRAY => "INIT_ARRAY",
            SHT_FINI_ARRAY => "FINI_ARRAY",
            SHT_PREINIT_ARRAY => "PREINIT_ARRAY",
            SHT_GROUP => "GROUP",
            SHT_GNU_HASH => "GNU_HASH",
            SHT_GNU_VERDEF => "VERDEF",
            SHT_GNU_VERNEED => "VERNEED",
            SHT_GNU_VERSYM => "VERSYM",
            _ => "OTHER",
        }
    }

    pub fn flag_string(&self) -> String {
        let mut s = String::new();
        if self.sh_flags & SHF_WRITE != 0 { s.push('W'); }
        if self.sh_flags & SHF_ALLOC != 0 { s.push('A'); }
        if self.sh_flags & SHF_EXECINSTR != 0 { s.push('X'); }
        if self.sh_flags & SHF_MERGE != 0 { s.push('M'); }
        if self.sh_flags & SHF_STRINGS != 0 { s.push('S'); }
        if self.sh_flags & SHF_INFO_LINK != 0 { s.push('I'); }
        if self.sh_flags & SHF_TLS != 0 { s.push('T'); }
        s
    }

    pub fn is_alloc(&self) -> bool {
        self.sh_flags & SHF_ALLOC != 0
    }

    pub fn is_writable(&self) -> bool {
        self.sh_flags & SHF_WRITE != 0
    }

    pub fn is_executable(&self) -> bool {
        self.sh_flags & SHF_EXECINSTR != 0
    }
}

/// Parse all section-header entries and resolve names from `.shstrtab`.
pub fn parse_shdr_table(
    buf: &[u8],
    off: u64,
    count: u16,
    shstrndx: u16,
) -> Result<Vec<Elf64Shdr>> {
    let off = off as usize;
    let mut out: Vec<Elf64Shdr> = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let entry_off = off
            .checked_add(i * SHDR64_SIZE)
            .ok_or_else(|| anyhow::anyhow!("shdr offset overflow at i={}", i))?;
        out.push(
            Elf64Shdr::parse(buf, entry_off)
                .with_context(|| format!("Shdr #{}", i))?,
        );
    }

    // Resolve names from .shstrtab.
    if (shstrndx as usize) < out.len() {
        let strtab = out[shstrndx as usize].clone();
        let strtab_off = strtab.sh_offset as usize;
        let strtab_end = strtab_off
            .checked_add(strtab.sh_size as usize)
            .context("shstrtab overflow")?;
        if strtab_end > buf.len() {
            bail!(
                ".shstrtab past EOF: 0x{:X}+0x{:X} > 0x{:X}",
                strtab_off,
                strtab.sh_size,
                buf.len()
            );
        }
        for sh in out.iter_mut() {
            let name_off = strtab_off + sh.sh_name as usize;
            sh.name = reader::cstring_at(buf, name_off)
                .unwrap_or_else(|_| String::new());
        }
    }

    Ok(out)
}
