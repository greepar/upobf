//! ELF parsing entry point.
//!
//! `ElfImage::from_file` reads a PIE/ET_EXEC ELF64 from disk, validates
//! the headers, and walks the program/section/dynamic structures that
//! upobf cares about for M0L: phdr table, shdr+shstrtab, PT_DYNAMIC,
//! .rela.dyn / .rela.plt, .dynsym/.dynstr, .eh_frame_hdr, notes.

pub mod dynamic;
pub mod eh_frame;
pub mod headers;
pub mod notes;
pub mod relocations;
pub mod symbols;
pub mod segments;

pub(crate) mod reader;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::Path;

use dynamic::DynamicInfo;
use eh_frame::EhFrameHdr;
use headers::{
    Elf64Ehdr, Elf64Phdr, Elf64Shdr, PT_DYNAMIC, PT_GNU_EH_FRAME, PT_NOTE,
};
use notes::NoteEntry;
use relocations::{Rela, RelaSummary};
use symbols::DynSymbol;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// In-memory representation of a parsed ELF64 image.
#[derive(Debug, Clone, Serialize)]
pub struct ElfImage {
    /// Original file bytes (kept verbatim for downstream M1L reuse).
    #[serde(skip)]
    pub raw: Vec<u8>,
    pub ehdr: Elf64Ehdr,
    pub phdrs: Vec<Elf64Phdr>,
    pub shdrs: Vec<Elf64Shdr>,
    pub dynamic: Option<DynamicInfo>,

    /// All `DT_NEEDED` library names resolved from `.dynstr`.
    pub needed: Vec<String>,

    /// .rela.dyn entries (RELATIVE / GLOB_DAT / abs64 / ifunc / ...).
    pub rela_dyn: Vec<Rela>,
    /// .rela.plt entries (JUMP_SLOT).
    pub rela_plt: Vec<Rela>,

    pub rela_dyn_summary: RelaSummary,
    pub rela_plt_summary: RelaSummary,

    pub dynsym: Vec<DynSymbol>,

    pub eh_frame_hdr: Option<EhFrameHdr>,
    pub notes: Vec<NoteEntry>,
}

// ---------------------------------------------------------------------------
// Top-level parser
// ---------------------------------------------------------------------------

impl ElfImage {
    /// Read an ELF file from disk and return the structured representation.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read(path)
            .with_context(|| format!("read {}", path.display()))?;
        Self::from_bytes(raw)
            .with_context(|| format!("parse {}", path.display()))
    }

    /// Parse an ELF image from an owned byte buffer.
    pub fn from_bytes(raw: Vec<u8>) -> Result<Self> {
        let ehdr = Elf64Ehdr::parse(&raw).context("Ehdr")?;

        let phdrs = headers::parse_phdr_table(&raw, ehdr.e_phoff, ehdr.e_phnum)
            .context("phdr table")?;
        let shdrs = if ehdr.e_shnum > 0 {
            headers::parse_shdr_table(&raw, ehdr.e_shoff, ehdr.e_shnum, ehdr.e_shstrndx)
                .context("shdr table")?
        } else {
            Vec::new()
        };

        // ---- PT_DYNAMIC ----
        let mut dynamic: Option<DynamicInfo> = None;
        let mut dynstr_blob: Vec<u8> = Vec::new();
        if let Some(pdyn) = phdrs.iter().find(|p| p.p_type == PT_DYNAMIC) {
            let info = DynamicInfo::parse(&raw, pdyn.p_offset, pdyn.p_filesz)
                .context("PT_DYNAMIC")?;
            // Resolve .dynstr blob to a vec for name lookups.
            if let (Some(strtab_va), Some(strsz)) = (info.strtab, info.strsz) {
                let (file_off, _) = segments::vaddr_to_file_offset(&phdrs, strtab_va)
                    .context("DT_STRTAB -> file offset")?;
                let end = file_off
                    .checked_add(strsz)
                    .context("DT_STRTAB+STRSZ overflow")?;
                if end as usize > raw.len() {
                    bail!(
                        ".dynstr past EOF: 0x{:X}+0x{:X} > 0x{:X}",
                        file_off,
                        strsz,
                        raw.len()
                    );
                }
                dynstr_blob =
                    raw[file_off as usize..end as usize].to_vec();
            }
            dynamic = Some(info);
        }

        // ---- DT_NEEDED resolution ----
        let mut needed: Vec<String> = Vec::new();
        if let Some(d) = &dynamic {
            for off in &d.needed_offsets {
                if let Ok(name) = dynamic::read_needed_name(&dynstr_blob, *off) {
                    needed.push(name);
                }
            }
        }

        // ---- Relocation tables ----
        let (rela_dyn, rela_plt) = if let Some(d) = &dynamic {
            let rela_dyn = if let (Some(rela_va), Some(sz)) = (d.rela, d.relasz) {
                let (off, _) = segments::vaddr_to_file_offset(&phdrs, rela_va)
                    .context("DT_RELA -> file offset")?;
                relocations::parse_rela_table(&raw, off, sz).context(".rela.dyn")?
            } else {
                Vec::new()
            };
            let rela_plt = if let (Some(jmp_va), Some(sz)) = (d.jmprel, d.pltrelsz) {
                let (off, _) = segments::vaddr_to_file_offset(&phdrs, jmp_va)
                    .context("DT_JMPREL -> file offset")?;
                relocations::parse_rela_table(&raw, off, sz).context(".rela.plt")?
            } else {
                Vec::new()
            };
            (rela_dyn, rela_plt)
        } else {
            (Vec::new(), Vec::new())
        };
        let rela_dyn_summary = RelaSummary::count(&rela_dyn);
        let rela_plt_summary = RelaSummary::count(&rela_plt);

        // ---- DynSym ----
        let dynsym = if let Some(d) = &dynamic {
            if let (Some(symtab_va), Some(syment)) = (d.symtab, d.syment) {
                if syment as usize != symbols::SYM_ENTRY_SIZE {
                    bail!(
                        "DT_SYMENT {} != ELF64 sym size {}",
                        syment,
                        symbols::SYM_ENTRY_SIZE
                    );
                }
                let (sym_off, _) = segments::vaddr_to_file_offset(&phdrs, symtab_va)
                    .context("DT_SYMTAB -> file offset")?;
                // Size of .dynsym is *not* in DT_*; derive from the
                // section header table (DYNSYM) when available, else
                // walk to STRTAB which conventionally follows.
                let size = shdrs
                    .iter()
                    .find(|s| s.sh_type == headers::SHT_DYNSYM)
                    .map(|s| s.sh_size)
                    .unwrap_or_else(|| {
                        // Fallback: derive from gap to STRTAB.
                        if let Some(strtab) = d.strtab {
                            if strtab > symtab_va {
                                strtab - symtab_va
                            } else {
                                0
                            }
                        } else {
                            0
                        }
                    });
                if size > 0 {
                    symbols::parse_dynsym_table(&raw, sym_off, size, &dynstr_blob)
                        .context(".dynsym")?
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // ---- eh_frame_hdr ----
        let eh_frame_hdr = phdrs
            .iter()
            .find(|p| p.p_type == PT_GNU_EH_FRAME)
            .map(|p| EhFrameHdr::parse(&raw, p.p_offset, p.p_filesz))
            .transpose()
            .context("PT_GNU_EH_FRAME")?;

        // ---- Notes ----
        let mut all_notes: Vec<NoteEntry> = Vec::new();
        for p in phdrs.iter().filter(|p| p.p_type == PT_NOTE) {
            let mut ns = notes::parse_notes(&raw, p.p_offset, p.p_filesz)
                .context("PT_NOTE")?;
            all_notes.append(&mut ns);
        }

        Ok(Self {
            raw,
            ehdr,
            phdrs,
            shdrs,
            dynamic,
            needed,
            rela_dyn,
            rela_plt,
            rela_dyn_summary,
            rela_plt_summary,
            dynsym,
            eh_frame_hdr,
            notes: all_notes,
        })
    }

    /// Convenience: section by name.
    pub fn section(&self, name: &str) -> Option<&Elf64Shdr> {
        self.shdrs.iter().find(|s| s.name == name)
    }

    /// `e_type == ET_DYN`. Implies PIE for executables, DSO for
    /// libraries; we treat both the same way (load slide applied by
    /// ld.so).
    pub fn is_pie(&self) -> bool {
        self.ehdr.e_type == headers::ET_DYN
    }

    /// Translate a vaddr (== RVA in our packer terms) to file offset.
    pub fn vaddr_to_file_offset(&self, vaddr: u64) -> Result<u64> {
        Ok(segments::vaddr_to_file_offset(&self.phdrs, vaddr)?.0)
    }

    /// Produce a JSON inspection report.
    pub fn to_json_report(&self) -> Result<String> {
        let report = self.json_value();
        serde_json::to_string_pretty(&report).context("serialize ELF JSON report")
    }

    pub fn json_value(&self) -> serde_json::Value {
        use serde_json::json;

        let phdrs_json: Vec<_> = self
            .phdrs
            .iter()
            .map(|p| {
                json!({
                    "type": p.type_name(),
                    "type_raw": p.p_type,
                    "flags": p.flag_string(),
                    "offset": p.p_offset,
                    "vaddr": p.p_vaddr,
                    "filesz": p.p_filesz,
                    "memsz": p.p_memsz,
                    "align": p.p_align,
                })
            })
            .collect();

        let shdrs_json: Vec<_> = self
            .shdrs
            .iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "type": s.type_name(),
                    "flags": s.flag_string(),
                    "addr": s.sh_addr,
                    "offset": s.sh_offset,
                    "size": s.sh_size,
                })
            })
            .collect();

        let notes_json: Vec<_> = self
            .notes
            .iter()
            .map(|n| {
                json!({
                    "name": n.name,
                    "type": n.note_type,
                    "desc_hex": n.desc_hex(),
                })
            })
            .collect();

        json!({
            "header": {
                "type": self.ehdr.type_name(),
                "machine": self.ehdr.e_machine,
                "entry": self.ehdr.e_entry,
                "phoff": self.ehdr.e_phoff,
                "shoff": self.ehdr.e_shoff,
                "phnum": self.ehdr.e_phnum,
                "shnum": self.ehdr.e_shnum,
                "shstrndx": self.ehdr.e_shstrndx,
                "is_pie": self.is_pie(),
            },
            "phdrs": phdrs_json,
            "shdrs": shdrs_json,
            "dynamic": self.dynamic,
            "needed": self.needed,
            "rela_dyn_summary": self.rela_dyn_summary,
            "rela_plt_summary": self.rela_plt_summary,
            "eh_frame_hdr": self.eh_frame_hdr,
            "notes": notes_json,
        })
    }
}
