//! PE parsing entry point.
//!
//! `PeImage::from_file` reads a PE32+ file from disk, validates the headers,
//! and walks the data directories that upobf cares about for M1: TLS, Load
//! Config, Exception (.pdata), Imports, Exports, Delay-Imports.
//!
//! This module deliberately depends only on `byteorder` for primitive reads
//! and decodes everything in safe Rust through bounds-checked slice helpers
//! (see [`reader`]). No third-party PE crate is used.

pub mod data_dir;
pub mod headers;
pub mod load_config;
pub mod pdata;
pub mod sections;
pub mod tls;

pub(crate) mod reader;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::Path;

use data_dir::{DataDirectory, DIRECTORY_NAMES};
use headers::{DosHeader, NtHeaders64};
use load_config::LoadConfig;
use pdata::PdataInfo;
use sections::SectionHeader;
use tls::TlsDirectory;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// In-memory representation of a parsed PE32+ image.
#[derive(Debug, Clone, Serialize)]
pub struct PeImage {
    /// Original file bytes (kept verbatim for downstream M2/M3 reuse).
    #[serde(skip)]
    pub raw: Vec<u8>,
    pub dos: DosHeader,
    pub nt: NtHeaders64,
    pub sections: Vec<SectionHeader>,
    pub data_dirs: [DataDirectory; 16],
    pub tls: Option<TlsDirectory>,
    pub load_config: Option<LoadConfig>,
    pub pdata: Option<PdataInfo>,
    pub imports: ImportSummary,
    pub delay_imports: DelayImportSummary,
    pub export: Option<ExportSummary>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportSummary {
    pub dlls: Vec<ImportedDll>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportedDll {
    pub name: String,
    pub original_first_thunk_rva: u32,
    pub first_thunk_rva: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub functions: Vec<ImportedFunction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportedFunction {
    /// Function name (when imported by name).
    pub name: Option<String>,
    /// Hint (paired with name) or ordinal (when imported by ordinal).
    pub hint_or_ordinal: u16,
    /// True if imported by ordinal (high bit of thunk was set).
    pub by_ordinal: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DelayImportSummary {
    pub dlls: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportSummary {
    pub name: Option<String>,
    pub ordinal_base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    /// First name in `AddressOfNames` (just enough to confirm the table walks).
    pub first_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Top-level parser
// ---------------------------------------------------------------------------

impl PeImage {
    /// Read a PE file from disk and return the structured representation.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read(path)
            .with_context(|| format!("read {}", path.display()))?;
        Self::from_bytes(raw)
            .with_context(|| format!("parse {}", path.display()))
    }

    /// Parse a PE image from an owned byte buffer.
    pub fn from_bytes(raw: Vec<u8>) -> Result<Self> {
        let dos = DosHeader::parse(&raw).context("DOS header")?;

        // Validate that e_lfanew points within the file.
        let nt_off = dos.e_lfanew as usize;
        // We need at least signature(4) + FileHeader(20) + OptionalHeaderPrefix(112)
        // before we can know how big the directory tail is.
        let min_nt = nt_off
            .checked_add(4 + headers::FileHeader::SIZE + headers::OptionalHeader64::PREFIX_SIZE)
            .context("e_lfanew overflow")?;
        if min_nt > raw.len() {
            bail!(
                "e_lfanew=0x{:X} points past end of file (file len={})",
                nt_off,
                raw.len()
            );
        }

        let nt = NtHeaders64::parse(&raw, nt_off).context("NT headers")?;

        // DataDirectory follows the optional-header prefix.
        let dd_off = nt_off + 4 + headers::FileHeader::SIZE + headers::OptionalHeader64::PREFIX_SIZE;
        let data_dirs = data_dir::parse(&raw, dd_off, nt.optional_header.number_of_rva_and_sizes)
            .context("DataDirectory")?;

        // Section table follows the optional header (SizeOfOptionalHeader bytes after FileHeader).
        let sect_off = nt_off + 4 + headers::FileHeader::SIZE
            + nt.file_header.size_of_optional_header as usize;
        let sections = sections::parse_table(
            &raw,
            sect_off,
            nt.file_header.number_of_sections as usize,
        )
        .context("section table")?;

        // ---- TLS ----
        let tls_dir = data_dirs[data_dir::IDX_TLS];
        let tls = if tls_dir.is_present() {
            Some(
                TlsDirectory::parse(
                    &raw,
                    &sections,
                    tls_dir.virtual_address,
                    nt.optional_header.image_base,
                )
                .context("TLS directory")?,
            )
        } else {
            None
        };

        // ---- LoadConfig ----
        let lc_dir = data_dirs[data_dir::IDX_LOADCONFIG];
        let load_config = if lc_dir.is_present() {
            Some(
                LoadConfig::parse(&raw, &sections, lc_dir.virtual_address, lc_dir.size)
                    .context("LoadConfig directory")?,
            )
        } else {
            None
        };

        // ---- .pdata ----
        let pdata_dir = data_dirs[data_dir::IDX_EXCEPTION];
        let pdata = if pdata_dir.is_present() {
            Some(
                PdataInfo::parse(&raw, &sections, pdata_dir.virtual_address, pdata_dir.size)
                    .context("Exception directory")?,
            )
        } else {
            None
        };

        // ---- Imports ----
        let imp_dir = data_dirs[data_dir::IDX_IMPORT];
        let imports = if imp_dir.is_present() {
            parse_imports(&raw, &sections, imp_dir.virtual_address, imp_dir.size)
                .context("Import directory")?
        } else {
            ImportSummary::default()
        };

        // ---- Delay-Imports ----
        let dimp_dir = data_dirs[data_dir::IDX_DELAYIMPORT];
        let delay_imports = if dimp_dir.is_present() {
            parse_delay_imports(&raw, &sections, dimp_dir.virtual_address)
                .context("DelayImport directory")?
        } else {
            DelayImportSummary::default()
        };

        // ---- Export ----
        let exp_dir = data_dirs[data_dir::IDX_EXPORT];
        let export = if exp_dir.is_present() {
            Some(
                parse_export(&raw, &sections, exp_dir.virtual_address)
                    .context("Export directory")?,
            )
        } else {
            None
        };

        Ok(Self {
            raw,
            dos,
            nt,
            sections,
            data_dirs,
            tls,
            load_config,
            pdata,
            imports,
            delay_imports,
            export,
        })
    }

    /// Translate an RVA into a file offset using the section table.
    pub fn rva_to_file_offset(&self, rva: u32) -> Result<usize> {
        tls::rva_to_file_offset(&self.sections, rva)
    }

    /// Produce a JSON inspection report aligned to design plan §9.4.
    pub fn to_json_report(&self) -> Result<String> {
        let report = self.json_value();
        serde_json::to_string_pretty(&report).context("serialize JSON report")
    }

    /// Build the structured JSON value (separate from `to_json_report` so that
    /// callers can embed the report into a larger document if needed).
    pub fn json_value(&self) -> serde_json::Value {
        use serde_json::json;

        let oh = &self.nt.optional_header;
        let fh = &self.nt.file_header;

        let sections_json: Vec<_> = self
            .sections
            .iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "virtual_address": s.virtual_address,
                    "virtual_size": s.virtual_size,
                    "pointer_to_raw_data": s.pointer_to_raw_data,
                    "size_of_raw_data": s.size_of_raw_data,
                    "characteristics": s.characteristics,
                    "protection": s.protection_flags(),
                })
            })
            .collect();

        let data_dirs_json: Vec<_> = self
            .data_dirs
            .iter()
            .enumerate()
            .map(|(i, d)| {
                json!({
                    "index": i,
                    "name": DIRECTORY_NAMES[i],
                    "rva": d.virtual_address,
                    "size": d.size,
                })
            })
            .collect();

        json!({
            "dos": {
                "e_magic": self.dos.e_magic,
                "e_lfanew": self.dos.e_lfanew,
            },
            "file_header": {
                "machine": fh.machine,
                "number_of_sections": fh.number_of_sections,
                "time_date_stamp": fh.time_date_stamp,
                "size_of_optional_header": fh.size_of_optional_header,
                "characteristics": fh.characteristics,
                "characteristics_flags": fh.characteristics_flags(),
            },
            "optional_header": {
                "magic": oh.magic,
                "linker_version": format!("{}.{}", oh.major_linker_version, oh.minor_linker_version),
                "address_of_entry_point": oh.address_of_entry_point,
                "image_base": oh.image_base,
                "section_alignment": oh.section_alignment,
                "file_alignment": oh.file_alignment,
                "size_of_image": oh.size_of_image,
                "size_of_headers": oh.size_of_headers,
                "subsystem": oh.subsystem,
                "subsystem_name": oh.subsystem_name(),
                "subsystem_version": format!("{}.{}", oh.major_subsystem_version, oh.minor_subsystem_version),
                "dll_characteristics": oh.dll_characteristics,
                "dll_characteristics_flags": oh.dll_characteristics_flags(),
                "size_of_stack_reserve": oh.size_of_stack_reserve,
                "size_of_stack_commit": oh.size_of_stack_commit,
                "size_of_heap_reserve": oh.size_of_heap_reserve,
                "size_of_heap_commit": oh.size_of_heap_commit,
                "number_of_rva_and_sizes": oh.number_of_rva_and_sizes,
            },
            "data_directories": data_dirs_json,
            "sections": sections_json,
            "tls": self.tls,
            "load_config": self.load_config,
            "pdata": self.pdata,
            "imports": self.imports,
            "delay_imports": self.delay_imports,
            "export": self.export,
        })
    }
}

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

/// Size of one IMAGE_IMPORT_DESCRIPTOR.
const IMPORT_DESC_SIZE: usize = 20;
/// Hard cap on the number of DLLs we are willing to parse from a single image
/// (PatchInstaller has 25; anything > 1024 is almost certainly malformed).
const MAX_IMPORT_DLLS: usize = 1024;
/// Hard cap on the number of imports per DLL.
const MAX_IMPORTS_PER_DLL: usize = 65_536;

fn parse_imports(
    buf: &[u8],
    sections: &[SectionHeader],
    dir_rva: u32,
    _dir_size: u32,
) -> Result<ImportSummary> {
    let mut dlls = Vec::new();

    for i in 0..MAX_IMPORT_DLLS {
        let entry_rva = dir_rva + (i * IMPORT_DESC_SIZE) as u32;
        let entry_off = tls::rva_to_file_offset(sections, entry_rva)
            .with_context(|| format!("Import descriptor #{}", i))?;
        let s = reader::slice(buf, entry_off, IMPORT_DESC_SIZE)
            .with_context(|| format!("Import descriptor #{} bytes", i))?;
        let original_first_thunk = reader::u32(s, 0)?;
        let time_date_stamp = reader::u32(s, 4)?;
        let forwarder_chain = reader::u32(s, 8)?;
        let name_rva = reader::u32(s, 12)?;
        let first_thunk = reader::u32(s, 16)?;

        // NULL terminator: all-zero descriptor.
        if original_first_thunk == 0
            && time_date_stamp == 0
            && forwarder_chain == 0
            && name_rva == 0
            && first_thunk == 0
        {
            break;
        }

        let name = read_cstring_at_rva(buf, sections, name_rva)
            .with_context(|| format!("Import DLL #{} name @ RVA 0x{:08X}", i, name_rva))?;

        // Use OriginalFirstThunk if present (ILT), else fall back to FirstThunk (IAT).
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let functions = parse_thunks(buf, sections, thunk_rva)
            .with_context(|| format!("Import DLL '{}' thunks", name))?;

        dlls.push(ImportedDll {
            name,
            original_first_thunk_rva: original_first_thunk,
            first_thunk_rva: first_thunk,
            time_date_stamp,
            forwarder_chain,
            functions,
        });

        if dlls.len() >= MAX_IMPORT_DLLS {
            bail!(
                "Import directory exceeds {} DLLs without NULL terminator",
                MAX_IMPORT_DLLS
            );
        }
    }

    Ok(ImportSummary { dlls })
}

fn parse_thunks(
    buf: &[u8],
    sections: &[SectionHeader],
    thunk_rva: u32,
) -> Result<Vec<ImportedFunction>> {
    if thunk_rva == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let base_off = tls::rva_to_file_offset(sections, thunk_rva)?;
    const ORDINAL_FLAG_64: u64 = 0x8000_0000_0000_0000;

    for i in 0..MAX_IMPORTS_PER_DLL {
        let entry_off = base_off
            .checked_add(i * 8)
            .context("thunk offset overflow")?;
        let v = reader::u64(buf, entry_off)
            .with_context(|| format!("thunk[{}] @ 0x{:X}", i, entry_off))?;
        if v == 0 {
            break;
        }
        if v & ORDINAL_FLAG_64 != 0 {
            // Imported by ordinal: low 16 bits.
            let ord = (v & 0xFFFF) as u16;
            out.push(ImportedFunction {
                name: None,
                hint_or_ordinal: ord,
                by_ordinal: true,
            });
        } else {
            // Imported by name: low 31 bits = RVA of IMAGE_IMPORT_BY_NAME (Hint:u16, Name:char[]).
            let name_rva = (v & 0x7FFF_FFFF) as u32;
            let off = tls::rva_to_file_offset(sections, name_rva)
                .with_context(|| format!("import-by-name RVA 0x{:08X}", name_rva))?;
            let hint = reader::u16(buf, off)?;
            let name = read_cstring_at_offset(buf, off + 2)
                .with_context(|| format!("import-by-name @ 0x{:X}", off + 2))?;
            out.push(ImportedFunction {
                name: Some(name),
                hint_or_ordinal: hint,
                by_ordinal: false,
            });
        }
        if i + 1 == MAX_IMPORTS_PER_DLL {
            bail!("thunk array exceeds {} entries", MAX_IMPORTS_PER_DLL);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Delay-Imports
// ---------------------------------------------------------------------------

/// Size of one IMAGE_DELAYLOAD_DESCRIPTOR.
const DELAY_DESC_SIZE: usize = 32;

fn parse_delay_imports(
    buf: &[u8],
    sections: &[SectionHeader],
    dir_rva: u32,
) -> Result<DelayImportSummary> {
    let mut dlls = Vec::new();
    for i in 0..MAX_IMPORT_DLLS {
        let entry_rva = dir_rva + (i * DELAY_DESC_SIZE) as u32;
        let entry_off = tls::rva_to_file_offset(sections, entry_rva)
            .with_context(|| format!("DelayImport descriptor #{}", i))?;
        let s = reader::slice(buf, entry_off, DELAY_DESC_SIZE)
            .with_context(|| format!("DelayImport descriptor #{} bytes", i))?;
        // Layout (V2): Attributes(4), DllNameRVA(4), ModuleHandleRVA(4),
        // ImportAddressTableRVA(4), ImportNameTableRVA(4), BoundIATRVA(4),
        // UnloadIATRVA(4), TimeStamp(4).
        let attributes = reader::u32(s, 0)?;
        let name_rva = reader::u32(s, 4)?;
        let iat_rva = reader::u32(s, 12)?;
        if attributes == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }
        let name = read_cstring_at_rva(buf, sections, name_rva)
            .with_context(|| format!("DelayImport #{} name @ RVA 0x{:08X}", i, name_rva))?;
        dlls.push(name);
    }
    Ok(DelayImportSummary { dlls })
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

fn parse_export(
    buf: &[u8],
    sections: &[SectionHeader],
    dir_rva: u32,
) -> Result<ExportSummary> {
    let off = tls::rva_to_file_offset(sections, dir_rva)
        .with_context(|| format!("Export directory RVA 0x{:08X}", dir_rva))?;
    // IMAGE_EXPORT_DIRECTORY (40 bytes).
    let s = reader::slice(buf, off, 40).context("Export directory bytes")?;
    let _characteristics = reader::u32(s, 0)?;
    let _time_date_stamp = reader::u32(s, 4)?;
    let _major = reader::u16(s, 8)?;
    let _minor = reader::u16(s, 10)?;
    let name_rva = reader::u32(s, 12)?;
    let ordinal_base = reader::u32(s, 16)?;
    let number_of_functions = reader::u32(s, 20)?;
    let number_of_names = reader::u32(s, 24)?;
    let _addr_of_funcs = reader::u32(s, 28)?;
    let address_of_names = reader::u32(s, 32)?;
    let _addr_of_name_ords = reader::u32(s, 36)?;

    let name = if name_rva != 0 {
        Some(read_cstring_at_rva(buf, sections, name_rva)?)
    } else {
        None
    };

    let first_name = if address_of_names != 0 && number_of_names > 0 {
        let names_off = tls::rva_to_file_offset(sections, address_of_names)?;
        let first_rva = reader::u32(buf, names_off)?;
        Some(read_cstring_at_rva(buf, sections, first_rva)?)
    } else {
        None
    };

    Ok(ExportSummary {
        name,
        ordinal_base,
        number_of_functions,
        number_of_names,
        first_name,
    })
}

// ---------------------------------------------------------------------------
// CString helpers
// ---------------------------------------------------------------------------

/// Read a NUL-terminated ASCII/UTF-8 string starting at the given file offset.
/// Caps the length at 1 KiB to avoid runaway scans on malformed images.
fn read_cstring_at_offset(buf: &[u8], off: usize) -> Result<String> {
    const MAX_LEN: usize = 1024;
    if off >= buf.len() {
        bail!(
            "string offset 0x{:X} >= file len 0x{:X}",
            off,
            buf.len()
        );
    }
    let limit = (off + MAX_LEN).min(buf.len());
    let slice = &buf[off..limit];
    let nul = slice
        .iter()
        .position(|&b| b == 0)
        .with_context(|| format!("unterminated C-string @ 0x{:X}", off))?;
    Ok(String::from_utf8_lossy(&slice[..nul]).into_owned())
}

fn read_cstring_at_rva(buf: &[u8], sections: &[SectionHeader], rva: u32) -> Result<String> {
    let off = tls::rva_to_file_offset(sections, rva)?;
    read_cstring_at_offset(buf, off)
}
