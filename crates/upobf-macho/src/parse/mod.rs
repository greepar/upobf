//! Mach-O parsing entry point.
//!
//! `MachoImage::from_file` reads a Mach-O 64-bit arm64 binary from disk,
//! validates the header, and walks all load commands to populate the
//! structured representation needed by the packer.

pub mod chained_fixups;
pub mod dylib;
pub mod headers;
pub mod segments;
pub mod symbols;

pub(crate) mod reader;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::Path;

use chained_fixups::ChainedFixupsInfo;
use dylib::{
    BuildVersionCmd, DylibCmd, ExportsTrieCmd, LinkEditDataCmd, MainCmd, RpathCmd, UuidCmd,
};
use headers::{
    LoadCmdHeader, MachHeader64, LC_BUILD_VERSION, LC_CODE_SIGNATURE, LC_DATA_IN_CODE,
    LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE, LC_DYSYMTAB, LC_FUNCTION_STARTS,
    LC_ID_DYLIB, LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_MAIN, LC_REEXPORT_DYLIB, LC_RPATH,
    LC_SEGMENT_64, LC_SYMTAB, LC_UUID,
};
use segments::SegmentCommand64;
use symbols::{DysymtabInfo, DysymtabCmd, SymtabCmd, SymtabInfo};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// In-memory representation of a parsed Mach-O 64-bit image.
#[derive(Debug, Clone, Serialize)]
pub struct MachoImage {
    /// Original file bytes (kept verbatim for downstream writer reuse).
    #[serde(skip)]
    pub raw: Vec<u8>,

    pub header: MachHeader64,

    /// All load command headers (for iteration / unknown LC passthrough).
    pub load_cmds: Vec<LoadCmdHeader>,

    /// LC_SEGMENT_64 entries (in order).
    pub segments: Vec<SegmentCommand64>,

    /// LC_SYMTAB parsed info.
    pub symtab: Option<SymtabInfo>,

    /// LC_DYSYMTAB parsed info.
    pub dysymtab: Option<DysymtabInfo>,

    /// LC_DYLD_CHAINED_FIXUPS (header-level only).
    pub chained_fixups: Option<ChainedFixupsInfo>,

    /// LC_DYLD_EXPORTS_TRIE location.
    pub exports_trie: Option<ExportsTrieCmd>,

    /// All LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB / LC_REEXPORT_DYLIB entries.
    pub dylibs: Vec<DylibCmd>,

    /// LC_RPATH entries.
    pub rpaths: Vec<RpathCmd>,

    /// LC_MAIN (entry point).
    pub main_cmd: Option<MainCmd>,

    /// LC_BUILD_VERSION.
    pub build_version: Option<BuildVersionCmd>,

    /// LC_CODE_SIGNATURE.
    pub code_signature: Option<LinkEditDataCmd>,

    /// LC_FUNCTION_STARTS.
    pub function_starts: Option<LinkEditDataCmd>,

    /// LC_DATA_IN_CODE.
    pub data_in_code: Option<LinkEditDataCmd>,

    /// LC_UUID.
    pub uuid: Option<UuidCmd>,
}

// ---------------------------------------------------------------------------
// Top-level parser
// ---------------------------------------------------------------------------

impl MachoImage {
    /// Read a Mach-O file from disk and return the structured representation.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read(path)
            .with_context(|| format!("read {}", path.display()))?;
        Self::from_bytes(raw)
            .with_context(|| format!("parse {}", path.display()))
    }

    /// Parse a Mach-O image from an owned byte buffer.
    pub fn from_bytes(raw: Vec<u8>) -> Result<Self> {
        let header = MachHeader64::parse(&raw).context("mach_header_64")?;

        let load_cmds = headers::parse_load_commands(&raw, header.ncmds, header.sizeofcmds)
            .context("load commands")?;

        let mut segments: Vec<SegmentCommand64> = Vec::new();
        let mut symtab_cmd: Option<SymtabCmd> = None;
        let mut dysymtab_cmd: Option<DysymtabCmd> = None;
        let mut chained_fixups_cmd: Option<chained_fixups::ChainedFixupsCmd> = None;
        let mut exports_trie: Option<ExportsTrieCmd> = None;
        let mut dylibs: Vec<DylibCmd> = Vec::new();
        let mut rpaths: Vec<RpathCmd> = Vec::new();
        let mut main_cmd: Option<MainCmd> = None;
        let mut build_version: Option<BuildVersionCmd> = None;
        let mut code_signature: Option<LinkEditDataCmd> = None;
        let mut function_starts: Option<LinkEditDataCmd> = None;
        let mut data_in_code: Option<LinkEditDataCmd> = None;
        let mut uuid: Option<UuidCmd> = None;

        // Dispatch each load command to its specific parser.
        for lc in &load_cmds {
            match lc.cmd {
                LC_SEGMENT_64 => {
                    let seg = SegmentCommand64::parse(&raw, lc.offset, lc.cmdsize)
                        .with_context(|| {
                            format!("LC_SEGMENT_64 @ 0x{:X}", lc.offset)
                        })?;
                    segments.push(seg);
                }
                LC_SYMTAB => {
                    symtab_cmd = Some(
                        SymtabCmd::parse(&raw, lc.offset)
                            .context("LC_SYMTAB")?,
                    );
                }
                LC_DYSYMTAB => {
                    dysymtab_cmd = Some(
                        DysymtabCmd::parse(&raw, lc.offset)
                            .context("LC_DYSYMTAB")?,
                    );
                }
                LC_DYLD_CHAINED_FIXUPS => {
                    chained_fixups_cmd = Some(
                        chained_fixups::ChainedFixupsCmd::parse(&raw, lc.offset)
                            .context("LC_DYLD_CHAINED_FIXUPS")?,
                    );
                }
                LC_DYLD_EXPORTS_TRIE => {
                    exports_trie = Some(
                        ExportsTrieCmd::parse(&raw, lc.offset)
                            .context("LC_DYLD_EXPORTS_TRIE")?,
                    );
                }
                LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_ID_DYLIB => {
                    let d = DylibCmd::parse(&raw, lc.offset, lc.cmd, lc.cmdsize)
                        .with_context(|| {
                            format!("{} @ 0x{:X}", lc.cmd_name(), lc.offset)
                        })?;
                    dylibs.push(d);
                }
                LC_RPATH => {
                    let r = RpathCmd::parse(&raw, lc.offset, lc.cmdsize)
                        .context("LC_RPATH")?;
                    rpaths.push(r);
                }
                LC_MAIN => {
                    main_cmd = Some(
                        MainCmd::parse(&raw, lc.offset).context("LC_MAIN")?,
                    );
                }
                LC_BUILD_VERSION => {
                    build_version = Some(
                        BuildVersionCmd::parse(&raw, lc.offset)
                            .context("LC_BUILD_VERSION")?,
                    );
                }
                LC_CODE_SIGNATURE => {
                    code_signature = Some(
                        LinkEditDataCmd::parse(&raw, lc.offset, lc.cmd)
                            .context("LC_CODE_SIGNATURE")?,
                    );
                }
                LC_FUNCTION_STARTS => {
                    function_starts = Some(
                        LinkEditDataCmd::parse(&raw, lc.offset, lc.cmd)
                            .context("LC_FUNCTION_STARTS")?,
                    );
                }
                LC_DATA_IN_CODE => {
                    data_in_code = Some(
                        LinkEditDataCmd::parse(&raw, lc.offset, lc.cmd)
                            .context("LC_DATA_IN_CODE")?,
                    );
                }
                LC_UUID => {
                    uuid = Some(
                        UuidCmd::parse(&raw, lc.offset).context("LC_UUID")?,
                    );
                }
                _ => {
                    // Unknown/unhandled load commands are preserved in load_cmds
                    // for passthrough by the writer.
                }
            }
        }

        // Validate: we need at least LC_MAIN or LC_UNIXTHREAD for an executable.
        if header.filetype == headers::MH_EXECUTE && main_cmd.is_none() {
            bail!("MH_EXECUTE without LC_MAIN (LC_UNIXTHREAD not supported)");
        }

        // Validate: LC_BUILD_VERSION should be present.
        if build_version.is_none() {
            // Not fatal, but warn-worthy. Some older binaries use LC_VERSION_MIN_MACOSX.
            // We'll handle this gracefully.
        }

        // Parse full symbol table if LC_SYMTAB present.
        let symtab = if let Some(ref cmd) = symtab_cmd {
            Some(SymtabInfo::from_cmd(&raw, cmd).context("symtab parse")?)
        } else {
            None
        };

        // Parse dysymtab if present.
        let dysymtab = if let Some(ref cmd) = dysymtab_cmd {
            Some(DysymtabInfo::from_cmd(&raw, cmd).context("dysymtab parse")?)
        } else {
            None
        };

        // Parse chained fixups if present.
        let chained_fixups = if let Some(ref cmd) = chained_fixups_cmd {
            Some(
                ChainedFixupsInfo::from_cmd(&raw, cmd)
                    .context("chained fixups parse")?,
            )
        } else {
            None
        };

        Ok(Self {
            raw,
            header,
            load_cmds,
            segments,
            symtab,
            dysymtab,
            chained_fixups,
            exports_trie,
            dylibs,
            rpaths,
            main_cmd,
            build_version,
            code_signature,
            function_starts,
            data_in_code,
            uuid,
        })
    }

    // -----------------------------------------------------------------------
    // Convenience accessors
    // -----------------------------------------------------------------------

    /// Find a segment by name.
    pub fn segment(&self, name: &str) -> Option<&SegmentCommand64> {
        self.segments.iter().find(|s| s.segname == name)
    }

    /// Find a section by "segname,sectname" (e.g. "__TEXT,__text").
    pub fn section(&self, segname: &str, sectname: &str) -> Option<&segments::Section64> {
        self.segment(segname)
            .and_then(|seg| seg.section(sectname))
    }

    /// Whether this is a PIE executable.
    pub fn is_pie(&self) -> bool {
        self.header.is_pie()
    }

    /// Get the entry point file offset (LC_MAIN.entryoff is relative to
    /// __TEXT segment's file offset, which is typically 0).
    pub fn entry_file_offset(&self) -> Option<u64> {
        self.main_cmd.as_ref().map(|m| m.entryoff)
    }

    /// List of dependent dylib names (LC_LOAD_DYLIB only, not ID/REEXPORT).
    pub fn needed_dylibs(&self) -> Vec<&str> {
        self.dylibs
            .iter()
            .filter(|d| {
                d.cmd == headers::LC_LOAD_DYLIB || d.cmd == headers::LC_LOAD_WEAK_DYLIB
            })
            .map(|d| d.name.as_str())
            .collect()
    }

    /// Translate a virtual address to file offset using segment table.
    pub fn vaddr_to_file_offset(&self, vaddr: u64) -> Result<u64> {
        Ok(segments::vaddr_to_file_offset(&self.segments, vaddr)?.0)
    }

    /// Produce a JSON inspection report (for debugging / CLI inspect command).
    pub fn to_json_report(&self) -> Result<String> {
        let report = self.json_value();
        serde_json::to_string_pretty(&report).context("serialize Mach-O JSON report")
    }

    pub fn json_value(&self) -> serde_json::Value {
        use serde_json::json;

        let segments_json: Vec<_> = self
            .segments
            .iter()
            .map(|seg| {
                let sections_json: Vec<_> = seg
                    .sections
                    .iter()
                    .map(|s| {
                        json!({
                            "sectname": s.sectname,
                            "segname": s.segname,
                            "addr": format!("0x{:X}", s.addr),
                            "size": s.size,
                            "offset": s.offset,
                            "flags": format!("0x{:08X}", s.flags),
                        })
                    })
                    .collect();
                json!({
                    "segname": seg.segname,
                    "vmaddr": format!("0x{:X}", seg.vmaddr),
                    "vmsize": format!("0x{:X}", seg.vmsize),
                    "fileoff": format!("0x{:X}", seg.fileoff),
                    "filesize": format!("0x{:X}", seg.filesize),
                    "prot": seg.prot_string(),
                    "nsects": seg.nsects,
                    "sections": sections_json,
                })
            })
            .collect();

        let dylibs_json: Vec<_> = self
            .dylibs
            .iter()
            .map(|d| {
                json!({
                    "name": d.name,
                    "current_version": DylibCmd::version_string(d.current_version),
                    "compat_version": DylibCmd::version_string(d.compat_version),
                })
            })
            .collect();

        let lc_summary: Vec<_> = self
            .load_cmds
            .iter()
            .map(|lc| {
                json!({
                    "cmd": lc.cmd_name(),
                    "cmd_raw": format!("0x{:08X}", lc.cmd),
                    "cmdsize": lc.cmdsize,
                    "offset": format!("0x{:X}", lc.offset),
                })
            })
            .collect();

        json!({
            "header": {
                "magic": format!("0x{:08X}", self.header.magic),
                "cputype": format!("0x{:08X}", self.header.cputype),
                "cpusubtype": format!("0x{:08X}", self.header.cpusubtype),
                "filetype": self.header.filetype_name(),
                "ncmds": self.header.ncmds,
                "sizeofcmds": self.header.sizeofcmds,
                "flags": format!("0x{:08X}", self.header.flags),
                "pie": self.header.is_pie(),
            },
            "load_commands": lc_summary,
            "segments": segments_json,
            "dylibs": dylibs_json,
            "main": self.main_cmd.as_ref().map(|m| json!({
                "entryoff": format!("0x{:X}", m.entryoff),
                "stacksize": m.stacksize,
            })),
            "build_version": self.build_version.as_ref().map(|bv| json!({
                "platform": bv.platform_name(),
                "minos": bv.minos_string(),
                "sdk": bv.sdk_string(),
            })),
            "uuid": self.uuid.as_ref().map(|u| u.uuid_string()),
            "chained_fixups": self.chained_fixups.as_ref().map(|cf| json!({
                "imports_count": cf.imports_count,
                "starts_seg_count": cf.starts.seg_count,
            })),
            "exports_trie": self.exports_trie.as_ref().map(|et| json!({
                "dataoff": format!("0x{:X}", et.dataoff),
                "datasize": et.datasize,
            })),
            "symtab": self.symtab.as_ref().map(|st| json!({
                "nsyms": st.cmd.nsyms,
                "strsize": st.cmd.strsize,
            })),
            "code_signature": self.code_signature.as_ref().map(|cs| json!({
                "dataoff": format!("0x{:X}", cs.dataoff),
                "datasize": cs.datasize,
            })),
        })
    }
}
