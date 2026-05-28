//! Mach-O 64-bit header parser: mach_header_64 + load_command constants.
//!
//! Reference: <mach-o/loader.h> from Apple's open-source headers.

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::reader;

// ---------------------------------------------------------------------------
// Magic / CPU / Filetype constants
// ---------------------------------------------------------------------------

pub const MH_MAGIC_64: u32 = 0xFEED_FACF;
pub const MH_CIGAM_64: u32 = 0xCFFA_EDFE; // big-endian (unsupported)

pub const CPU_TYPE_ARM64: u32 = 0x0100_000C; // CPU_TYPE_ARM | CPU_ARCH_ABI64
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
pub const CPU_SUBTYPE_ARM64E: u32 = 2;

// Mach-O file types we accept.
pub const MH_EXECUTE: u32 = 2;
pub const MH_DYLIB: u32 = 6;
pub const MH_BUNDLE: u32 = 8;

// Mach-O header flags (subset we care about).
pub const MH_PIE: u32 = 0x0020_0000;
pub const MH_DYLDLINK: u32 = 0x0000_0004;
pub const MH_TWOLEVEL: u32 = 0x0000_0080;

// ---------------------------------------------------------------------------
// Load command types
// ---------------------------------------------------------------------------

pub const LC_REQ_DYLD: u32 = 0x8000_0000;

pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_SYMTAB: u32 = 0x02;
pub const LC_DYSYMTAB: u32 = 0x0B;
pub const LC_LOAD_DYLIB: u32 = 0x0C;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub const LC_ID_DYLIB: u32 = 0x0D;
pub const LC_RPATH: u32 = 0x1C | LC_REQ_DYLD;
pub const LC_REEXPORT_DYLIB: u32 = 0x1F | LC_REQ_DYLD;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_CODE_SIGNATURE: u32 = 0x1D;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_SOURCE_VERSION: u32 = 0x2A;
pub const LC_UUID: u32 = 0x1B;
pub const LC_UNIXTHREAD: u32 = 0x05;

// ---------------------------------------------------------------------------
// mach_header_64 (32 bytes)
// ---------------------------------------------------------------------------

pub const MACH_HEADER_64_SIZE: usize = 32;

#[derive(Debug, Clone, Serialize)]
pub struct MachHeader64 {
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: u32,
}

impl MachHeader64 {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let s = reader::slice(buf, 0, MACH_HEADER_64_SIZE).context("mach_header_64 bytes")?;

        let magic = reader::u32(s, 0)?;
        if magic == MH_CIGAM_64 {
            bail!("big-endian Mach-O (MH_CIGAM_64) is not supported");
        }
        if magic != MH_MAGIC_64 {
            bail!(
                "bad Mach-O magic: 0x{:08X} (expected MH_MAGIC_64=0xFEEDFACF)",
                magic
            );
        }

        let cputype = reader::u32(s, 4)?;
        let cpusubtype = reader::u32(s, 8)?;
        let filetype = reader::u32(s, 12)?;
        let ncmds = reader::u32(s, 16)?;
        let sizeofcmds = reader::u32(s, 20)?;
        let flags = reader::u32(s, 24)?;
        let reserved = reader::u32(s, 28)?;

        // Validate CPU type.
        if cputype != CPU_TYPE_ARM64 {
            bail!(
                "unsupported cputype: 0x{:08X} (expected CPU_TYPE_ARM64=0x0100000C)",
                cputype
            );
        }

        // Validate file type.
        if filetype != MH_EXECUTE && filetype != MH_DYLIB && filetype != MH_BUNDLE {
            bail!(
                "unsupported filetype: {} (expected MH_EXECUTE=2, MH_DYLIB=6, or MH_BUNDLE=8)",
                filetype
            );
        }

        Ok(Self {
            magic,
            cputype,
            cpusubtype,
            filetype,
            ncmds,
            sizeofcmds,
            flags,
            reserved,
        })
    }

    /// Human-readable name for `filetype`.
    pub fn filetype_name(&self) -> &'static str {
        match self.filetype {
            MH_EXECUTE => "EXECUTE",
            MH_DYLIB => "DYLIB",
            MH_BUNDLE => "BUNDLE",
            _ => "UNKNOWN",
        }
    }

    /// Whether the binary is position-independent (PIE).
    pub fn is_pie(&self) -> bool {
        self.flags & MH_PIE != 0
    }
}

// ---------------------------------------------------------------------------
// Generic load_command header (8 bytes: cmd + cmdsize)
// ---------------------------------------------------------------------------

pub const LOAD_CMD_HEADER_SIZE: usize = 8;

/// Raw load command header — just cmd + cmdsize.
/// Used for iterating the LC table before dispatching to specific parsers.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct LoadCmdHeader {
    pub cmd: u32,
    pub cmdsize: u32,
    /// File offset where this load command starts.
    pub offset: usize,
}

impl LoadCmdHeader {
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, LOAD_CMD_HEADER_SIZE)
            .context("load_command header")?;
        let cmd = reader::u32(s, 0)?;
        let cmdsize = reader::u32(s, 4)?;
        if cmdsize < LOAD_CMD_HEADER_SIZE as u32 {
            bail!(
                "load command @ 0x{:X}: cmdsize {} < minimum {}",
                off,
                cmdsize,
                LOAD_CMD_HEADER_SIZE
            );
        }
        Ok(Self {
            cmd,
            cmdsize,
            offset: off,
        })
    }

    /// Human-readable name for the load command type.
    pub fn cmd_name(&self) -> &'static str {
        match self.cmd {
            LC_SEGMENT_64 => "LC_SEGMENT_64",
            LC_SYMTAB => "LC_SYMTAB",
            LC_DYSYMTAB => "LC_DYSYMTAB",
            LC_LOAD_DYLIB => "LC_LOAD_DYLIB",
            LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB",
            LC_ID_DYLIB => "LC_ID_DYLIB",
            LC_RPATH => "LC_RPATH",
            LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB",
            LC_MAIN => "LC_MAIN",
            LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY",
            LC_DYLD_CHAINED_FIXUPS => "LC_DYLD_CHAINED_FIXUPS",
            LC_DYLD_EXPORTS_TRIE => "LC_DYLD_EXPORTS_TRIE",
            LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS",
            LC_DATA_IN_CODE => "LC_DATA_IN_CODE",
            LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE",
            LC_BUILD_VERSION => "LC_BUILD_VERSION",
            LC_SOURCE_VERSION => "LC_SOURCE_VERSION",
            LC_UUID => "LC_UUID",
            LC_UNIXTHREAD => "LC_UNIXTHREAD",
            _ => "LC_UNKNOWN",
        }
    }
}

/// Iterate all load commands in the Mach-O header, returning their headers.
pub fn parse_load_commands(buf: &[u8], ncmds: u32, sizeofcmds: u32) -> Result<Vec<LoadCmdHeader>> {
    let mut cmds = Vec::with_capacity(ncmds as usize);
    let mut off = MACH_HEADER_64_SIZE;
    let lc_end = MACH_HEADER_64_SIZE + sizeofcmds as usize;

    for i in 0..ncmds {
        if off >= lc_end {
            bail!(
                "load command #{}: offset 0x{:X} past LC region end 0x{:X}",
                i,
                off,
                lc_end
            );
        }
        let hdr = LoadCmdHeader::parse(buf, off)
            .with_context(|| format!("load command #{}", i))?;
        cmds.push(hdr);
        off += hdr.cmdsize as usize;
    }

    Ok(cmds)
}
