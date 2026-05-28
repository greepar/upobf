//! LC_SEGMENT_64 + section_64 parsers.
//!
//! Reference: <mach-o/loader.h> — struct segment_command_64, struct section_64.

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::reader;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of `segment_command_64` (without sections): 72 bytes.
pub const SEGMENT_CMD_64_SIZE: usize = 72;

/// Size of one `section_64` entry: 80 bytes.
pub const SECTION_64_SIZE: usize = 80;

// Segment VM protection flags (vm_prot_t).
pub const VM_PROT_READ: u32 = 0x01;
pub const VM_PROT_WRITE: u32 = 0x02;
pub const VM_PROT_EXECUTE: u32 = 0x04;

// Section types (low 8 bits of section_64.flags).
pub const S_REGULAR: u8 = 0x0;
pub const S_ZEROFILL: u8 = 0x1;
pub const S_CSTRING_LITERALS: u8 = 0x2;
pub const S_4BYTE_LITERALS: u8 = 0x3;
pub const S_8BYTE_LITERALS: u8 = 0x4;
pub const S_LITERAL_POINTERS: u8 = 0x5;
pub const S_NON_LAZY_SYMBOL_POINTERS: u8 = 0x6;
pub const S_LAZY_SYMBOL_POINTERS: u8 = 0x7;
pub const S_SYMBOL_STUBS: u8 = 0x8;
pub const S_MOD_INIT_FUNC_POINTERS: u8 = 0x9;
pub const S_MOD_TERM_FUNC_POINTERS: u8 = 0xA;

// Section attribute flags (high 24 bits of section_64.flags).
pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

// ---------------------------------------------------------------------------
// Section64
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Section64 {
    /// Section name (up to 16 bytes, NUL-padded).
    pub sectname: String,
    /// Segment name this section belongs to.
    pub segname: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

impl Section64 {
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, SECTION_64_SIZE).context("section_64 bytes")?;
        Ok(Self {
            sectname: reader::fixed_str(s, 0, 16)?,
            segname: reader::fixed_str(s, 16, 16)?,
            addr: reader::u64(s, 32)?,
            size: reader::u64(s, 40)?,
            offset: reader::u32(s, 48)?,
            align: reader::u32(s, 52)?,
            reloff: reader::u32(s, 56)?,
            nreloc: reader::u32(s, 60)?,
            flags: reader::u32(s, 64)?,
            reserved1: reader::u32(s, 68)?,
            reserved2: reader::u32(s, 72)?,
            reserved3: reader::u32(s, 76)?,
        })
    }

    /// Section type (low 8 bits of flags).
    pub fn section_type(&self) -> u8 {
        (self.flags & 0xFF) as u8
    }

    /// Whether this section contains executable instructions.
    pub fn is_executable(&self) -> bool {
        self.flags & S_ATTR_PURE_INSTRUCTIONS != 0
            || self.flags & S_ATTR_SOME_INSTRUCTIONS != 0
    }

    /// Whether this is a zerofill section (no file backing).
    pub fn is_zerofill(&self) -> bool {
        self.section_type() == S_ZEROFILL
    }

    /// Full qualified name: "segname,sectname" (e.g. "__TEXT,__text").
    pub fn full_name(&self) -> String {
        format!("{},{}", self.segname, self.sectname)
    }
}

// ---------------------------------------------------------------------------
// SegmentCommand64
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct SegmentCommand64 {
    /// Segment name (up to 16 bytes, NUL-padded).
    pub segname: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
    pub flags: u32,
    /// Sections contained in this segment.
    pub sections: Vec<Section64>,
    /// File offset of the LC_SEGMENT_64 load command itself.
    pub cmd_offset: usize,
}

impl SegmentCommand64 {
    /// Parse a segment_command_64 + its sections from the load command at `off`.
    /// `off` points to the start of the load command (i.e., the `cmd` field).
    pub fn parse(buf: &[u8], off: usize, cmdsize: u32) -> Result<Self> {
        let s = reader::slice(buf, off, SEGMENT_CMD_64_SIZE)
            .context("segment_command_64 bytes")?;

        // Fields start at offset 8 (after cmd + cmdsize).
        let segname = reader::fixed_str(s, 8, 16)?;
        let vmaddr = reader::u64(s, 24)?;
        let vmsize = reader::u64(s, 32)?;
        let fileoff = reader::u64(s, 40)?;
        let filesize = reader::u64(s, 48)?;
        let maxprot = reader::u32(s, 56)?;
        let initprot = reader::u32(s, 60)?;
        let nsects = reader::u32(s, 64)?;
        let flags = reader::u32(s, 68)?;

        // Validate cmdsize vs expected.
        let expected_size = SEGMENT_CMD_64_SIZE + nsects as usize * SECTION_64_SIZE;
        if (cmdsize as usize) < expected_size {
            bail!(
                "LC_SEGMENT_64 '{}': cmdsize {} < expected {} (nsects={})",
                segname,
                cmdsize,
                expected_size,
                nsects
            );
        }

        // Parse sections.
        let mut sections = Vec::with_capacity(nsects as usize);
        let mut sect_off = off + SEGMENT_CMD_64_SIZE;
        for i in 0..nsects {
            let sect = Section64::parse(buf, sect_off)
                .with_context(|| format!("section #{} in segment '{}'", i, segname))?;
            sections.push(sect);
            sect_off += SECTION_64_SIZE;
        }

        Ok(Self {
            segname,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            nsects,
            flags,
            sections,
            cmd_offset: off,
        })
    }

    /// Symbolic protection string (e.g. "R-X", "RW-", "R--").
    pub fn prot_string(&self) -> String {
        let mut s = String::with_capacity(3);
        s.push(if self.initprot & VM_PROT_READ != 0 { 'R' } else { '-' });
        s.push(if self.initprot & VM_PROT_WRITE != 0 { 'W' } else { '-' });
        s.push(if self.initprot & VM_PROT_EXECUTE != 0 { 'X' } else { '-' });
        s
    }

    /// Whether this segment is the __TEXT segment.
    pub fn is_text(&self) -> bool {
        self.segname == "__TEXT"
    }

    /// Whether this segment is the __DATA or __DATA_CONST segment.
    pub fn is_data(&self) -> bool {
        self.segname == "__DATA" || self.segname == "__DATA_CONST"
    }

    /// Whether this segment is the __LINKEDIT segment.
    pub fn is_linkedit(&self) -> bool {
        self.segname == "__LINKEDIT"
    }

    /// Find a section by name within this segment.
    pub fn section(&self, sectname: &str) -> Option<&Section64> {
        self.sections.iter().find(|s| s.sectname == sectname)
    }
}

/// Translate a virtual address to a file offset using the segment table.
/// Returns (file_offset, segment_index).
pub fn vaddr_to_file_offset(segments: &[SegmentCommand64], vaddr: u64) -> Result<(u64, usize)> {
    for (i, seg) in segments.iter().enumerate() {
        if vaddr >= seg.vmaddr && vaddr < seg.vmaddr + seg.vmsize {
            let delta = vaddr - seg.vmaddr;
            if delta < seg.filesize {
                return Ok((seg.fileoff + delta, i));
            }
            // vaddr is in the zero-fill region (filesize < vmsize).
            bail!(
                "vaddr 0x{:X} in segment '{}' zero-fill region (filesize=0x{:X}, delta=0x{:X})",
                vaddr,
                seg.segname,
                seg.filesize,
                delta
            );
        }
    }
    bail!(
        "vaddr 0x{:X} not found in any segment",
        vaddr
    );
}
