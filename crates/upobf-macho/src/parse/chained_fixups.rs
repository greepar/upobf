//! LC_DYLD_CHAINED_FIXUPS parser.
//!
//! Parses the top-level `dyld_chained_fixups_header`, the
//! `dyld_chained_starts_in_image` table, and per-segment
//! `dyld_chained_starts_in_segment` structures including per-page
//! chain walks. The chain walk identifies which pages in each segment
//! contain fixup entries (bind or rebase pointers that dyld processes
//! at load time). This information is used by safe_ranges to determine
//! which pages can be safely compressed.
//!
//! Reference: <mach-o/fixup-chains.h>

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::reader;

// ---------------------------------------------------------------------------
// LC_DYLD_CHAINED_FIXUPS linkedit_data_command (16 bytes)
// ---------------------------------------------------------------------------

pub const LINKEDIT_DATA_CMD_SIZE: usize = 16;

/// The load command itself just points into __LINKEDIT.
#[derive(Debug, Clone, Serialize)]
pub struct ChainedFixupsCmd {
    /// File offset of the chained fixups data in __LINKEDIT.
    pub dataoff: u32,
    /// Size of the chained fixups data.
    pub datasize: u32,
}

impl ChainedFixupsCmd {
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, LINKEDIT_DATA_CMD_SIZE)
            .context("linkedit_data_command bytes")?;
        Ok(Self {
            dataoff: reader::u32(s, 8)?,
            datasize: reader::u32(s, 12)?,
        })
    }
}

// ---------------------------------------------------------------------------
// dyld_chained_fixups_header (32 bytes at dataoff)
// ---------------------------------------------------------------------------

pub const CHAINED_FIXUPS_HEADER_SIZE: usize = 32;

/// Top-level header of the chained fixups blob in __LINKEDIT.
#[derive(Debug, Clone, Serialize)]
pub struct ChainedFixupsHeader {
    pub fixups_version: u32,
    /// Offset of dyld_chained_starts_in_image (relative to this header).
    pub starts_offset: u32,
    /// Offset of imports table (relative to this header).
    pub imports_offset: u32,
    /// Offset of symbol strings (relative to this header).
    pub symbols_offset: u32,
    /// Number of imported symbols.
    pub imports_count: u32,
    /// Format of imports (1=DYLD_CHAINED_IMPORT, 2=DYLD_CHAINED_IMPORT_ADDEND, 3=DYLD_CHAINED_IMPORT_ADDEND64).
    pub imports_format: u32,
    /// Format of symbols (0 = uncompressed, 1 = zlib compressed).
    pub symbols_format: u32,
}

impl ChainedFixupsHeader {
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, CHAINED_FIXUPS_HEADER_SIZE)
            .context("dyld_chained_fixups_header bytes")?;
        Ok(Self {
            fixups_version: reader::u32(s, 0)?,
            starts_offset: reader::u32(s, 4)?,
            imports_offset: reader::u32(s, 8)?,
            symbols_offset: reader::u32(s, 12)?,
            imports_count: reader::u32(s, 16)?,
            imports_format: reader::u32(s, 20)?,
            symbols_format: reader::u32(s, 24)?,
        })
    }
}

// ---------------------------------------------------------------------------
// dyld_chained_starts_in_image
// ---------------------------------------------------------------------------

/// Per-segment starts info (offset from starts_in_image to the
/// dyld_chained_starts_in_segment for each segment).
#[derive(Debug, Clone, Serialize)]
pub struct ChainedStartsInImage {
    pub seg_count: u32,
    /// Offsets from the start of dyld_chained_starts_in_image to each
    /// segment's dyld_chained_starts_in_segment. 0 means no fixups in
    /// that segment.
    pub seg_info_offsets: Vec<u32>,
}

impl ChainedStartsInImage {
    /// Parse from `off` which points to the dyld_chained_starts_in_image.
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let seg_count = reader::u32(buf, off).context("starts_in_image.seg_count")?;
        let mut seg_info_offsets = Vec::with_capacity(seg_count as usize);
        for i in 0..seg_count {
            let entry_off = off + 4 + (i as usize) * 4;
            let v = reader::u32(buf, entry_off)
                .with_context(|| format!("starts_in_image.seg_info_offset[{}]", i))?;
            seg_info_offsets.push(v);
        }
        Ok(Self {
            seg_count,
            seg_info_offsets,
        })
    }
}

// ---------------------------------------------------------------------------
// Aggregated chained fixups info
// ---------------------------------------------------------------------------

/// High-level chained fixups information parsed from __LINKEDIT.
/// Individual chain walks are deferred to later phases.
#[derive(Debug, Clone, Serialize)]
pub struct ChainedFixupsInfo {
    pub cmd: ChainedFixupsCmd,
    pub header: ChainedFixupsHeader,
    pub starts: ChainedStartsInImage,
    /// Number of imported symbols.
    pub imports_count: u32,
}

impl ChainedFixupsInfo {
    /// Parse the chained fixups data given the load command and file buffer.
    pub fn from_cmd(buf: &[u8], cmd: &ChainedFixupsCmd) -> Result<Self> {
        let base = cmd.dataoff as usize;
        let header = ChainedFixupsHeader::parse(buf, base)
            .context("chained fixups header")?;

        let starts_off = base + header.starts_offset as usize;
        let starts = ChainedStartsInImage::parse(buf, starts_off)
            .context("chained starts_in_image")?;

        Ok(Self {
            cmd: cmd.clone(),
            imports_count: header.imports_count,
            header,
            starts,
        })
    }
}

// ---------------------------------------------------------------------------
// Import name resolution (for GOT entry lookup)
// ---------------------------------------------------------------------------

/// Resolve the name of an import by its ordinal index.
/// Returns the symbol name from the chained fixups string pool.
pub fn resolve_import_name(buf: &[u8], cmd: &ChainedFixupsCmd, ordinal: u32) -> Result<String> {
    let base = cmd.dataoff as usize;
    let header = ChainedFixupsHeader::parse(buf, base)?;

    if ordinal >= header.imports_count {
        bail!("import ordinal {} >= imports_count {}", ordinal, header.imports_count);
    }

    // imports_format 1 = DYLD_CHAINED_IMPORT (4 bytes each)
    let imports_base = base + header.imports_offset as usize;
    let imp_off = imports_base + ordinal as usize * 4;
    let imp = reader::u32(buf, imp_off)?;
    let name_offset = (imp >> 9) & 0x7FFFFF;

    let syms_base = base + header.symbols_offset as usize;
    let name_off = syms_base + name_offset as usize;
    reader::cstring_at(buf, name_off)
}

/// Find the GOT entry vmaddr for a given symbol name by scanning the
/// __DATA_CONST,__got section's chained fixup bind entries.
///
/// Returns the vmaddr of the GOT slot that will contain the resolved
/// function pointer at runtime (after dyld processes chained fixups).
pub fn find_got_entry_for_symbol(
    buf: &[u8],
    cmd: &ChainedFixupsCmd,
    got_fileoff: u64,
    got_vmaddr: u64,
    got_size: u64,
    symbol_name: &str,
) -> Result<Option<u64>> {
    let base = cmd.dataoff as usize;
    let header = ChainedFixupsHeader::parse(buf, base)?;

    // Build import name lookup: find the ordinal for our target symbol.
    let imports_base = base + header.imports_offset as usize;
    let syms_base = base + header.symbols_offset as usize;

    let mut target_ordinal: Option<u32> = None;
    for i in 0..header.imports_count {
        let imp_off = imports_base + i as usize * 4;
        let imp = reader::u32(buf, imp_off)?;
        let name_offset = (imp >> 9) & 0x7FFFFF;
        let name_off = syms_base + name_offset as usize;
        let name = reader::cstring_at(buf, name_off).unwrap_or_default();
        if name == symbol_name {
            target_ordinal = Some(i);
            break;
        }
    }

    let target_ordinal = match target_ordinal {
        Some(o) => o,
        None => return Ok(None),
    };

    // Scan GOT entries for a bind with this ordinal.
    // pointer_format 6 = DYLD_CHAINED_PTR_64_OFFSET:
    //   bind: bit63=1, ordinal=bits[0:23], addend=bits[24:31], next=bits[52:62]
    let got_count = got_size / 8;
    for i in 0..got_count {
        let entry_off = got_fileoff as usize + i as usize * 8;
        let raw = reader::u64(buf, entry_off)?;
        let is_bind = (raw >> 63) & 1 == 1;
        if is_bind {
            let ordinal = (raw & 0xFFFFFF) as u32;
            if ordinal == target_ordinal {
                return Ok(Some(got_vmaddr + i * 8));
            }
        }
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// Per-segment chain walk: dyld_chained_starts_in_segment + page chain walk
// ---------------------------------------------------------------------------

/// Known pointer formats from <mach-o/fixup-chains.h>.
pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
pub const DYLD_CHAINED_PTR_64: u16 = 2;
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
pub const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;

/// Sentinel value in page_starts indicating no fixups on this page.
pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
/// Multi-start indicator (page_starts entry has high bit set).
pub const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;

/// Parsed `dyld_chained_starts_in_segment` for one segment.
#[derive(Debug, Clone, Serialize)]
pub struct ChainedStartsInSegment {
    /// Size of this struct (including page_starts array).
    pub size: u32,
    /// Page size for this segment (typically 0x4000 on arm64).
    pub page_size: u16,
    /// Pointer format (e.g. DYLD_CHAINED_PTR_64_OFFSET = 6).
    pub pointer_format: u16,
    /// Offset from the mach_header to the start of this segment's data.
    pub segment_offset: u64,
    /// Max valid offset (used for bounds checking).
    pub max_valid_pointer: u32,
    /// Number of pages in this segment.
    pub page_count: u16,
    /// Per-page start offsets. DYLD_CHAINED_PTR_START_NONE means no fixups.
    pub page_starts: Vec<u16>,
}

impl ChainedStartsInSegment {
    /// Parse from `off` which points to the dyld_chained_starts_in_segment.
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        // struct dyld_chained_starts_in_segment {
        //     uint32_t size;               // +0
        //     uint16_t page_size;          // +4
        //     uint16_t pointer_format;     // +6
        //     uint64_t segment_offset;     // +8
        //     uint32_t max_valid_pointer;  // +16
        //     uint16_t page_count;         // +20
        //     uint16_t page_start[0];      // +22
        // }
        let size = reader::u32(buf, off).context("starts_in_segment.size")?;
        let page_size = reader::u16(buf, off + 4).context("starts_in_segment.page_size")?;
        let pointer_format = reader::u16(buf, off + 6).context("starts_in_segment.pointer_format")?;
        let segment_offset = reader::u64(buf, off + 8).context("starts_in_segment.segment_offset")?;
        let max_valid_pointer = reader::u32(buf, off + 16).context("starts_in_segment.max_valid_pointer")?;
        let page_count = reader::u16(buf, off + 20).context("starts_in_segment.page_count")?;

        let mut page_starts = Vec::with_capacity(page_count as usize);
        for i in 0..page_count as usize {
            let ps_off = off + 22 + i * 2;
            let v = reader::u16(buf, ps_off)
                .with_context(|| format!("page_start[{}]", i))?;
            page_starts.push(v);
        }

        Ok(Self {
            size,
            page_size,
            pointer_format,
            segment_offset,
            max_valid_pointer,
            page_count,
            page_starts,
        })
    }
}

/// Stride (in bytes) between chained fixup entries for a given pointer format.
/// The `next` field in each entry encodes how many stride-units to advance.
fn stride_for_pointer_format(fmt: u16) -> u64 {
    match fmt {
        DYLD_CHAINED_PTR_ARM64E
        | DYLD_CHAINED_PTR_ARM64E_KERNEL
        | DYLD_CHAINED_PTR_ARM64E_USERLAND
        | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => 8,
        DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => 4,
        _ => 4, // conservative default
    }
}

/// Extract the `next` field from a raw 8-byte fixup entry based on pointer format.
/// Returns 0 if this is the last entry in the chain.
fn next_delta(raw: u64, pointer_format: u16) -> u64 {
    match pointer_format {
        // DYLD_CHAINED_PTR_64 / DYLD_CHAINED_PTR_64_OFFSET:
        //   rebase: next = bits[51:62] (11 bits)
        //   bind:   next = bits[52:62] (11 bits) — same position
        DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => {
            // Both bind and rebase have `next` at bits [51..62].
            // For bind (bit63=1): bits[52:62] = 11 bits
            // For rebase (bit63=0): bits[51:62] = 12 bits
            // Actually in the Apple header:
            //   rebase: target[36], high8[8], next[12], bind[1] — bits[36..48]=next? No.
            // Let's use the correct layout:
            //   DYLD_CHAINED_PTR_64_OFFSET rebase: target(36), high8(8), next(12), bind(1=0)
            //     next = bits[36+8..36+8+12] = bits[44..56]? No.
            // Correct layout from dyld source:
            //   struct dyld_chained_ptr_64_rebase {
            //     uint64_t target   : 36,  // bits[0:35]
            //              high8    :  8,  // bits[36:43]
            //              reserved :  7,  // bits[44:50]
            //              next     : 12,  // bits[51:62]
            //              bind     :  1;  // bit 63
            //   };
            //   struct dyld_chained_ptr_64_bind {
            //     uint64_t ordinal  : 24,  // bits[0:23]
            //              addend   :  8,  // bits[24:31]
            //              reserved : 19,  // bits[32:50]
            //              next     : 12,  // bits[51:62]
            //              bind     :  1;  // bit 63
            //   };
            (raw >> 51) & 0xFFF
        }
        // ARM64E formats: next is bits[52:62] (11 bits).
        DYLD_CHAINED_PTR_ARM64E
        | DYLD_CHAINED_PTR_ARM64E_KERNEL
        | DYLD_CHAINED_PTR_ARM64E_USERLAND
        | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => {
            (raw >> 52) & 0x7FF
        }
        _ => {
            // Unknown format — assume bits[51:62] like PTR_64.
            (raw >> 51) & 0xFFF
        }
    }
}

/// Result of walking all fixup chains in a segment: a set of page indices
/// that contain at least one fixup entry.
#[derive(Debug, Clone)]
pub struct SegmentFixupPages {
    /// Segment index (matching the order in LC_SEGMENT_64 load commands).
    pub segment_index: usize,
    /// Segment name.
    pub segname: String,
    /// Page size used by this segment's fixup chains.
    pub page_size: u64,
    /// Segment's vmaddr (from the segment_offset field, which is relative to mach_header).
    pub segment_vmaddr: u64,
    /// Bitmap: page_has_fixups[i] == true means page i has at least one fixup.
    pub page_has_fixups: Vec<bool>,
    /// Total number of fixup entries found across all pages.
    pub total_fixup_count: usize,
}

/// Walk all chained fixup chains in the binary and return per-segment
/// information about which pages contain fixup entries.
///
/// This is the key function for safe_ranges: any page with fixups cannot
/// be compressed because dyld walks the chain at load time.
pub fn walk_all_fixup_chains(
    buf: &[u8],
    cmd: &ChainedFixupsCmd,
    segments: &[crate::parse::segments::SegmentCommand64],
) -> Result<Vec<SegmentFixupPages>> {
    let base = cmd.dataoff as usize;
    let header = ChainedFixupsHeader::parse(buf, base)?;
    let starts_off = base + header.starts_offset as usize;
    let starts = ChainedStartsInImage::parse(buf, starts_off)?;

    let mut results = Vec::new();

    for seg_idx in 0..starts.seg_count as usize {
        let seg_info_offset = starts.seg_info_offsets[seg_idx];
        if seg_info_offset == 0 {
            // No fixups in this segment.
            continue;
        }

        // Parse dyld_chained_starts_in_segment.
        let seg_starts_off = starts_off + seg_info_offset as usize;
        let seg_starts = ChainedStartsInSegment::parse(buf, seg_starts_off)
            .with_context(|| format!("starts_in_segment[{}]", seg_idx))?;

        let page_size = seg_starts.page_size as u64;
        let pointer_format = seg_starts.pointer_format;
        let stride = stride_for_pointer_format(pointer_format);

        // The segment_offset is relative to the mach_header (file offset 0 for
        // the main executable). This gives us the file offset of the segment's data.
        let seg_file_start = seg_starts.segment_offset as usize;

        let mut page_has_fixups = vec![false; seg_starts.page_count as usize];
        let mut total_fixup_count: usize = 0;

        for page_idx in 0..seg_starts.page_count as usize {
            let page_start = seg_starts.page_starts[page_idx];

            if page_start == DYLD_CHAINED_PTR_START_NONE {
                continue;
            }

            if page_start & DYLD_CHAINED_PTR_START_MULTI != 0 {
                // Multi-start page: the page_starts entry is an index into
                // an overflow array. For now, conservatively mark the page.
                page_has_fixups[page_idx] = true;
                total_fixup_count += 1;
                continue;
            }

            // Walk the chain starting at page_start offset within this page.
            let page_file_off = seg_file_start + page_idx * page_size as usize;
            let mut offset_in_page = page_start as u64;

            loop {
                let entry_file_off = page_file_off + offset_in_page as usize;
                if entry_file_off + 8 > buf.len() {
                    break; // Bounds safety
                }

                page_has_fixups[page_idx] = true;
                total_fixup_count += 1;

                let raw = reader::u64(buf, entry_file_off)?;
                let next = next_delta(raw, pointer_format);
                if next == 0 {
                    break; // End of chain
                }
                offset_in_page += next * stride;

                // Safety: don't walk past page boundary.
                if offset_in_page >= page_size {
                    break;
                }
            }
        }

        // Determine segment vmaddr from the segment table.
        let seg_vmaddr = if seg_idx < segments.len() {
            segments[seg_idx].vmaddr
        } else {
            // Fallback: use segment_offset as a proxy (it's the file offset
            // which equals vmaddr for __TEXT-based images, but not generally).
            seg_starts.segment_offset
        };

        let segname = if seg_idx < segments.len() {
            segments[seg_idx].segname.clone()
        } else {
            format!("__SEG{}", seg_idx)
        };

        results.push(SegmentFixupPages {
            segment_index: seg_idx,
            segname,
            page_size,
            segment_vmaddr: seg_vmaddr,
            page_has_fixups,
            total_fixup_count,
        });
    }

    Ok(results)
}

/// Convenience: get the set of vmaddr ranges (page-aligned) that contain
/// fixup entries across all segments. These ranges are FORBIDDEN for compression.
pub fn fixup_forbidden_ranges(
    buf: &[u8],
    cmd: &ChainedFixupsCmd,
    segments: &[crate::parse::segments::SegmentCommand64],
) -> Result<Vec<(u64, u64)>> {
    let seg_pages = walk_all_fixup_chains(buf, cmd, segments)?;
    let mut ranges: Vec<(u64, u64)> = Vec::new();

    for sp in &seg_pages {
        for (page_idx, &has_fixup) in sp.page_has_fixups.iter().enumerate() {
            if has_fixup {
                let page_vaddr = sp.segment_vmaddr + (page_idx as u64) * sp.page_size;
                ranges.push((page_vaddr, sp.page_size));
            }
        }
    }

    Ok(ranges)
}
