//! Forbidden-range computation for Mach-O in-place section compression.
//!
//! On macOS arm64, the following constraints apply:
//!
//! 1. **AMFI page hashes**: `__TEXT` segment pages are verified by code
//!    signature page hashes. Writing to `__TEXT` at runtime → SIGKILL.
//!    Therefore `__TEXT` is entirely forbidden for runtime decompression.
//!
//! 2. **Chained fixups**: dyld walks pointer chains in `__DATA*` segments
//!    at load time (before any user code runs). Pages containing fixup
//!    entries cannot be zeroed or compressed — doing so destroys the chain
//!    and causes SIGBUS/crash at dyld startup.
//!
//! 3. **ObjC metadata**: `__objc_*` sections contain pointers that the
//!    ObjC runtime reads very early (before `+load` or `__mod_init_func`).
//!
//! 4. **GOT / lazy binding**: `__got`, `__la_symbol_ptr`, `__auth_got`
//!    are written by dyld during binding.
//!
//! 5. **Initializers**: `__mod_init_func` / `__mod_term_func` contain
//!    function pointer arrays read by dyld.
//!
//! This module computes which pages are safe to compress by:
//! - Walking chained fixup chains to find pages with fixup entries
//! - Pinning known forbidden sections (GOT, objc, initializers)
//! - Coalescing and page-aligning forbidden ranges
//! - Carving out safe runs (>= MIN_COMPRESS_RUN) from candidate sections

use anyhow::Result;

use crate::parse::chained_fixups::{self, ChainedFixupsCmd};
use crate::parse::segments::{Section64, SegmentCommand64};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// macOS arm64 page size (16 KB).
pub const PAGE_SIZE: u64 = 0x4000;

/// Minimum compressible run length. Below this threshold, LZMA framing
/// overhead + per-chunk metadata (40 bytes + nonce) eats the compression win.
pub const MIN_COMPRESS_RUN: u64 = 16 * 1024; // 16 KB (one full page minimum)

// ---------------------------------------------------------------------------
// Range type (mirrors ELF crate's Range)
// ---------------------------------------------------------------------------

/// One half-open virtual-address range: `[vaddr, vaddr + len)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub vaddr: u64,
    pub len: u64,
}

impl Range {
    pub fn new(vaddr: u64, len: u64) -> Self {
        Self { vaddr, len }
    }

    pub fn end(&self) -> u64 {
        self.vaddr.saturating_add(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ---------------------------------------------------------------------------
// Forbidden section names
// ---------------------------------------------------------------------------

/// Section names in `__DATA*` segments that are read/written by dyld or the
/// ObjC runtime before any user initializer runs. These are always forbidden.
const FORBIDDEN_SECTION_NAMES: &[&str] = &[
    // GOT and binding
    "__got",
    "__auth_got",
    "__la_symbol_ptr",
    "__nl_symbol_ptr",
    "__stub_helper",
    // ObjC runtime metadata (read by libobjc before +load)
    "__objc_classlist",
    "__objc_catlist",
    "__objc_protolist",
    "__objc_classrefs",
    "__objc_superrefs",
    "__objc_selrefs",
    "__objc_protorefs",
    "__objc_ivar",
    "__objc_imageinfo",
    "__objc_nlclslist",
    "__objc_nlcatlist",
    // Initializers / terminators
    "__mod_init_func",
    "__mod_term_func",
    // Thread-local storage
    "__thread_vars",
    "__thread_data",
    "__thread_bss",
    "__thread_ptrs",
    // Swift metadata
    "__swift5_proto",
    "__swift5_protos",
    "__swift5_types",
    "__swift5_fieldmd",
    "__swift5_assocty",
    "__swift5_builtin",
    "__swift5_capture",
    "__swift5_typeref",
    "__swift5_reflstr",
    "__swift5_replace",
    "__swift5_replac2",
];

// ---------------------------------------------------------------------------
// Core API
// ---------------------------------------------------------------------------

/// Collect all forbidden ranges from a Mach-O binary.
///
/// Sources:
/// 1. Chained fixup pages (from chain walk)
/// 2. Known forbidden section names
/// 3. Entire `__TEXT` segment (AMFI)
/// 4. Entire `__LINKEDIT` segment
pub fn collect_forbidden(
    buf: &[u8],
    segments: &[SegmentCommand64],
    chained_fixups_cmd: Option<&ChainedFixupsCmd>,
) -> Result<Vec<Range>> {
    let mut forbidden: Vec<Range> = Vec::new();

    // 1. Entire __TEXT segment is forbidden (AMFI page hashes).
    for seg in segments {
        if seg.is_text() || seg.is_linkedit() {
            if seg.vmsize > 0 {
                forbidden.push(Range::new(seg.vmaddr, seg.vmsize));
            }
        }
    }

    // 2. Known forbidden sections in __DATA* segments.
    for seg in segments {
        if !seg.segname.starts_with("__DATA") {
            continue;
        }
        for sect in &seg.sections {
            if FORBIDDEN_SECTION_NAMES.iter().any(|&n| sect.sectname == n) {
                if sect.size > 0 {
                    forbidden.push(Range::new(sect.addr, sect.size));
                }
            }
        }
    }

    // 3. Chained fixup pages (the critical part).
    if let Some(cmd) = chained_fixups_cmd {
        let fixup_ranges = chained_fixups::fixup_forbidden_ranges(buf, cmd, segments)?;
        for (vaddr, size) in fixup_ranges {
            forbidden.push(Range::new(vaddr, size));
        }
    }

    Ok(forbidden)
}

/// Sort + merge overlapping/adjacent ranges.
pub fn coalesce(mut ranges: Vec<Range>) -> Vec<Range> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.retain(|r| !r.is_empty());
    ranges.sort_by_key(|r| (r.vaddr, r.len));
    let mut out: Vec<Range> = Vec::with_capacity(ranges.len());
    for r in ranges {
        match out.last_mut() {
            Some(last) if last.end() >= r.vaddr => {
                let new_end = last.end().max(r.end());
                last.len = new_end - last.vaddr;
            }
            _ => out.push(r),
        }
    }
    out
}

/// Pad each forbidden range out to its enclosing page boundaries (16 KB).
/// Returns an already-coalesced list.
pub fn pad_to_pages(ranges: &[Range]) -> Vec<Range> {
    let mut padded: Vec<Range> = ranges
        .iter()
        .map(|r| {
            let start_page = r.vaddr & !(PAGE_SIZE - 1);
            let end_page = align_up(r.end(), PAGE_SIZE);
            Range::new(start_page, end_page - start_page)
        })
        .collect();
    padded.sort_by_key(|r| (r.vaddr, r.len));
    coalesce(padded)
}

/// Compute the safe (compressible) runs within a section.
///
/// Each returned range is:
/// - Page-aligned (start and end on 16 KB boundaries)
/// - At least `MIN_COMPRESS_RUN` bytes long
/// - Free of any forbidden content
/// - Within the section's virtual address range
pub fn safe_runs_in_section(
    sect: &Section64,
    forbidden_padded: &[Range],
) -> Vec<Range> {
    // Skip zerofill sections (no file backing to compress).
    if sect.is_zerofill() || sect.size == 0 {
        return Vec::new();
    }

    let sec_start = sect.addr;
    let sec_end = sec_start.saturating_add(sect.size);

    // Trim each forbidden range to the section's window.
    let mut blocks: Vec<Range> = forbidden_padded
        .iter()
        .filter_map(|r| {
            let lo = r.vaddr.max(sec_start);
            let hi = r.end().min(sec_end);
            if hi > lo {
                Some(Range::new(lo, hi - lo))
            } else {
                None
            }
        })
        .collect();
    blocks.sort_by_key(|r| (r.vaddr, r.len));
    blocks = coalesce(blocks);

    // Carve out safe runs between forbidden blocks.
    let mut runs: Vec<Range> = Vec::new();
    let mut cursor = sec_start;
    for b in &blocks {
        if b.vaddr > cursor {
            runs.push(Range::new(cursor, b.vaddr - cursor));
        }
        cursor = cursor.max(b.end());
    }
    if sec_end > cursor {
        runs.push(Range::new(cursor, sec_end - cursor));
    }

    // Page-align each run inward and filter by minimum size.
    runs.into_iter()
        .filter_map(|r| {
            let inner_start = align_up(r.vaddr, PAGE_SIZE);
            let inner_end = r.end() & !(PAGE_SIZE - 1);
            if inner_end > inner_start && inner_end - inner_start >= MIN_COMPRESS_RUN {
                Some(Range::new(inner_start, inner_end - inner_start))
            } else {
                None
            }
        })
        .collect()
}

/// Compute all safe compressible runs across all `__DATA*` segments.
///
/// Returns a list of (section_full_name, Vec<Range>) pairs where each Range
/// is a page-aligned, fixup-free region that can be safely compressed.
pub fn compute_safe_ranges(
    buf: &[u8],
    segments: &[SegmentCommand64],
    chained_fixups_cmd: Option<&ChainedFixupsCmd>,
) -> Result<Vec<(String, Vec<Range>)>> {
    // 1. Collect all forbidden ranges.
    let forbidden = collect_forbidden(buf, segments, chained_fixups_cmd)?;

    // 2. Coalesce and pad to pages.
    let coalesced = coalesce(forbidden);
    let padded = pad_to_pages(&coalesced);

    // 3. For each section in __DATA* segments, compute safe runs.
    let mut results: Vec<(String, Vec<Range>)> = Vec::new();

    for seg in segments {
        if !seg.segname.starts_with("__DATA") {
            continue;
        }
        for sect in &seg.sections {
            // Skip forbidden sections entirely.
            if FORBIDDEN_SECTION_NAMES.iter().any(|&n| sect.sectname == n) {
                continue;
            }
            // Skip zerofill.
            if sect.is_zerofill() {
                continue;
            }
            // Skip tiny sections.
            if sect.size < MIN_COMPRESS_RUN {
                continue;
            }

            let runs = safe_runs_in_section(sect, &padded);
            if !runs.is_empty() {
                results.push((sect.full_name(), runs));
            }
        }
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn align_up(v: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    v.saturating_add(align - 1) & !(align - 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn r(v: u64, l: u64) -> Range {
        Range::new(v, l)
    }

    #[test]
    fn coalesce_merges_overlapping_and_touching() {
        let v = coalesce(vec![r(0x1000, 0x100), r(0x1080, 0x200), r(0x1280, 0x100)]);
        assert_eq!(v, vec![r(0x1000, 0x380)]);
    }

    #[test]
    fn coalesce_preserves_disjoint() {
        let v = coalesce(vec![r(0x10000, 0x4000), r(0x20000, 0x4000)]);
        assert_eq!(v, vec![r(0x10000, 0x4000), r(0x20000, 0x4000)]);
    }

    #[test]
    fn pad_to_pages_rounds_to_16k_boundary() {
        // A range in the middle of a page should expand to full page.
        let v = pad_to_pages(&[r(0x14234, 0x10)]);
        assert_eq!(v, vec![r(0x14000, 0x4000)]);
    }

    #[test]
    fn pad_to_pages_merges_adjacent_pages() {
        // Two ranges on adjacent 16KB pages should merge.
        // 0x14100 is on page 0x14000..0x18000
        // 0x18100 is on page 0x18000..0x1C000
        let v = pad_to_pages(&[r(0x14100, 0x10), r(0x18100, 0x10)]);
        assert_eq!(v, vec![r(0x14000, 0x8000)]);
    }

    #[test]
    fn safe_runs_skips_zerofill_and_short() {
        use crate::parse::segments::{S_ZEROFILL, Section64};

        let zerofill = Section64 {
            sectname: "__bss".to_string(),
            segname: "__DATA".to_string(),
            addr: 0x100000,
            size: 0x40000,
            offset: 0,
            align: 0,
            reloff: 0,
            nreloc: 0,
            flags: S_ZEROFILL as u32,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        };
        assert!(safe_runs_in_section(&zerofill, &[]).is_empty());

        let small = Section64 {
            sectname: "__small".to_string(),
            segname: "__DATA".to_string(),
            addr: 0x100000,
            size: 0x2000, // 8KB < MIN_COMPRESS_RUN (16KB)
            offset: 0,
            align: 0,
            reloff: 0,
            nreloc: 0,
            flags: 0,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        };
        assert!(safe_runs_in_section(&small, &[]).is_empty());
    }

    #[test]
    fn safe_runs_carves_around_forbidden_pages() {
        use crate::parse::segments::Section64;

        // A large section with one forbidden page in the middle.
        let sect = Section64 {
            sectname: ".dotnet_eh_table".to_string(),
            segname: "__DATA".to_string(),
            addr: 0x100000,       // page-aligned start
            size: 0x100000,       // 1 MB
            offset: 0x100000,
            align: 0,
            reloff: 0,
            nreloc: 0,
            flags: 0,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        };

        // One forbidden page at 0x140000 (256 KB into the section).
        let forbidden = vec![r(0x140000, PAGE_SIZE)];
        let runs = safe_runs_in_section(&sect, &forbidden);

        // Should get two runs:
        // Head: 0x100000..0x140000 (256 KB)
        // Tail: 0x144000..0x200000 (768 KB)
        assert_eq!(runs, vec![
            r(0x100000, 0x40000),   // 256 KB
            r(0x144000, 0xBC000),   // 768 KB
        ]);
    }
}
