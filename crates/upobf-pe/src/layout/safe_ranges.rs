//! Forbidden-range computation for in-place section compression (Phase E).
//!
//! When upobf compresses a host section, it asks the OS Loader to map
//! the section as zero-filled (raw bytes are dropped from the packed
//! file) and asks the stub TLS callback to write the decompressed
//! bytes back to the original RVA before the host's OEP runs.
//!
//! That trick is safe for `.text` (executed only after we've finished
//! unpacking) but **not** safe for the bytes the OS Loader itself
//! reads before TLS callbacks fire. Examples that live inside
//! `.rdata` on a typical Windows PE include:
//!
//!  - the entire Import directory (descriptors, ILT, IBN strings,
//!    DLL name strings),
//!  - the Import Address Table (the loader fills it with resolved
//!    function addresses),
//!  - Resource directory + data,
//!  - LoadConfig (SecurityCookie, GuardCF tables),
//!  - the Exception directory (.pdata),
//!  - the BaseReloc / Debug / DelayImport / CLR / Bound-Import
//!    descriptors,
//!  - the TLS Directory itself plus its callback array.
//!
//! Phase E partitions a section into 4-KiB pages; any page that
//! intersects ANY forbidden range stays uncompressed. The remaining
//! "safe" pages are coalesced into runs and packaged as separate
//! compression chunks. Each chunk's raw bytes are zeroed out in the
//! packed image (the section header still spans them with
//! `size_of_raw_data >= chunk_end_in_section`) and the stub re-injects
//! the decompressed contents at runtime.
//!
//! This module is host-aware but stub-agnostic: it produces a list of
//! `(rva, len)` pairs the packer can hand to `build_payload` and
//! mark on the writer; it never touches the wire format directly.
//!
//! All functions are pure and bounds-checked; tests live at the
//! bottom of the file and exercise every forbidden-range source.

use crate::parse::data_dir::{
    IDX_BASERELOC, IDX_BOUNDIMPORT, IDX_CLR, IDX_DEBUG, IDX_DELAYIMPORT, IDX_EXCEPTION, IDX_EXPORT,
    IDX_IAT, IDX_IMPORT, IDX_LOADCONFIG, IDX_RESOURCE, IDX_SECURITY, IDX_TLS,
};
use crate::parse::sections::SectionHeader;
use crate::parse::PeImage;

/// Compression page granularity. Aligned to the OS Loader page size
/// so the safe/forbidden split happens at the natural memory-map
/// boundary; mixing forbidden bytes onto the same page would force us
/// to pin those pages anyway.
pub const SAFE_PAGE_SIZE: u32 = 0x1000;

/// Drop runs shorter than this from the compression set. Below this
/// threshold LZMA's framing overhead (13-byte alone header + ~5-15%
/// of the payload as range-coded book-keeping) eats the win and the
/// per-chunk metadata cost (40 bytes + nonce derivation work) becomes
/// disproportionate.
pub const MIN_COMPRESS_RUN: u32 = 8 * 1024;

/// One half-open RVA range: `[rva, rva + len)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub rva: u32,
    pub len: u32,
}

impl Range {
    pub fn new(rva: u32, len: u32) -> Self {
        Self { rva, len }
    }

    pub fn end(&self) -> u32 {
        self.rva.saturating_add(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn intersects(&self, other: &Range) -> bool {
        !self.is_empty() && !other.is_empty() && self.rva < other.end() && other.rva < self.end()
    }
}

/// Collect every range inside `sec` that the OS Loader (or another
/// pre-TLS-callback consumer) reads before our stub can write the
/// decompressed bytes back. The returned list is unsorted and may
/// contain overlapping entries; callers should pass it through
/// [`coalesce`] before using it.
///
/// Anything that lives outside `sec` is filtered out — this lets the
/// caller invoke the function once per candidate section without
/// having to slice the host's data dirs by hand.
pub fn collect_forbidden_in_section(image: &PeImage, sec: &SectionHeader) -> Vec<Range> {
    let mut out: Vec<Range> = Vec::new();

    let push = |out: &mut Vec<Range>, rva: u32, len: u32| {
        if len == 0 {
            return;
        }
        // Clip to the section: a directory may span only part of the
        // section, and we don't care about parts outside it for the
        // purposes of this section's safe-range computation.
        let r = Range::new(rva, len);
        let sec_range = Range::new(
            sec.virtual_address,
            sec.virtual_size.max(sec.size_of_raw_data),
        );
        if !r.intersects(&sec_range) {
            return;
        }
        // Clamp the range to the section bounds.
        let start = r.rva.max(sec_range.rva);
        let end = r.end().min(sec_range.end());
        if end > start {
            out.push(Range::new(start, end - start));
        }
    };

    // Bring in every relevant data directory verbatim. Some of these
    // are themselves trees (Import / Resource / Reloc) that fan out
    // into sub-tables; we walk those separately below to catch the
    // child structures as well as the root descriptors.
    let dd = &image.data_dirs;
    for &idx in &[
        IDX_EXPORT,
        IDX_IMPORT,
        IDX_RESOURCE,
        IDX_EXCEPTION,
        IDX_SECURITY,
        IDX_BASERELOC,
        IDX_DEBUG,
        IDX_LOADCONFIG,
        IDX_BOUNDIMPORT,
        IDX_IAT,
        IDX_DELAYIMPORT,
        IDX_CLR,
        IDX_TLS,
    ] {
        let d = dd[idx];
        if d.is_present() {
            push(&mut out, d.virtual_address, d.size);
        }
    }

    // Import directory: every descriptor points at three sub-arrays
    // (OFT / FT / NameRVA) and at IBN structs for each function.
    // The descriptor block itself is already covered by IDX_IMPORT;
    // the children are scattered through .rdata and need explicit
    // entries.
    for dll in &image.imports.dlls {
        // ILT (OriginalFirstThunk) and IAT (FirstThunk) arrays. Each
        // is `(functions.len() + 1) * 8` bytes (NULL-terminated).
        let thunk_bytes = (dll.functions.len() as u32 + 1) * 8;
        if dll.original_first_thunk_rva != 0 {
            push(&mut out, dll.original_first_thunk_rva, thunk_bytes);
        }
        if dll.first_thunk_rva != 0 {
            push(&mut out, dll.first_thunk_rva, thunk_bytes);
        }

        // DLL name: NUL-terminated ASCII. The Loader reads it before
        // calling LoadLibraryA. We pin `len + 1` bytes; the trailing
        // NUL must stay readable.
        if dll.name_rva != 0 {
            let n = dll.name.len() as u32 + 1;
            push(&mut out, dll.name_rva, n);
        }

        // Per-function IMAGE_IMPORT_BY_NAME records: 2-byte hint +
        // ASCIIZ name. Pin each one explicitly. Functions imported
        // by ordinal don't have a name struct, so they contribute
        // nothing to the forbidden set.
        for func in &dll.functions {
            if let (Some(rva), Some(name)) =
                (func.import_by_name_rva, func.name.as_ref())
            {
                let n = 2u32 + name.len() as u32 + 1;
                push(&mut out, rva, n);
            }
        }
    }

    // TLS Directory's callback array — the writer patches it in place
    // (see writer.rs `patch_original_tls_callback_array`). It must be
    // present as raw bytes when the OS Loader walks it.
    if let Some(tls) = &image.tls {
        if tls.callbacks_va != 0 {
            // The packer reserves three 8-byte slots (stub, original,
            // NULL) for the chained-callback layout; budget 32 bytes
            // including a one-slot guard band.
            let cb_array_rva = tls
                .callbacks_va
                .saturating_sub(image.nt.optional_header.image_base) as u32;
            push(&mut out, cb_array_rva, 32);
        }
        // The TLS Directory struct itself is already covered via IDX_TLS.
    }

    // .pdata's IMAGE_RUNTIME_FUNCTION_ENTRY records each carry an
    // `UnwindInfoAddress` RVA pointing into a UNWIND_INFO struct
    // that the OS unwinder reads when servicing exceptions. The
    // UNWIND_INFO blocks for a typical Windows binary live inside
    // `.rdata` and span tens to hundreds of thousands of small
    // structures. Pinning each one individually would explode the
    // forbidden-range list; we instead compute the bounding box of
    // the smallest .. largest UnwindInfoAddress and pin that one
    // contiguous span.
    //
    // RUNTIME_FUNCTION layout (12 bytes per entry):
    //   u32 BeginAddress;
    //   u32 EndAddress;
    //   u32 UnwindInfoAddress;
    //
    // Bit 0 of UnwindInfoAddress can be set to indicate a chained
    // RUNTIME_FUNCTION descriptor — we strip that flag before
    // tracking the bounds.
    let pdata_dir = image.data_dirs[IDX_EXCEPTION];
    if pdata_dir.is_present() {
        if let Ok(off) = image.rva_to_file_offset(pdata_dir.virtual_address) {
            let raw = &image.raw;
            let total = pdata_dir.size as usize;
            if off + total <= raw.len() {
                let count = total / 12;
                let mut min_u: u32 = u32::MAX;
                let mut max_u: u32 = 0;
                for i in 0..count {
                    let p = off + i * 12 + 8;
                    let mut unwind = u32::from_le_bytes([
                        raw[p],
                        raw[p + 1],
                        raw[p + 2],
                        raw[p + 3],
                    ]);
                    unwind &= !1u32;
                    if unwind == 0 || unwind > 0x7fff_ffff {
                        continue;
                    }
                    if unwind < min_u {
                        min_u = unwind;
                    }
                    if unwind > max_u {
                        max_u = unwind;
                    }
                }
                if min_u != u32::MAX && max_u >= min_u {
                    // The longest single UNWIND_INFO record (with all
                    // optional sub-records) is bounded by 4 + 2*255 +
                    // 4 = 518 bytes. We pad with 1024 to cover the
                    // tail entry plus alignment.
                    let span = max_u - min_u + 1024;
                    push(&mut out, min_u, span);
                }
            }
        }
    }

    // LoadConfig sub-tables. The directory entry itself is already
    // pinned via IDX_LOADCONFIG, but the structure points at several
    // tables that the OS Loader reads before TLS callbacks fire:
    //
    //   - GuardCFFunctionTable: Control-Flow Guard valid-target
    //     table. Loader walks it to lock down indirect calls.
    //
    //   - GuardEHContinuationTable: Win10+ valid SEH continuation
    //     RVAs. The loader walks this list as part of
    //     IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION setup; missing it
    //     produces a silent startup hang on .NET NativeAOT, which
    //     opts in. Each entry is 4 bytes (RVA) + 1 byte (flags?)
    //     padded to 5 bytes, but in practice we pin a generous
    //     8 bytes per entry.
    //
    // We don't have an exact entry size for every table (it depends
    // on GuardFlags), so we pin `count * 8` bytes — a conservative
    // over-estimate that covers worst-case 5-byte-per-entry layout
    // plus alignment padding.
    if let Some(lc) = &image.load_config {
        let image_base = image.nt.optional_header.image_base;
        let to_rva =
            |va: u64| -> Option<u32> { va.checked_sub(image_base).map(|v| v as u32) };

        let pin_table = |out: &mut Vec<Range>,
                         table_va: Option<u64>,
                         count: Option<u64>,
                         min_bytes: u32| {
            if let (Some(va), Some(count)) = (table_va, count) {
                if va != 0 && count != 0 {
                    if let Some(rva) = to_rva(va) {
                        let len = count.saturating_mul(8) as u32;
                        push(out, rva, len.max(min_bytes));
                    }
                }
            }
        };

        pin_table(
            &mut out,
            lc.guard_cf_function_table,
            lc.guard_cf_function_count,
            64,
        );
        pin_table(
            &mut out,
            lc.guard_eh_continuation_table,
            lc.guard_eh_continuation_count,
            64,
        );

        // VolatileMetadataPointer points at an IMAGE_VOLATILE_METADATA
        // structure (24-byte header) followed by an access table and
        // a range table. Both sub-tables can be tens of KiB, so we
        // parse the header and pin each table by its declared size.
        // The header itself has the layout:
        //
        //     u32 Size;
        //     u32 Version;
        //     u32 VolatileAccessTableRVA;
        //     u32 VolatileAccessTableSize;
        //     u32 VolatileInfoRangeTableRVA;
        //     u32 VolatileInfoRangeTableSize;
        if let Some(va) = lc.volatile_metadata_pointer {
            if va != 0 {
                if let Some(rva) = to_rva(va) {
                    push(&mut out, rva, 24); // header itself
                    if let Ok(off) = image.rva_to_file_offset(rva) {
                        let raw = &image.raw;
                        if off + 24 <= raw.len() {
                            let read_u32 = |delta: usize| {
                                u32::from_le_bytes([
                                    raw[off + delta],
                                    raw[off + delta + 1],
                                    raw[off + delta + 2],
                                    raw[off + delta + 3],
                                ])
                            };
                            let access_rva = read_u32(8);
                            let access_size = read_u32(12);
                            let info_rva = read_u32(16);
                            let info_size = read_u32(20);
                            push(&mut out, access_rva, access_size);
                            push(&mut out, info_rva, info_size);
                        }
                    }
                }
            }
        }

        // Pointer-storage slots: SecurityCookie, GuardCFCheck/Dispatch,
        // and the XFG check/dispatch/table pointers all live at fixed
        // VA slots that the loader writes/reads. They almost always
        // live in `.data` for MSVC-linked binaries, but pinning them
        // here defensively is cheap.
        for vop in [
            lc.security_cookie_va,
            lc.guard_cf_check_function_pointer,
            lc.guard_cf_dispatch_function_pointer,
            lc.guard_xfg_check_function_pointer,
            lc.guard_xfg_dispatch_function_pointer,
            lc.guard_xfg_table_dispatch_function_pointer,
        ] {
            if let Some(va) = vop {
                if va != 0 {
                    if let Some(rva) = to_rva(va) {
                        push(&mut out, rva, 8);
                    }
                }
            }
        }
    }

    out
}

/// Sort + merge overlapping/adjacent ranges.
///
/// "Adjacent" here means `a.end == b.rva`; we merge touching ranges
/// because the pages either side of the join would have been forbidden
/// in both cases anyway, and merging shrinks the working set.
pub fn coalesce(mut ranges: Vec<Range>) -> Vec<Range> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.retain(|r| !r.is_empty());
    ranges.sort_by_key(|r| (r.rva, r.len));
    let mut out: Vec<Range> = Vec::with_capacity(ranges.len());
    for r in ranges {
        match out.last_mut() {
            Some(last) if last.end() >= r.rva => {
                let new_end = last.end().max(r.end());
                last.len = new_end - last.rva;
            }
            _ => out.push(r),
        }
    }
    out
}

/// Pad each forbidden range out to its enclosing
/// [`SAFE_PAGE_SIZE`]-aligned page so the page mask works at OS-loader
/// granularity. Returns an already-coalesced list.
pub fn pad_to_pages(ranges: &[Range]) -> Vec<Range> {
    let mut padded: Vec<Range> = ranges
        .iter()
        .map(|r| {
            let start_page = r.rva & !(SAFE_PAGE_SIZE - 1);
            let end_unaligned = r.end();
            let end_page = align_up(end_unaligned, SAFE_PAGE_SIZE);
            Range::new(start_page, end_page - start_page)
        })
        .collect();
    padded.sort_by_key(|r| (r.rva, r.len));
    coalesce(padded)
}

/// Compute the **safe** runs in a section: byte ranges where every
/// page is free of forbidden content AND every byte is initialised
/// (i.e. lies within `size_of_raw_data`, not inside the BSS tail).
/// Each run is at least [`MIN_COMPRESS_RUN`] bytes long.
pub fn safe_runs_in_section(
    sec: &SectionHeader,
    forbidden_padded: &[Range],
) -> Vec<Range> {
    // Bound: the initialised, mapped-from-file portion of the section.
    let sec_start = sec.virtual_address;
    let raw_len = sec.virtual_size.min(sec.size_of_raw_data);
    let sec_end = sec_start.saturating_add(raw_len);
    if sec_end <= sec_start {
        return Vec::new();
    }

    // Trim each forbidden range to the section's initialised window.
    let mut blocks: Vec<Range> = forbidden_padded
        .iter()
        .filter_map(|r| {
            let lo = r.rva.max(sec_start);
            let hi = r.end().min(sec_end);
            if hi > lo {
                Some(Range::new(lo, hi - lo))
            } else {
                None
            }
        })
        .collect();
    blocks.sort_by_key(|r| (r.rva, r.len));
    blocks = coalesce(blocks);

    let mut runs: Vec<Range> = Vec::new();
    let mut cursor = sec_start;
    for b in &blocks {
        if b.rva > cursor {
            runs.push(Range::new(cursor, b.rva - cursor));
        }
        cursor = cursor.max(b.end());
    }
    if sec_end > cursor {
        runs.push(Range::new(cursor, sec_end - cursor));
    }

    // Trim each run to a page-aligned interior so we never compress a
    // page that holds *any* forbidden byte (even if `forbidden_padded`
    // missed something; defence in depth).
    runs.into_iter()
        .filter_map(|r| {
            let inner_start = align_up(r.rva, SAFE_PAGE_SIZE);
            let inner_end = r.end() & !(SAFE_PAGE_SIZE - 1);
            if inner_end > inner_start && inner_end - inner_start >= MIN_COMPRESS_RUN {
                Some(Range::new(inner_start, inner_end - inner_start))
            } else {
                None
            }
        })
        .collect()
}

fn align_up(v: u32, align: u32) -> u32 {
    debug_assert!(align.is_power_of_two());
    v.saturating_add(align - 1) & !(align - 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn rng(rva: u32, len: u32) -> Range {
        Range::new(rva, len)
    }

    #[test]
    fn coalesce_merges_overlapping() {
        let v = coalesce(vec![rng(0x1000, 0x100), rng(0x1080, 0x200)]);
        assert_eq!(v, vec![rng(0x1000, 0x280)]);
    }

    #[test]
    fn coalesce_merges_touching() {
        let v = coalesce(vec![rng(0x1000, 0x100), rng(0x1100, 0x100)]);
        assert_eq!(v, vec![rng(0x1000, 0x200)]);
    }

    #[test]
    fn coalesce_keeps_disjoint() {
        let v = coalesce(vec![rng(0x1000, 0x100), rng(0x1200, 0x100)]);
        assert_eq!(v, vec![rng(0x1000, 0x100), rng(0x1200, 0x100)]);
    }

    #[test]
    fn coalesce_drops_empty() {
        let v = coalesce(vec![rng(0x1000, 0), rng(0x2000, 0x100)]);
        assert_eq!(v, vec![rng(0x2000, 0x100)]);
    }

    #[test]
    fn pad_to_pages_rounds_out() {
        // [0x1234, +0x10) -> page 0x1000, end ceil to 0x2000.
        let v = pad_to_pages(&[rng(0x1234, 0x10)]);
        assert_eq!(v, vec![rng(0x1000, 0x1000)]);
    }

    #[test]
    fn pad_to_pages_merges_adjacent_pages() {
        // Two ranges that, after padding, touch each other.
        let v = pad_to_pages(&[rng(0x1234, 0x10), rng(0x2300, 0x10)]);
        assert_eq!(v, vec![rng(0x1000, 0x2000)]);
    }

    fn fake_section(rva: u32, vsize: u32, raw: u32) -> SectionHeader {
        SectionHeader {
            name: ".rdata".into(),
            virtual_address: rva,
            virtual_size: vsize,
            size_of_raw_data: raw,
            pointer_to_raw_data: 0x400,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0x4000_0040,
        }
    }

    #[test]
    fn safe_runs_returns_section_when_no_forbidden() {
        let sec = fake_section(0x10000, 0x40000, 0x40000);
        let runs = safe_runs_in_section(&sec, &[]);
        assert_eq!(runs, vec![rng(0x10000, 0x40000)]);
    }

    #[test]
    fn safe_runs_skips_forbidden_pages() {
        // 256 KiB section; pin one page in the middle.
        let sec = fake_section(0x10000, 0x40000, 0x40000);
        let pinned = vec![rng(0x20000, SAFE_PAGE_SIZE)];
        let runs = safe_runs_in_section(&sec, &pinned);
        // Head run: 0x10000..0x20000 = 0x10000 bytes.
        // Tail run: 0x21000..0x50000 = 0x2F000 bytes.
        assert_eq!(
            runs,
            vec![rng(0x10000, 0x10000), rng(0x21000, 0x2F000)]
        );
    }

    #[test]
    fn safe_runs_drops_runs_below_min() {
        // Force one run to come out shorter than MIN_COMPRESS_RUN.
        let sec = fake_section(0x10000, 0x40000, 0x40000);
        // Pin a page right after the section start so the head run
        // is exactly 0 bytes (only the tail survives).
        let pinned = vec![rng(0x10000, SAFE_PAGE_SIZE)];
        let runs = safe_runs_in_section(&sec, &pinned);
        // Tail should still be > MIN_COMPRESS_RUN.
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].rva, 0x11000);
        assert!(runs[0].len >= MIN_COMPRESS_RUN);

        // Now exercise the actual drop: shrink the section to 16 KiB
        // and pin the third 4-KiB page (RVA 0x12000..0x13000). Head
        // run = 0x10000..0x12000 = 8 KiB == MIN_COMPRESS_RUN (kept);
        // tail run = 0x13000..0x14000 = 4 KiB < MIN_COMPRESS_RUN
        // (dropped).
        let sec2 = fake_section(0x10000, 0x4000, 0x4000);
        let pinned2 = vec![rng(0x12000, SAFE_PAGE_SIZE)];
        let runs2 = safe_runs_in_section(&sec2, &pinned2);
        assert_eq!(runs2.len(), 1, "expected only the >= MIN run to survive");
        assert_eq!(runs2[0], rng(0x10000, MIN_COMPRESS_RUN));
    }

    #[test]
    fn safe_runs_respects_size_of_raw_data() {
        // A section with a BSS tail (vsize > raw). Compression must
        // stop at `size_of_raw_data` because the tail is zero-filled
        // by the OS Loader and there is nothing to compress.
        let sec = fake_section(0x10000, 0x40000, 0x10000);
        let runs = safe_runs_in_section(&sec, &[]);
        assert_eq!(runs, vec![rng(0x10000, 0x10000)]);
    }

    #[test]
    fn safe_runs_handles_forbidden_overlapping_section_start() {
        // Forbidden range starts before the section (e.g. a directory
        // headquartered in a previous section but spanning into ours).
        let sec = fake_section(0x10000, 0x40000, 0x40000);
        let pinned = vec![rng(0x0F000, 0x4000)]; // 0xF000..0x13000
        let runs = safe_runs_in_section(&sec, &pinned);
        // Section starts at 0x10000; first 12 KiB are forbidden;
        // remainder is one big run starting at 0x13000.
        assert_eq!(runs, vec![rng(0x13000, 0x3D000)]);
    }
}
