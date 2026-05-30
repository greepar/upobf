//! Forbidden-range computation for ELF in-place section compression.
//!
//! When upobf compresses bytes from the host image, it asks the OS
//! Loader (ld.so) to map them as zero-filled while letting the stub
//! `init_array` callback decompress the originals back at runtime.
//!
//! That trick is safe for `.text`/`.rodata` (executed/read only after
//! the C runtime has called our init_array hook) but **unsafe** for
//! anything ld.so reads before init_array fires. On a typical
//! glibc-linked Linux ELF that includes:
//!
//!  - `.interp`            (kernel reads it before exec()-time)
//!  - `.dynsym` / `.dynstr` / `.gnu.hash` / `.gnu.version*`
//!    (ld.so walks them to resolve `DT_NEEDED` libraries and lay out
//!    the linkage table)
//!  - `.rela.dyn` / `.rela.plt`
//!    (relocations applied before init_array)
//!  - `.got` / `.got.plt`
//!    (ld.so writes the resolved function pointers there)
//!  - `.plt`  (called during init_array execution itself; libc's
//!    `__libc_start_main` etc.)
//!  - `.eh_frame_hdr` / `.eh_frame`
//!    (libgcc_s unwinder reads them very early)
//!  - `.init` / `.fini`
//!    (DT_INIT / DT_FINI handlers fire before the array)
//!  - `.init_array` / `.fini_array` / `.preinit_array`
//!    (we extend them in M3L; the bytes themselves are read by the
//!    loader to walk the function pointer list)
//!  - `PT_DYNAMIC` content
//!  - `PT_NOTE` content (kernel reads NT_GNU_BUILD_ID for module
//!    identification when generating core dumps; not strictly needed
//!    for run, but keeping notes intact stays AV-friendly)
//!  - `PT_PHDR` content (the program header table itself)
//!
//! Anything outside the forbidden set on a 4-KiB page boundary is a
//! candidate for compression in Phase E (mirroring the PE side).
//! M1L baseline only consumes this module to decide what to keep
//! verbatim during writer testing; M3L+ feeds it into the payload
//! builder.

use crate::parse::headers::{
    Elf64Phdr, Elf64Shdr, PF_W, PT_DYNAMIC, PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_INTERP, PT_LOAD,
    PT_NOTE, PT_PHDR,
};
use crate::parse::relocations::Rela;
use crate::parse::symbols::DynSymbol;

/// Compression page granularity. ld.so maps segments at 4 KiB on
/// x86_64 so the safe/forbidden split happens at the natural memory
/// boundary; mixing forbidden bytes onto the same page would force us
/// to pin those pages anyway.
pub const SAFE_PAGE_SIZE: u64 = 0x1000;

/// Drop runs shorter than this from the compression set. Below this
/// threshold LZMA's framing overhead and the per-chunk metadata cost
/// (40 bytes + nonce derivation) eat the win.
pub const MIN_COMPRESS_RUN: u64 = 8 * 1024;

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

    pub fn intersects(&self, other: &Range) -> bool {
        !self.is_empty() && !other.is_empty() && self.vaddr < other.end() && other.vaddr < self.end()
    }
}

/// Section names that ld.so / libgcc unwinder consume before the
/// stub's init_array hook can run. Everything matching gets pinned.
const FORBIDDEN_SECTION_NAMES: &[&str] = &[
    ".interp",
    ".dynsym",
    ".dynstr",
    ".gnu.hash",
    ".hash",
    ".gnu.version",
    ".gnu.version_d",
    ".gnu.version_r",
    ".rela.dyn",
    ".rela.plt",
    ".rel.dyn",
    ".rel.plt",
    ".got",
    ".got.plt",
    ".plt",
    ".plt.got",
    ".plt.sec",
    ".eh_frame_hdr",
    ".eh_frame",
    ".init",
    ".fini",
    ".init_array",
    ".fini_array",
    ".preinit_array",
    ".dynamic",
    ".note.ABI-tag",
    ".note.gnu.build-id",
    ".note.gnu.property",
    ".tdata",
    ".tbss",
];

/// Collect every range the OS Loader (or unwinder) reads before the
/// stub's init_array hook runs.
///
/// Output is unsorted and may contain overlapping entries; callers
/// should pipe it through [`coalesce`] before using it.
pub fn collect_forbidden(
    phdrs: &[Elf64Phdr],
    shdrs: &[Elf64Shdr],
) -> Vec<Range> {
    let mut out: Vec<Range> = Vec::new();

    // ---- Section-name driven entries -----------------------------------
    for sh in shdrs {
        if FORBIDDEN_SECTION_NAMES.iter().any(|n| sh.name == *n) {
            if sh.sh_size > 0 {
                out.push(Range::new(sh.sh_addr, sh.sh_size));
            }
        }
    }

    // ---- Program-header driven entries (catch-all in case section -----
    // headers were stripped or named differently). PT_PHDR / PT_DYNAMIC
    // / PT_INTERP / PT_NOTE / PT_GNU_EH_FRAME all contribute.
    for p in phdrs {
        match p.p_type {
            PT_PHDR | PT_DYNAMIC | PT_INTERP | PT_NOTE | PT_GNU_EH_FRAME => {
                if p.p_memsz > 0 {
                    out.push(Range::new(p.p_vaddr, p.p_memsz));
                }
            }
            _ => {}
        }
    }

    out
}

/// Pin every byte ld.so writes via dynamic relocation BEFORE the
/// stub's init_array hook fires. Each rela's `r_offset` is an 8-byte
/// slot the loader overwrites with a resolved address / value. We only
/// pin offsets that land inside RW LOAD segments (the packer's
/// compression targets); text relocations are irrelevant here.
pub fn collect_forbidden_relocs(
    rela_dyn: &[Rela],
    phdrs: &[Elf64Phdr],
) -> Vec<Range> {
    // Build a list of RW LOAD vaddr ranges.
    let rw_loads: Vec<(u64, u64)> = phdrs
        .iter()
        .filter(|p| p.p_type == PT_LOAD && (p.p_flags & PF_W) != 0)
        .map(|p| (p.p_vaddr, p.p_vaddr + p.p_memsz))
        .collect();

    let in_rw_load = |va: u64| -> bool {
        rw_loads.iter().any(|(lo, hi)| va >= *lo && va < *hi)
    };

    rela_dyn
        .iter()
        .filter(|r| in_rw_load(r.r_offset))
        .map(|r| Range::new(r.r_offset, 8))
        .collect()
}

/// Pin glibc's early-access globals that ld.so / the C runtime write
/// before init_array fires. Each matched symbol gets 16 bytes pinned
/// (8 for the slot + 8 guard for compiler-introduced sibling padding).
/// Only defined (non-undefined) symbols are considered.
pub fn collect_forbidden_critical_globals(
    dynsym: &[DynSymbol],
) -> Vec<Range> {
    const CRITICAL_NAMES: &[&str] = &[
        "__stack_chk_guard",
        "__libc_start_main",
        "__libc_argc",
        "__libc_argv",
        "_environ",
        "__environ",
        "environ",
        "__progname",
        "__progname_full",
        "_dl_argv",
    ];

    dynsym
        .iter()
        .filter(|s| !s.is_undefined() && s.st_value != 0)
        .filter(|s| CRITICAL_NAMES.iter().any(|n| s.name == *n))
        .map(|s| Range::new(s.st_value, 16))
        .collect()
}

/// Pin every `PT_GNU_RELRO` range. ld.so applies `mprotect(R)` over
/// these pages after relocations but before init_array fires, so any
/// stub writes there would race with the loader's protection change.
/// Pinning the entire RELRO region is the safest strategy.
pub fn collect_forbidden_relro(phdrs: &[Elf64Phdr]) -> Vec<Range> {
    phdrs
        .iter()
        .filter(|p| p.p_type == PT_GNU_RELRO && p.p_memsz > 0)
        .map(|p| Range::new(p.p_vaddr, p.p_memsz))
        .collect()
}

/// Pin the leading page of a candidate section so the writer's
/// split-section path can't shift the section start RVA. Mirrors
/// PE Phase L's `collect_forbidden_in_section` head-page pin.
pub fn pin_section_head(sec: &Elf64Shdr) -> Range {
    Range::new(sec.sh_addr, SAFE_PAGE_SIZE)
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

/// Pad each forbidden range out to its enclosing page so the page mask
/// works at OS-loader granularity. Returns an already-coalesced list.
pub fn pad_to_pages(ranges: &[Range]) -> Vec<Range> {
    let mut padded: Vec<Range> = ranges
        .iter()
        .map(|r| {
            let start_page = r.vaddr & !(SAFE_PAGE_SIZE - 1);
            let end_unaligned = r.end();
            let end_page = align_up(end_unaligned, SAFE_PAGE_SIZE);
            Range::new(start_page, end_page - start_page)
        })
        .collect();
    padded.sort_by_key(|r| (r.vaddr, r.len));
    coalesce(padded)
}

/// Compute the safe runs in a section: byte ranges where every
/// page is free of forbidden content AND every byte is initialised
/// (i.e. the section is PROGBITS, not NOBITS / .bss-style).
/// Each run is at least [`MIN_COMPRESS_RUN`] bytes long.
pub fn safe_runs_in_section(
    sec: &Elf64Shdr,
    forbidden_padded: &[Range],
) -> Vec<Range> {
    use crate::parse::headers::{SHT_PROGBITS, SHT_NOBITS};
    if sec.sh_type == SHT_NOBITS || sec.sh_size == 0 {
        return Vec::new();
    }
    if sec.sh_type != SHT_PROGBITS {
        return Vec::new();
    }
    let sec_start = sec.sh_addr;
    let sec_end = sec_start.saturating_add(sec.sh_size);

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

    runs.into_iter()
        .filter_map(|r| {
            let inner_start = align_up(r.vaddr, SAFE_PAGE_SIZE);
            let inner_end = r.end() & !(SAFE_PAGE_SIZE - 1);
            if inner_end > inner_start && inner_end - inner_start >= MIN_COMPRESS_RUN {
                Some(Range::new(inner_start, inner_end - inner_start))
            } else {
                None
            }
        })
        .collect()
}

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
    use crate::parse::headers::{SHT_PROGBITS, SHT_NOBITS};

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
        let v = coalesce(vec![r(0x1000, 0x100), r(0x1200, 0x100)]);
        assert_eq!(v, vec![r(0x1000, 0x100), r(0x1200, 0x100)]);
    }

    #[test]
    fn pad_to_pages_rounds_to_page_boundary() {
        let v = pad_to_pages(&[r(0x1234, 0x10)]);
        assert_eq!(v, vec![r(0x1000, 0x1000)]);
        let v = pad_to_pages(&[r(0x1234, 0x10), r(0x2300, 0x10)]);
        assert_eq!(v, vec![r(0x1000, 0x2000)]);
    }

    fn fake_section(name: &str, addr: u64, size: u64, ty: u32) -> Elf64Shdr {
        Elf64Shdr {
            name: name.to_string(),
            sh_name: 0,
            sh_type: ty,
            sh_flags: 0x2,
            sh_addr: addr,
            sh_offset: addr,
            sh_size: size,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        }
    }

    #[test]
    fn safe_runs_skips_bss_and_short_runs() {
        let sec = fake_section(".bss", 0x10000, 0x40000, SHT_NOBITS);
        assert!(safe_runs_in_section(&sec, &[]).is_empty());

        let small = fake_section(".rodata", 0x10000, 0x1000, SHT_PROGBITS);
        // 1 page < MIN_COMPRESS_RUN
        assert!(safe_runs_in_section(&small, &[]).is_empty());
    }

    #[test]
    fn safe_runs_carves_around_forbidden_pages() {
        let sec = fake_section(".rodata", 0x10000, 0x40000, SHT_PROGBITS);
        let forbidden = vec![r(0x20000, SAFE_PAGE_SIZE)];
        let runs = safe_runs_in_section(&sec, &forbidden);
        // Head run 0x10000..0x20000 (64 KiB), tail run 0x21000..0x50000 (188 KiB).
        assert_eq!(runs, vec![r(0x10000, 0x10000), r(0x21000, 0x2F000)]);
    }

    #[test]
    fn forbidden_relocs_picks_up_rw_load_only() {
        use crate::parse::headers::{PF_R, PF_W, PF_X, PT_LOAD};
        use crate::parse::relocations::Rela;

        // Two LOADs: one R-only, one RW.
        let phdrs = vec![
            Elf64Phdr {
                p_type: PT_LOAD, p_flags: PF_R,
                p_offset: 0, p_vaddr: 0x1000, p_paddr: 0x1000,
                p_filesz: 0x10000, p_memsz: 0x10000, p_align: 0x1000,
            },
            Elf64Phdr {
                p_type: PT_LOAD, p_flags: PF_R | PF_W,
                p_offset: 0x20000, p_vaddr: 0x20000, p_paddr: 0x20000,
                p_filesz: 0x10000, p_memsz: 0x10000, p_align: 0x1000,
            },
        ];
        let relas = vec![
            Rela { r_offset: 0x2000, r_info: 8, r_addend: 0 },  // in R-only LOAD
            Rela { r_offset: 0x25000, r_info: 8, r_addend: 0 }, // in RW LOAD
            Rela { r_offset: 0x28000, r_info: 8, r_addend: 0 }, // in RW LOAD
        ];
        let result = collect_forbidden_relocs(&relas, &phdrs);
        // Only the two in RW LOAD should be pinned.
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], r(0x25000, 8));
        assert_eq!(result[1], r(0x28000, 8));
    }

    #[test]
    fn forbidden_critical_globals_skips_undefined() {
        use crate::parse::symbols::DynSymbol;

        let syms = vec![
            DynSymbol {
                name: "__stack_chk_guard".into(),
                st_name: 1, st_info: 0x11, st_other: 0,
                st_shndx: 10, // defined
                st_value: 0x30000, st_size: 8,
            },
            DynSymbol {
                name: "environ".into(),
                st_name: 2, st_info: 0x11, st_other: 0,
                st_shndx: 0, // undefined
                st_value: 0, st_size: 0,
            },
            DynSymbol {
                name: "__progname".into(),
                st_name: 3, st_info: 0x11, st_other: 0,
                st_shndx: 12, // defined
                st_value: 0x30100, st_size: 8,
            },
            DynSymbol {
                name: "unrelated_func".into(),
                st_name: 4, st_info: 0x12, st_other: 0,
                st_shndx: 5,
                st_value: 0x40000, st_size: 16,
            },
        ];
        let result = collect_forbidden_critical_globals(&syms);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], r(0x30000, 16));
        assert_eq!(result[1], r(0x30100, 16));
    }

    #[test]
    fn forbidden_relro_covers_pt_gnu_relro() {
        use crate::parse::headers::PT_GNU_RELRO;

        let phdrs = vec![
            Elf64Phdr {
                p_type: PT_GNU_RELRO, p_flags: 4,
                p_offset: 0, p_vaddr: 0x50000, p_paddr: 0x50000,
                p_filesz: 0x2000, p_memsz: 0x3000, p_align: 1,
            },
        ];
        let result = collect_forbidden_relro(&phdrs);
        assert_eq!(result, vec![r(0x50000, 0x3000)]);
    }

    #[test]
    fn pin_section_head_returns_first_page() {
        let sec = fake_section(".data", 0x234b600, 0x67ff8, SHT_PROGBITS);
        let pinned = pin_section_head(&sec);
        assert_eq!(pinned, r(0x234b600, SAFE_PAGE_SIZE));
    }
}
