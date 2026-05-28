//! Final ELF writer (M1L).
//!
//! Takes a parsed [`ElfImage`], an optional stub blob and an
//! optional payload blob, and produces a packed ELF on disk.
//!
//! # Layout strategy
//!
//! 1. Original file bytes are copied verbatim into the output buffer.
//! 2. New PT_LOAD segments are appended at the end of the file:
//!       - `.upobf0` (R+X): contains the relocated phdr table at its
//!         head, then the stub bytes.
//!       - `.upobf2` (R+W): contains the rewritten `.init_array`
//!         table and the rewritten `.rela.dyn` (only present when
//!         init_array injection is enabled). Must be writable so
//!         ld.so can apply R_X86_64_RELATIVE relocations onto the
//!         init_array slots before invoking them.
//!       - `.upobf1` (R): contains the encrypted payload blob (when
//!         supplied).
//! 3. The ELF header `e_phoff` is rewritten to point inside `.upobf0`
//!    so ld.so reads the new phdr table; the new PT_PHDR entry in
//!    that table also points at itself.
//! 4. When init_array injection is enabled, the `.dynamic` table is
//!    rewritten in place to redirect:
//!       * `DT_INIT_ARRAY` / `DT_INIT_ARRAYSZ` -> new array in .upobf2
//!       * `DT_RELA` / `DT_RELASZ` / `DT_RELACOUNT` -> new rela in .upobf2
//!    The new arrays are immediately consumed by ld.so via these
//!    DT_* tags; the original copies stay in place but are no
//!    longer referenced.
//!
//! `e_entry` is rewritten to point at the stub's
//! `upobf_entry_trampoline` when [`PackedElfBuilder::with_entry_redirect`]
//! is enabled (Phase I). The trampoline runs the full stub init
//! pipeline before jumping to the host's original entry point. PE
//! Phase I uses prologue-stealing instead because Windows entry
//! semantics differ; on glibc the main executable's
//! `DT_INIT_ARRAY` runs from inside `__libc_start_main`, which
//! itself is reached via `_start`, so an init_array hook can't
//! fire before `_start` reads compressed `.text` bytes.
//!
//! # Constraints honoured by the writer
//!
//! - The original bytes for any forbidden range stay verbatim at
//!   their original RVAs (handled by leaving the host bytes alone
//!   when no payload is supplied; in M3L+ the payload builder will
//!   absorb compressible runs after consulting [`safe_ranges`]).
//! - The new phdr table is placed inside the .upobf0 LOAD region so
//!   ld.so always sees it as part of a valid memory mapping. The
//!   PT_PHDR entry covers exactly the new table size.
//! - All new RELATIVE relocations injected into `.rela.dyn` are
//!   added BEFORE existing entries so `DT_RELACOUNT` (if present)
//!   keeps describing a contiguous prefix of RELATIVE entries.

use anyhow::{anyhow, bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};

use crate::parse::headers::{
    Elf64Phdr, PHDR64_SIZE, SHDR64_SIZE, PF_R, PF_W, PF_X, PT_LOAD, PT_PHDR,
};
use crate::parse::ElfImage;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Page alignment for new LOAD segments.
const PAGE_SIZE: u64 = 0x1000;

/// Reserved bytes at the head of `.upobf0` for the relocated phdr
/// table. We pick 0x800 (2 KiB) which fits 36 phdr entries. With
/// LOAD-splitting (one sub-LOAD per file-backed run between
/// compressed holes) the demo now ships ~20 entries; 36 leaves
/// headroom for additional Tier-2 chunks or PT_NOTE smuggling.
pub const PHDR_TABLE_RESERVE: u64 = 0x800;

/// One file-backed slice of an original PT_LOAD. The writer emits
/// one [`Elf64Phdr`] of type `PT_LOAD` per `HostRun`. Each run's
/// `memsz` extends past `file_len` to virtually cover the
/// compressed hole that follows it (the kernel zero-fills
/// `[file_len, memsz)`).
struct HostRun {
    /// Index into the original `image.phdrs` we inherit flags / align
    /// from.
    phdr_template_idx: usize,
    /// Vaddr where this run begins.
    vaddr: u64,
    /// Bytes copied verbatim from the original file.
    file_len: u64,
    /// Virtual coverage (== `file_len + zero-fill tail`). Tail
    /// either covers a compressed hole (mid-LOAD) or the BSS
    /// portion of the very last run.
    memsz: u64,
    /// Source file offset in the *original* image.
    src_file_off: u64,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct PackedElfBuilder<'a> {
    image: &'a ElfImage,
    /// Optional stub bytes that go inside `.upobf0` after the relocated
    /// phdr table. None ⇒ baseline passthrough mode.
    stub: Option<Vec<u8>>,
    /// Optional payload bytes that go inside `.upobf1`. None ⇒ skip
    /// payload segment entirely.
    payload: Option<Vec<u8>>,
    /// When true, rewrite `.init_array` to put `stub_init_rva` first.
    /// Requires `stub.is_some()` and a valid `stub_init_offset`.
    inject_init_array: bool,
    /// Offset (within stub bytes) of the stub's init_array entry.
    /// Combined with `.upobf0` base RVA + PHDR_TABLE_RESERVE to derive
    /// the absolute init function address written into `.init_array`.
    stub_init_offset: u64,
    /// Phase I e_entry redirect. When `Some`, the writer rewrites the
    /// ELF header `e_entry` to point at the stub's
    /// `upobf_entry_trampoline` (offset given here, relative to stub
    /// bytes). The trampoline runs the full stub init pipeline and
    /// then jumps to the host's original entry point. Requires
    /// `stub.is_some()`.
    entry_trampoline_offset: Option<u64>,
    /// Half-open vaddr ranges whose bytes are zeroed in the output
    /// because the payload owns them now. The kernel maps zero pages
    /// at those vaddrs (filesz still covers them; but the on-disk
    /// bytes are 0); the stub's init_array callback writes the
    /// decompressed bytes back via `mprotect(RW)` then restores the
    /// original protection.
    compressed_ranges: Vec<(u64, u64)>,
}

impl<'a> PackedElfBuilder<'a> {
    pub fn new(image: &'a ElfImage) -> Self {
        Self {
            image,
            stub: None,
            payload: None,
            inject_init_array: false,
            stub_init_offset: 0,
            entry_trampoline_offset: None,
            compressed_ranges: Vec::new(),
        }
    }

    pub fn with_stub(mut self, stub_bytes: Vec<u8>, init_offset: u64) -> Self {
        self.stub = Some(stub_bytes);
        self.stub_init_offset = init_offset;
        self
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn enable_init_array_injection(mut self, on: bool) -> Self {
        self.inject_init_array = on;
        self
    }

    /// Phase I: redirect the ELF header `e_entry` to the stub's
    /// trampoline (offset given relative to the stub bytes). The
    /// trampoline runs `upobf_stub_init`, then jumps to the host's
    /// original entry point. Pass `None` to disable redirect.
    pub fn with_entry_redirect(mut self, trampoline_offset: u64) -> Self {
        self.entry_trampoline_offset = Some(trampoline_offset);
        self
    }

    /// Mark a `[vaddr, vaddr+len)` range as compressed by the
    /// payload. The writer zeros the matching file bytes so the
    /// kernel maps that region as zero-filled at run time.
    pub fn mark_compressed_range(mut self, vaddr: u64, len: u64) -> Self {
        self.compressed_ranges.push((vaddr, len));
        self
    }

    /// Produce the packed ELF bytes.
    pub fn build(self) -> Result<Vec<u8>> {
        use crate::parse::headers::{PT_DYNAMIC, SHT_NOBITS};
        use crate::parse::relocations::RELA_ENTRY_SIZE;

        let raw = &self.image.raw;

        // ---- 1. Compute "file-backed runs" per original PT_LOAD --------
        //
        // A "run" is a contiguous portion of an original PT_LOAD that
        // we keep backing on disk. Compressed ranges produce holes
        // *inside* a LOAD; each hole splits the LOAD into runs that
        // straddle it.
        //
        // ld.so requires `(p_vaddr - p_offset) % p_align == 0`; we
        // honour that by snapping each hole's [start, end) inward to
        // page boundaries. Bytes between the hole's user-supplied
        // boundary and the page boundary stay file-backed but get
        // overwritten with zeros (the stub re-decompresses them at
        // runtime, so the on-disk content is irrelevant).
        //
        // For each original PT_LOAD we end up with one of:
        //
        //   * Empty hole list                     => 1 run = the whole LOAD
        //   * N holes wholly inside the LOAD      => N+1 runs (head + N gaps + tail)
        //
        // The first run keeps the original LOAD's filesz/memsz quirk
        // (e.g. the BSS tail where memsz > filesz). Subsequent
        // sub-LOADs are pure file-backed (filesz == memsz of their
        // run), and any final memsz-only tail of the original LOAD
        // becomes the last sub-LOAD's mem-only padding.

        // Snap a `(vaddr, len)` range inward to page bounds.
        // Returns None if the snapped range is empty.
        let snap = |vaddr: u64, len: u64| -> Option<(u64, u64)> {
            if len == 0 {
                return None;
            }
            let start = align_up(vaddr, PAGE_SIZE);
            let end = (vaddr + len) & !(PAGE_SIZE - 1);
            if end > start {
                Some((start, end - start))
            } else {
                None
            }
        };

        // Group snapped holes by enclosing PT_LOAD index.
        let mut holes_per_load: Vec<Vec<(u64, u64)>> =
            vec![Vec::new(); self.image.phdrs.len()];
        for (vaddr, len) in &self.compressed_ranges {
            let Some((sva, slen)) = snap(*vaddr, *len) else { continue };
            let mut placed = false;
            for (i, p) in self.image.phdrs.iter().enumerate() {
                if p.p_type != PT_LOAD {
                    continue;
                }
                if sva >= p.p_vaddr && sva + slen <= p.p_vaddr + p.p_filesz {
                    holes_per_load[i].push((sva, slen));
                    placed = true;
                    break;
                }
            }
            if !placed {
                bail!(
                    "compressed range vaddr {:#x}+{:#x} (snapped to {:#x}+{:#x}) \
                     not contained in any PT_LOAD's filesz region",
                    vaddr, len, sva, slen
                );
            }
        }
        // Sort + sanity-check no overlaps.
        for holes in holes_per_load.iter_mut() {
            holes.sort_by_key(|h| h.0);
            for w in holes.windows(2) {
                if w[0].0 + w[0].1 > w[1].0 {
                    bail!(
                        "overlapping compressed ranges: {:#x}+{:#x} vs {:#x}+{:#x}",
                        w[0].0, w[0].1, w[1].0, w[1].1
                    );
                }
            }
        }

        // ---- 2. Build the new PT_LOAD list (with sub-LOADs) ------------
        //
        // For each original PT_LOAD, emit one or more sub-LOADs that
        // collectively cover the same vaddr range. Holes inside a
        // sub-LOAD are skipped on disk: we close the current
        // sub-LOAD at the hole's start, then open a fresh sub-LOAD
        // immediately after the hole ends. The hole's bytes are
        // covered by the previous sub-LOAD's `p_memsz`-vs-`p_filesz`
        // gap (kernel zero-fills the unbacked tail).
        //
        // To keep ld.so's `(p_vaddr - p_offset) % p_align == 0`
        // invariant trivially satisfiable, every sub-LOAD past the
        // first one starts at a page-aligned vaddr (because we
        // snapped holes inward to page bounds).
        //
        // Each entry collected here ends up as one PT_LOAD sub-segment.
        let mut runs: Vec<HostRun> = Vec::new();

        for (i, p) in self.image.phdrs.iter().enumerate() {
            if p.p_type != PT_LOAD {
                continue;
            }
            let mut cursor_va = p.p_vaddr;
            let load_file_end_va = p.p_vaddr + p.p_filesz;
            let load_mem_end_va = p.p_vaddr + p.p_memsz;
            for &(hva, hlen) in &holes_per_load[i] {
                let head_len = hva - cursor_va;
                runs.push(HostRun {
                    phdr_template_idx: i,
                    vaddr: cursor_va,
                    file_len: head_len,
                    // Run extends virtually to cover the hole that
                    // immediately follows so the kernel zero-fills it.
                    memsz: head_len + hlen,
                    src_file_off: p.p_offset + (cursor_va - p.p_vaddr),
                });
                cursor_va = hva + hlen;
            }
            // Final run covers [cursor_va, load_file_end_va) on disk,
            // plus the BSS tail if any.
            let tail_file_len = load_file_end_va.saturating_sub(cursor_va);
            let tail_mem_len = load_mem_end_va.saturating_sub(cursor_va);
            runs.push(HostRun {
                phdr_template_idx: i,
                vaddr: cursor_va,
                file_len: tail_file_len,
                memsz: tail_mem_len,
                src_file_off: p.p_offset + (cursor_va - p.p_vaddr),
            });
        }

        // ---- 3. Lay out the output file -------------------------------
        //
        // Phase 1: ELF header + new phdr table at file offset 0.
        // Phase 2: each HostRun packed sequentially with page skew.
        // Phase 3: stub (.upobf0), upobf2 (init_array+rela), upobf1 (payload).
        //
        // We need to know the phdr count up front to reserve the
        // header region. Total = HostRuns + .upobf0 + maybe .upobf2 +
        // maybe .upobf1 + every non-LOAD phdr from the original (PHDR/
        // INTERP/DYNAMIC/NOTE/TLS/GNU_*).

        let stub_bytes = self.stub.as_deref().unwrap_or(&[]);
        let init_array_va = self.image.dynamic.as_ref()
            .and_then(|d| d.init_array);
        let init_array_size = self.image.dynamic.as_ref()
            .and_then(|d| d.init_arraysz)
            .unwrap_or(0);
        let host_init_count = (init_array_size / 8) as usize;

        let new_rela_entries: Vec<RelaWrite> = if self.inject_init_array {
            collect_rela_for_init_redirect(self.image, host_init_count)?
        } else {
            Vec::new()
        };
        let new_init_array_bytes_len: u64 = if self.inject_init_array {
            8 * (1 + host_init_count as u64)
        } else {
            0
        };
        let new_rela_bytes_len: u64 =
            new_rela_entries.len() as u64 * RELA_ENTRY_SIZE as u64;

        let stub_off_in_upobf0 = PHDR_TABLE_RESERVE;
        let upobf0_size = align_up(stub_off_in_upobf0 + stub_bytes.len() as u64, PAGE_SIZE);

        let init_array_off_in_upobf2: u64 = 0;
        let rela_off_in_upobf2: u64 = align_up(new_init_array_bytes_len, 8);
        let upobf2_inner_end = rela_off_in_upobf2 + new_rela_bytes_len;
        let have_upobf2 = self.inject_init_array && upobf2_inner_end > 0;
        let upobf2_size: u64 = if have_upobf2 {
            align_up(upobf2_inner_end, PAGE_SIZE)
        } else {
            0
        };

        let payload_bytes = self.payload.as_deref().unwrap_or(&[]);
        let upobf1_size: u64 = align_up(payload_bytes.len() as u64, PAGE_SIZE).max(PAGE_SIZE);
        let have_upobf1 = !payload_bytes.is_empty();

        // ---- Allocate vaddrs for appended segments --------------------
        let mut va_cursor: u64 = self
            .image
            .phdrs
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .map(|p| p.p_vaddr + p.p_memsz)
            .max()
            .ok_or_else(|| anyhow!("no PT_LOAD segments"))?;
        va_cursor = align_up(va_cursor, PAGE_SIZE);

        let upobf0_vaddr = va_cursor;
        va_cursor += upobf0_size;
        let upobf2_vaddr = va_cursor;
        if have_upobf2 { va_cursor += upobf2_size; }
        let upobf1_vaddr = va_cursor;
        if have_upobf1 { va_cursor += upobf1_size; }
        let _ = va_cursor; // unused after this point

        // ---- Count phdrs to figure header size ------------------------
        // All original non-LOAD phdrs + N HostRuns + .upobf0 +
        // .upobf2? + .upobf1?
        let non_load_phdr_count = self.image.phdrs
            .iter()
            .filter(|p| p.p_type != PT_LOAD)
            .count();
        let final_phnum: u64 = (non_load_phdr_count as u64)
            + (runs.len() as u64)
            + 1u64
            + (have_upobf2 as u64)
            + (have_upobf1 as u64);
        let phdr_table_bytes = final_phnum * PHDR64_SIZE as u64;
        if phdr_table_bytes > PHDR_TABLE_RESERVE {
            bail!(
                "new phdr table {} bytes ({} entries) overflows reserve {} bytes — bump PHDR_TABLE_RESERVE",
                phdr_table_bytes, final_phnum, PHDR_TABLE_RESERVE
            );
        }

        // ---- File-offset assignment ------------------------------------
        //
        // Strategy: keep the ELF header + main phdr table at file
        // offset 0 (mirrors how every linker lays things out). The
        // first HostRun normally starts at vaddr 0 (the read-only
        // ELF header LOAD), so its file offset can be 0 too —
        // satisfying `(vaddr - offset) % page == 0`. We just need
        // the file portion of that first run to be large enough to
        // contain the rebuilt phdr table (it usually is — the
        // original first LOAD covers ~10 MiB of headers + .rodata).
        //
        // For subsequent runs, we advance the file cursor with page
        // skew matching the run's vaddr. This ensures
        // `(p_vaddr - p_offset) & 0xFFF == 0` on every sub-LOAD.

        // Helper: bump file cursor to satisfy page skew == vaddr & 0xfff.
        let align_file_for_vaddr = |cur: u64, vaddr: u64| -> u64 {
            let target_skew = vaddr & (PAGE_SIZE - 1);
            let cur_skew = cur & (PAGE_SIZE - 1);
            if cur_skew == target_skew {
                cur
            } else if cur_skew < target_skew {
                cur + (target_skew - cur_skew)
            } else {
                cur + (PAGE_SIZE - cur_skew) + target_skew
            }
        };

        let mut run_file_offsets: Vec<u64> = Vec::with_capacity(runs.len());
        let mut file_cursor: u64 = 0;
        for r in &runs {
            file_cursor = align_file_for_vaddr(file_cursor, r.vaddr);
            run_file_offsets.push(file_cursor);
            file_cursor += r.file_len;
        }
        // Page-align before appended segments so subsequent LOAD
        // p_offsets stay clean.
        file_cursor = align_up(file_cursor, PAGE_SIZE);

        let upobf0_file_off = align_file_for_vaddr(file_cursor, upobf0_vaddr);
        file_cursor = upobf0_file_off + upobf0_size;
        let upobf2_file_off = if have_upobf2 {
            let f = align_file_for_vaddr(file_cursor, upobf2_vaddr);
            file_cursor = f + upobf2_size;
            f
        } else { 0 };
        let upobf1_file_off = if have_upobf1 {
            let f = align_file_for_vaddr(file_cursor, upobf1_vaddr);
            file_cursor = f + upobf1_size;
            f
        } else { 0 };

        let total_file_len = file_cursor;

        // ---- 4. Build the new phdr table -------------------------------
        let mut new_phdrs: Vec<Elf64Phdr> = Vec::with_capacity(final_phnum as usize);

        // (a) HostRun sub-LOADs (one per run).
        for (i, r) in runs.iter().enumerate() {
            let template = &self.image.phdrs[r.phdr_template_idx];
            new_phdrs.push(Elf64Phdr {
                p_type: PT_LOAD,
                p_flags: template.p_flags,
                p_offset: run_file_offsets[i],
                p_vaddr: r.vaddr,
                p_paddr: r.vaddr,
                p_filesz: r.file_len,
                p_memsz: r.memsz,
                p_align: template.p_align.max(PAGE_SIZE),
            });
        }

        // (b) Original non-LOAD phdrs, with file offsets re-mapped
        //     through the LOAD layout (vaddr stays put, file offset
        //     follows the new run that contains the vaddr).
        //
        // PT_PHDR is a special case: it points at the new phdr
        // table at file offset 0 (or wherever we put it). We rewrite
        // it explicitly so a stale offset can't bite ld.so.
        let vaddr_to_new_file_off = |va: u64| -> Option<u64> {
            for (i, r) in runs.iter().enumerate() {
                if va >= r.vaddr && va < r.vaddr + r.file_len {
                    return Some(run_file_offsets[i] + (va - r.vaddr));
                }
            }
            None
        };
        for p in &self.image.phdrs {
            if p.p_type == PT_LOAD {
                continue;
            }
            let mut q = p.clone();
            if q.p_type == PT_PHDR {
                // We'll relocate PT_PHDR to point at the rebuilt
                // table inside .upobf0 below; for now park it at
                // the .upobf0 head.
                q.p_offset = upobf0_file_off;
                q.p_vaddr = upobf0_vaddr;
                q.p_paddr = upobf0_vaddr;
                q.p_filesz = phdr_table_bytes;
                q.p_memsz = phdr_table_bytes;
                q.p_align = 8;
            } else if q.p_filesz > 0 {
                // Look up the file offset via the run map. Some
                // entries (e.g. PT_TLS pointing at .tdata + .tbss)
                // span both file-backed and BSS; we anchor on the
                // start vaddr.
                if let Some(new_off) = vaddr_to_new_file_off(q.p_vaddr) {
                    q.p_offset = new_off;
                } else {
                    bail!(
                        "non-LOAD phdr {:?} vaddr {:#x} not covered by any run",
                        q.type_name(), q.p_vaddr
                    );
                }
            }
            // PT_DYNAMIC special: writer rewrites .dynamic in place
            // later, file offset just needs to follow vaddr.
            let _ = PT_DYNAMIC;
            new_phdrs.push(q);
        }

        // (c) .upobf0 LOAD (R+X) — also hosts the rebuilt phdr table.
        new_phdrs.push(Elf64Phdr {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_offset: upobf0_file_off,
            p_vaddr: upobf0_vaddr,
            p_paddr: upobf0_vaddr,
            p_filesz: upobf0_size,
            p_memsz: upobf0_size,
            p_align: PAGE_SIZE,
        });
        if have_upobf2 {
            new_phdrs.push(Elf64Phdr {
                p_type: PT_LOAD,
                p_flags: PF_R | PF_W,
                p_offset: upobf2_file_off,
                p_vaddr: upobf2_vaddr,
                p_paddr: upobf2_vaddr,
                p_filesz: upobf2_size,
                p_memsz: upobf2_size,
                p_align: PAGE_SIZE,
            });
        }
        if have_upobf1 {
            new_phdrs.push(Elf64Phdr {
                p_type: PT_LOAD,
                p_flags: PF_R,
                p_offset: upobf1_file_off,
                p_vaddr: upobf1_vaddr,
                p_paddr: upobf1_vaddr,
                p_filesz: upobf1_size,
                p_memsz: upobf1_size,
                p_align: PAGE_SIZE,
            });
        }
        debug_assert_eq!(new_phdrs.len() as u64, final_phnum);

        // ---- 5. Materialise output buffer ------------------------------
        let mut out = vec![0u8; total_file_len as usize];

        // Copy ELF header from the original (offset 0..0x40).
        out[..64].copy_from_slice(&raw[..64]);

        // Copy each HostRun's bytes verbatim from the original.
        for (i, r) in runs.iter().enumerate() {
            if r.file_len == 0 {
                continue;
            }
            let src = r.src_file_off as usize;
            let dst = run_file_offsets[i] as usize;
            let n = r.file_len as usize;
            if src + n > raw.len() {
                bail!(
                    "run src past EOF: {:#x}+{:#x} > {:#x}",
                    src, n, raw.len()
                );
            }
            out[dst..dst + n].copy_from_slice(&raw[src..src + n]);
        }

        // Stub bytes follow the phdr reserve inside .upobf0.
        if !stub_bytes.is_empty() {
            let stub_off = (upobf0_file_off + stub_off_in_upobf0) as usize;
            out[stub_off..stub_off + stub_bytes.len()].copy_from_slice(stub_bytes);
        }

        // .upobf2 (init_array + rela) materialisation.
        let new_init_array_vaddr = upobf2_vaddr + init_array_off_in_upobf2;
        let new_rela_vaddr = upobf2_vaddr + rela_off_in_upobf2;
        if self.inject_init_array {
            let stub_init_va: u64 = upobf0_vaddr + PHDR_TABLE_RESERVE + self.stub_init_offset;
            let off = (upobf2_file_off + init_array_off_in_upobf2) as usize;
            out[off..off + 8].copy_from_slice(&stub_init_va.to_le_bytes());
            if let Some(init_va) = init_array_va {
                let src_off = self.image.vaddr_to_file_offset(init_va)
                    .context("DT_INIT_ARRAY -> file offset")? as usize;
                let copy_len = init_array_size as usize;
                if src_off + copy_len > raw.len() {
                    bail!(
                        ".init_array past EOF: {:#x}+{:#x} > {:#x}",
                        src_off, copy_len, raw.len()
                    );
                }
                out[off + 8..off + 8 + copy_len]
                    .copy_from_slice(&raw[src_off..src_off + copy_len]);
            }
        }
        if self.inject_init_array && !new_rela_entries.is_empty() {
            let off = (upobf2_file_off + rela_off_in_upobf2) as usize;
            for (i, e) in new_rela_entries.iter().enumerate() {
                let entry_off = off + i * RELA_ENTRY_SIZE;
                let (r_offset, r_addend) = if e.is_stub_slot {
                    let stub_init_va =
                        upobf0_vaddr + PHDR_TABLE_RESERVE + self.stub_init_offset;
                    (new_init_array_vaddr, stub_init_va as i64)
                } else if e.is_old_init_slot {
                    let new_offset = new_init_array_vaddr + 8 + 8 * e.old_slot_idx as u64;
                    (new_offset, e.original_addend)
                } else {
                    (e.original_offset, e.original_addend)
                };
                LittleEndian::write_u64(&mut out[entry_off..entry_off + 8], r_offset);
                LittleEndian::write_u64(&mut out[entry_off + 8..entry_off + 16], e.original_info);
                LittleEndian::write_u64(
                    &mut out[entry_off + 16..entry_off + 24],
                    r_addend as u64,
                );
            }
        }

        // Payload bytes.
        if have_upobf1 {
            let off = upobf1_file_off as usize;
            out[off..off + payload_bytes.len()].copy_from_slice(payload_bytes);
        }

        // Write the new phdr table at the head of .upobf0.
        write_phdr_table(&mut out, upobf0_file_off as usize, &new_phdrs)?;

        // ---- 6. Patch section header table -----------------------------
        //
        // Section headers are not consumed by ld.so but `readelf`
        // and gdb will choke if their `sh_offset` no longer
        // matches the actual file location. We:
        //   * Move the shdr table to the very end of the file.
        //   * Update each non-NOBITS shdr's `sh_offset` via the
        //     vaddr->new-offset map. NOBITS sections keep their
        //     original (irrelevant) offset — convention.
        //   * Update the ELF header's `e_shoff` accordingly.
        let mut shdr_table = Vec::with_capacity(self.image.shdrs.len() * SHDR64_SIZE);
        for s in &self.image.shdrs {
            let mut sh_offset = s.sh_offset;
            if s.sh_type != SHT_NOBITS && s.sh_addr != 0 {
                if let Some(new_off) = vaddr_to_new_file_off(s.sh_addr) {
                    sh_offset = new_off;
                }
            }
            // Sections without an addr (.symtab, .strtab, .shstrtab,
            // .comment, .debug_*) live in regions of the original
            // file we may have moved. We do a best-effort fixup:
            // if the original offset falls inside any HostRun's
            // src window, redirect it to the same offset in the
            // new file.
            if s.sh_addr == 0 && s.sh_type != SHT_NOBITS && s.sh_size > 0 {
                for (i, r) in runs.iter().enumerate() {
                    if r.file_len == 0 { continue; }
                    if s.sh_offset >= r.src_file_off
                        && s.sh_offset + s.sh_size <= r.src_file_off + r.file_len
                    {
                        sh_offset = run_file_offsets[i] + (s.sh_offset - r.src_file_off);
                        break;
                    }
                }
            }
            let mut entry = [0u8; SHDR64_SIZE];
            LittleEndian::write_u32(&mut entry[0..4], s.sh_name);
            LittleEndian::write_u32(&mut entry[4..8], s.sh_type);
            LittleEndian::write_u64(&mut entry[8..16], s.sh_flags);
            LittleEndian::write_u64(&mut entry[16..24], s.sh_addr);
            LittleEndian::write_u64(&mut entry[24..32], sh_offset);
            LittleEndian::write_u64(&mut entry[32..40], s.sh_size);
            LittleEndian::write_u32(&mut entry[40..44], s.sh_link);
            LittleEndian::write_u32(&mut entry[44..48], s.sh_info);
            LittleEndian::write_u64(&mut entry[48..56], s.sh_addralign);
            LittleEndian::write_u64(&mut entry[56..64], s.sh_entsize);
            shdr_table.extend_from_slice(&entry);
        }
        // Append the new shdr table.
        let new_shoff = total_file_len;
        out.extend_from_slice(&shdr_table);
        // Also append the unmapped .symtab/.strtab/.shstrtab/etc.
        // payloads — but only those we couldn't relocate via runs.
        // Simpler approach: append the original shdr-only sections
        // verbatim if they couldn't be mapped.
        let mut tail_offsets: std::collections::HashMap<usize, u64> =
            std::collections::HashMap::new();
        for (idx, s) in self.image.shdrs.iter().enumerate() {
            if s.sh_addr != 0 || s.sh_type == SHT_NOBITS || s.sh_size == 0 {
                continue;
            }
            let mut covered = false;
            for r in &runs {
                if r.file_len == 0 { continue; }
                if s.sh_offset >= r.src_file_off
                    && s.sh_offset + s.sh_size <= r.src_file_off + r.file_len
                {
                    covered = true;
                    break;
                }
            }
            if covered { continue; }
            // Append.
            let off = out.len() as u64;
            let src = s.sh_offset as usize;
            let n = s.sh_size as usize;
            if src + n > raw.len() {
                continue;
            }
            out.extend_from_slice(&raw[src..src + n]);
            tail_offsets.insert(idx, off);
        }
        // Rewrite shdr table entries for the appended sections.
        for (idx, new_off) in &tail_offsets {
            let entry_off = new_shoff as usize + idx * SHDR64_SIZE;
            LittleEndian::write_u64(&mut out[entry_off + 24..entry_off + 32], *new_off);
        }

        // ---- 7. Patch ELF header ---------------------------------------
        // e_phoff -> upobf0_file_off; e_phnum -> final_phnum;
        // e_shoff -> new_shoff; e_shnum unchanged.
        LittleEndian::write_u64(&mut out[0x20..0x28], upobf0_file_off);
        LittleEndian::write_u16(&mut out[0x38..0x3A], final_phnum as u16);
        LittleEndian::write_u64(&mut out[0x28..0x30], new_shoff);

        if let Some(tramp_off) = self.entry_trampoline_offset {
            let tramp_va = upobf0_vaddr + PHDR_TABLE_RESERVE + tramp_off;
            LittleEndian::write_u64(&mut out[0x18..0x20], tramp_va);
        }

        // ---- 8. Patch .dynamic ----------------------------------------
        if self.inject_init_array {
            patch_dynamic(
                &mut out,
                self.image,
                new_init_array_vaddr,
                8 * (1 + host_init_count as u64),
                new_rela_vaddr,
                new_rela_bytes_len,
                count_relative_prefix(&new_rela_entries) as u64,
                &runs,
                &run_file_offsets,
            )?;
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn align_up(v: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    v.saturating_add(align - 1) & !(align - 1)
}

/// Serialise the new phdr table starting at `out[off]`.
fn write_phdr_table(out: &mut [u8], off: usize, phdrs: &[Elf64Phdr]) -> Result<()> {
    let need = phdrs.len() * PHDR64_SIZE;
    if off + need > out.len() {
        bail!(
            "phdr write past EOF: {:#x}+{:#x} > {:#x}",
            off,
            need,
            out.len()
        );
    }
    for (i, p) in phdrs.iter().enumerate() {
        let base = off + i * PHDR64_SIZE;
        LittleEndian::write_u32(&mut out[base..base + 4], p.p_type);
        LittleEndian::write_u32(&mut out[base + 4..base + 8], p.p_flags);
        LittleEndian::write_u64(&mut out[base + 8..base + 16], p.p_offset);
        LittleEndian::write_u64(&mut out[base + 16..base + 24], p.p_vaddr);
        LittleEndian::write_u64(&mut out[base + 24..base + 32], p.p_paddr);
        LittleEndian::write_u64(&mut out[base + 32..base + 40], p.p_filesz);
        LittleEndian::write_u64(&mut out[base + 40..base + 48], p.p_memsz);
        LittleEndian::write_u64(&mut out[base + 48..base + 56], p.p_align);
    }
    Ok(())
}

/// One entry the writer wants to emit into the relocated `.rela.dyn`.
///
/// The sort key during construction matters: ld.so honours
/// `DT_RELACOUNT`, which says "the first N entries are RELATIVE".
/// We therefore put every RELATIVE entry first (in stable order:
/// our new stub-init slot, then the rewritten old init slots, then
/// the remaining host RELATIVE entries) and append everything else
/// in the original order.
#[derive(Debug, Clone)]
struct RelaWrite {
    /// Original `r_offset` (used when `is_stub_slot`/`is_old_init_slot`
    /// are both false).
    original_offset: u64,
    /// `r_info` to emit verbatim.
    original_info: u64,
    /// `r_addend` to emit (or for `is_stub_slot`, ignored — recomputed
    /// at materialise time once we know the stub VA).
    original_addend: i64,
    /// True for the single new RELATIVE entry pointing at slot 0 of
    /// the rebuilt init_array.
    is_stub_slot: bool,
    /// True for entries whose original `r_offset` pointed at one of
    /// the old init_array slots and that the writer has to redirect
    /// to the corresponding new slot.
    is_old_init_slot: bool,
    /// Index into the *new* init_array (1..=N for the host slots) for
    /// `is_old_init_slot` entries; 0 otherwise.
    old_slot_idx: u32,
}

/// Build the new `.rela.dyn` payload when redirecting init_array.
fn collect_rela_for_init_redirect(
    image: &crate::ElfImage,
    host_init_count: usize,
) -> Result<Vec<RelaWrite>> {
    use crate::parse::dynamic::{DT_INIT_ARRAY, DT_INIT_ARRAYSZ};
    use crate::parse::relocations::R_X86_64_RELATIVE;

    // Compute the half-open range [init_array, init_array+size) so
    // we can identify the RELATIVE entries that point at the old
    // slots.
    let dyn_info = image
        .dynamic
        .as_ref()
        .ok_or_else(|| anyhow!("rela rebuild requires PT_DYNAMIC"))?;
    let init_va = dyn_info
        .init_array
        .ok_or_else(|| anyhow!("DT_INIT_ARRAY missing"))?;
    let init_sz = dyn_info.init_arraysz.unwrap_or(0);
    debug_assert_eq!(init_sz / 8, host_init_count as u64);

    let mut out: Vec<RelaWrite> = Vec::with_capacity(image.rela_dyn.len() + 1);

    // Slot 0: NEW stub-init RELATIVE entry. r_info encodes
    // (sym=0, type=R_X86_64_RELATIVE).
    out.push(RelaWrite {
        original_offset: 0, // filled at materialise
        original_info: R_X86_64_RELATIVE as u64,
        original_addend: 0, // filled at materialise (= stub VA)
        is_stub_slot: true,
        is_old_init_slot: false,
        old_slot_idx: 0,
    });

    // Pass 1: RELATIVE entries that target the old init_array. Their
    // r_offset gets redirected to the new init_array slot.
    for r in &image.rela_dyn {
        if r.r_type() != R_X86_64_RELATIVE {
            continue;
        }
        if r.r_offset >= init_va && r.r_offset < init_va + init_sz {
            let slot_idx = (r.r_offset - init_va) / 8;
            out.push(RelaWrite {
                original_offset: r.r_offset,
                original_info: r.r_info,
                original_addend: r.r_addend,
                is_stub_slot: false,
                is_old_init_slot: true,
                old_slot_idx: slot_idx as u32,
            });
        }
    }

    // Pass 2: the remaining RELATIVE entries.
    for r in &image.rela_dyn {
        if r.r_type() != R_X86_64_RELATIVE {
            continue;
        }
        if r.r_offset >= init_va && r.r_offset < init_va + init_sz {
            continue;
        }
        out.push(RelaWrite {
            original_offset: r.r_offset,
            original_info: r.r_info,
            original_addend: r.r_addend,
            is_stub_slot: false,
            is_old_init_slot: false,
            old_slot_idx: 0,
        });
    }

    // Pass 3: non-RELATIVE entries (must come AFTER the RELATIVE
    // prefix so DT_RELACOUNT stays valid).
    for r in &image.rela_dyn {
        if r.r_type() == R_X86_64_RELATIVE {
            continue;
        }
        out.push(RelaWrite {
            original_offset: r.r_offset,
            original_info: r.r_info,
            original_addend: r.r_addend,
            is_stub_slot: false,
            is_old_init_slot: false,
            old_slot_idx: 0,
        });
    }

    // Suppress unused-import warnings for tags only consumed in
    // `patch_dynamic` below.
    let _ = (DT_INIT_ARRAY, DT_INIT_ARRAYSZ);
    Ok(out)
}

/// Number of leading RELATIVE entries (matches DT_RELACOUNT).
fn count_relative_prefix(entries: &[RelaWrite]) -> usize {
    use crate::parse::relocations::R_X86_64_RELATIVE;
    let r_type_relative = R_X86_64_RELATIVE as u64;
    entries
        .iter()
        .take_while(|e| (e.original_info & 0xFFFF_FFFF) == r_type_relative)
        .count()
}

/// Rewrite the `DT_INIT_ARRAY`, `DT_INIT_ARRAYSZ`, `DT_RELA`,
/// `DT_RELASZ`, and `DT_RELACOUNT` entries inside `.dynamic` in
/// place to point at the new arrays. `runs` + `run_file_offsets`
/// are needed so we can locate the new file offset of `.dynamic`
/// after host-run repacking.
fn patch_dynamic(
    out: &mut [u8],
    image: &crate::ElfImage,
    new_init_va: u64,
    new_init_sz: u64,
    new_rela_va: u64,
    new_rela_sz: u64,
    new_relacount: u64,
    runs: &[HostRun],
    run_file_offsets: &[u64],
) -> Result<()> {
    use crate::parse::dynamic::{
        DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_RELA, DT_RELACOUNT, DT_RELASZ, DT_ENTRY_SIZE,
    };

    let dyn_info = image
        .dynamic
        .as_ref()
        .ok_or_else(|| anyhow!("dynamic patch requires PT_DYNAMIC"))?;

    // The original .dynamic's file offset is no longer valid in the
    // repacked output; locate the new one via the run map.
    // Vaddr comes from the PT_DYNAMIC phdr (DynamicInfo only stores
    // the original file offset).
    let dyn_vaddr = image.phdrs
        .iter()
        .find(|p| p.p_type == crate::parse::headers::PT_DYNAMIC)
        .map(|p| p.p_vaddr)
        .ok_or_else(|| anyhow!("PT_DYNAMIC phdr missing"))?;
    let mut new_base_off: Option<u64> = None;
    for (i, r) in runs.iter().enumerate() {
        if r.file_len == 0 { continue; }
        if dyn_vaddr >= r.vaddr && dyn_vaddr < r.vaddr + r.file_len {
            new_base_off = Some(run_file_offsets[i] + (dyn_vaddr - r.vaddr));
            break;
        }
    }
    let base_off = new_base_off
        .ok_or_else(|| anyhow!("dynamic vaddr {:#x} not in any host run", dyn_vaddr))?
        as usize;

    for (i, entry) in dyn_info.raw.iter().enumerate() {
        let entry_off = base_off + i * DT_ENTRY_SIZE;
        match entry.tag {
            DT_INIT_ARRAY => {
                LittleEndian::write_u64(&mut out[entry_off + 8..entry_off + 16], new_init_va);
            }
            DT_INIT_ARRAYSZ => {
                LittleEndian::write_u64(&mut out[entry_off + 8..entry_off + 16], new_init_sz);
            }
            DT_RELA => {
                LittleEndian::write_u64(&mut out[entry_off + 8..entry_off + 16], new_rela_va);
            }
            DT_RELASZ => {
                LittleEndian::write_u64(&mut out[entry_off + 8..entry_off + 16], new_rela_sz);
            }
            DT_RELACOUNT => {
                LittleEndian::write_u64(&mut out[entry_off + 8..entry_off + 16], new_relacount);
            }
            _ => {}
        }
    }

    Ok(())
}

/// Helpers re-exported for external assertions in tests.
pub fn page_size() -> u64 {
    PAGE_SIZE
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_up_is_idempotent() {
        assert_eq!(align_up(0, 0x1000), 0);
        assert_eq!(align_up(1, 0x1000), 0x1000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
    }

    #[test]
    fn phdr_reserve_holds_thirtysix_entries() {
        // 36 phdrs * 56 bytes == 2016 < 2048.
        assert!(36 * PHDR64_SIZE as u64 <= PHDR_TABLE_RESERVE);
        // 37 phdrs would not fit.
        assert!(37 * PHDR64_SIZE as u64 > PHDR_TABLE_RESERVE);
    }
}
