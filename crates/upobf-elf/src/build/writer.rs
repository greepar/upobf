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
    Elf64Phdr, PHDR64_SIZE, PF_R, PF_W, PF_X, PT_LOAD, PT_PHDR,
};
use crate::parse::ElfImage;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Page alignment for new LOAD segments.
const PAGE_SIZE: u64 = 0x1000;

/// Reserved bytes at the head of `.upobf0` for the relocated phdr
/// table. We pick 0x400 (1 KiB) which fits 18 phdr entries (the demo
/// has 12 + 2 new = 14, so 18 leaves headroom for future Phase JL
/// PT_NOTE smuggling or extra PT_GNU_PROPERTY entries).
pub const PHDR_TABLE_RESERVE: u64 = 0x400;

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
        use crate::parse::relocations::RELA_ENTRY_SIZE;

        let raw = &self.image.raw;
        let _ehdr = &self.image.ehdr;

        // ---- 1. Compute layout ------------------------------------------
        // The new file starts as a verbatim copy of the original, then
        // grows. For M1L we keep the original phdr table in place
        // (ld.so reads from `e_phoff` so we just point it at the new
        // location after we install one).

        // File-end and virtual-address-end after the original bytes.
        let mut file_cursor: u64 = raw.len() as u64;
        // The highest vaddr end across PT_LOAD segments — we have to
        // start new LOAD segments above this so vaddrs don't overlap.
        let mut va_cursor: u64 = self
            .image
            .phdrs
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .map(|p| p.p_vaddr + p.p_memsz)
            .max()
            .ok_or_else(|| anyhow!("no PT_LOAD segments"))?;

        // Align both cursors up to a 4 KiB boundary so .upobf0's
        // phdr-relative base sits cleanly. ld.so requires
        // (vaddr - offset) % p_align == 0 for each LOAD segment.
        file_cursor = align_up(file_cursor, PAGE_SIZE);
        va_cursor = align_up(va_cursor, PAGE_SIZE);
        let page_skew = file_cursor.wrapping_sub(va_cursor) & (PAGE_SIZE - 1);
        if page_skew != 0 {
            bail!(
                "internal: file/vaddr alignment skew ({:#x} vs {:#x})",
                file_cursor,
                va_cursor
            );
        }

        // .upobf0 layout (file order, all aligned to 8 bytes):
        //
        //     +0                    new phdr table (PHDR_TABLE_RESERVE)
        //     +PHDR_TABLE_RESERVE   stub bytes
        //
        // .upobf2 (writable, only created when injecting init_array):
        //
        //     +0                    new init_array (8 * (1+N))
        //     +init_array_end       new .rela.dyn (24 * (orig + N))
        //
        // .upobf2 must be writable so ld.so can apply
        // R_X86_64_RELATIVE relocations onto the init_array slots
        // before invoking them.
        let stub_bytes = self.stub.as_deref().unwrap_or(&[]);
        let init_array_va = self.image.dynamic.as_ref()
            .and_then(|d| d.init_array);
        let init_array_size = self.image.dynamic.as_ref()
            .and_then(|d| d.init_arraysz)
            .unwrap_or(0);
        let host_init_count = (init_array_size / 8) as usize;

        // Derive the relocation table layout. We always rebuild
        // .rela.dyn end-to-end when injecting init_array so the
        // RELACOUNT prefix invariant (RELATIVE entries first) stays
        // intact.
        let new_rela_entries: Vec<RelaWrite> = if self.inject_init_array {
            collect_rela_for_init_redirect(self.image, host_init_count)?
        } else {
            Vec::new()
        };

        // Sizes of the writable trailing block (.upobf2).
        let new_init_array_bytes_len: u64 = if self.inject_init_array {
            8 * (1 + host_init_count as u64)
        } else {
            0
        };
        let new_rela_bytes_len: u64 =
            new_rela_entries.len() as u64 * RELA_ENTRY_SIZE as u64;

        // .upobf0 size: phdr reserve + stub bytes (page-aligned).
        let stub_off_in_upobf0 = PHDR_TABLE_RESERVE;
        let upobf0_size = align_up(stub_off_in_upobf0 + stub_bytes.len() as u64, PAGE_SIZE);

        let upobf0_file_off = file_cursor;
        let upobf0_vaddr = va_cursor;
        file_cursor += upobf0_size;
        va_cursor += upobf0_size;

        // .upobf2 (R+W): init_array + .rela.dyn. Only present when
        // injecting init_array.
        let init_array_off_in_upobf2: u64 = 0;
        let rela_off_in_upobf2: u64 = align_up(new_init_array_bytes_len, 8);
        let upobf2_inner_end = rela_off_in_upobf2 + new_rela_bytes_len;
        let have_upobf2 = self.inject_init_array && upobf2_inner_end > 0;
        let upobf2_size: u64 = if have_upobf2 {
            align_up(upobf2_inner_end, PAGE_SIZE)
        } else {
            0
        };
        let upobf2_file_off = file_cursor;
        let upobf2_vaddr = va_cursor;
        if have_upobf2 {
            file_cursor += upobf2_size;
            va_cursor += upobf2_size;
        }

        // .upobf1 layout: payload bytes (if any).
        let payload_bytes = self.payload.as_deref().unwrap_or(&[]);
        let upobf1_size: u64 = align_up(payload_bytes.len() as u64, PAGE_SIZE).max(PAGE_SIZE);
        let upobf1_file_off = file_cursor;
        let upobf1_vaddr = va_cursor;
        let have_upobf1 = !payload_bytes.is_empty();
        if have_upobf1 {
            file_cursor += upobf1_size;
            let _ = va_cursor + upobf1_size;
        }

        // ---- 2. Build new phdr table ------------------------------------
        // Original phdrs first, with PT_PHDR rewritten (and the LOAD
        // segment that contained it potentially expanded — we keep
        // it byte-for-byte and instead point PT_PHDR at the relocated
        // copy inside .upobf0).
        let mut new_phdrs: Vec<Elf64Phdr> = self.image.phdrs.clone();

        let final_phnum: u64 = (new_phdrs.len() as u64)
            + 1u64                                    // .upobf0
            + (have_upobf2 as u64)                    // .upobf2
            + (have_upobf1 as u64);                   // .upobf1
        let phdr_table_bytes = final_phnum * PHDR64_SIZE as u64;
        if phdr_table_bytes > PHDR_TABLE_RESERVE {
            bail!(
                "new phdr table {} bytes overflows reserve {} bytes — bump PHDR_TABLE_RESERVE",
                phdr_table_bytes,
                PHDR_TABLE_RESERVE
            );
        }

        // Rewrite original PT_PHDR (if present) to cover the relocated
        // table. The phdr table now lives at the *start* of .upobf0,
        // which is at upobf0_vaddr / upobf0_file_off.
        for p in new_phdrs.iter_mut() {
            if p.p_type == PT_PHDR {
                p.p_offset = upobf0_file_off;
                p.p_vaddr = upobf0_vaddr;
                p.p_paddr = upobf0_vaddr;
                p.p_filesz = phdr_table_bytes;
                p.p_memsz = phdr_table_bytes;
                p.p_align = 8;
            }
        }

        // Append PT_LOAD .upobf0 (R+X)
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

        // Append PT_LOAD .upobf2 (R+W) if present
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

        // Append PT_LOAD .upobf1 (if any). Note `p_filesz == p_memsz`
        // == upobf1_size so the kernel can mmap the full segment in
        // one shot — small unaligned `p_filesz` (especially when
        // `p_filesz` < a page) trips the kernel's ELF loader on
        // some configurations and fails the entire execve with
        // EFAULT.
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

        // ---- 3. Materialise output buffer -------------------------------
        let mut out = vec![0u8; file_cursor as usize];
        out[..raw.len()].copy_from_slice(raw);

        // Zero out compressed ranges in the host portion. The kernel
        // maps zero pages at those vaddrs at run time; the stub
        // mprotect(RW) -> writes decompressed bytes -> restores
        // original protection. We translate vaddr ranges to file
        // offsets via the original image's PT_LOAD walk.
        for (vaddr, len) in &self.compressed_ranges {
            if *len == 0 {
                continue;
            }
            let file_off = self
                .image
                .vaddr_to_file_offset(*vaddr)
                .with_context(|| {
                    format!("compressed range vaddr {:#x} -> file off", vaddr)
                })?;
            let end = (file_off + len) as usize;
            if end > raw.len() {
                bail!(
                    "compressed range past EOF: file 0x{:X}+0x{:X} > 0x{:X}",
                    file_off, len, raw.len()
                );
            }
            for b in &mut out[file_off as usize..end] {
                *b = 0;
            }
        }

        // Write the new phdr table into .upobf0 head.
        write_phdr_table(
            &mut out,
            upobf0_file_off as usize,
            &new_phdrs,
        )?;

        // Stub bytes follow the phdr reserve.
        if !stub_bytes.is_empty() {
            let stub_off = (upobf0_file_off + stub_off_in_upobf0) as usize;
            out[stub_off..stub_off + stub_bytes.len()].copy_from_slice(stub_bytes);
        }

        // Compute final vaddrs for the new init_array / .rela.dyn
        // (they live in .upobf2 when injection is enabled).
        let new_init_array_vaddr = upobf2_vaddr + init_array_off_in_upobf2;
        let new_rela_vaddr = upobf2_vaddr + rela_off_in_upobf2;

        // Build init_array bytes now that we know the slot 0 vaddr.
        if self.inject_init_array {
            let stub_init_va: u64 = upobf0_vaddr + PHDR_TABLE_RESERVE + self.stub_init_offset;
            let off = (upobf2_file_off + init_array_off_in_upobf2) as usize;
            // Slot 0: stub init function VA. (ld.so will apply
            // R_X86_64_RELATIVE on top via the new .rela.dyn entry
            // we emit below — value in file == link-time addr; ld.so
            // adds load slide.)
            out[off..off + 8].copy_from_slice(&stub_init_va.to_le_bytes());
            // Slots 1..=N: copy original .init_array entries verbatim.
            if let Some(init_va) = init_array_va {
                let src_off = self.image.vaddr_to_file_offset(init_va)
                    .context("DT_INIT_ARRAY -> file offset")? as usize;
                let copy_len = init_array_size as usize;
                if src_off + copy_len > raw.len() {
                    bail!(
                        ".init_array past EOF: {:#x}+{:#x} > {:#x}",
                        src_off,
                        copy_len,
                        raw.len()
                    );
                }
                out[off + 8..off + 8 + copy_len]
                    .copy_from_slice(&raw[src_off..src_off + copy_len]);
            }
        }

        // ---- 4. Materialise the new .rela.dyn ---------------------------
        if self.inject_init_array && !new_rela_entries.is_empty() {
            let off = (upobf2_file_off + rela_off_in_upobf2) as usize;
            for (i, e) in new_rela_entries.iter().enumerate() {
                let entry_off = off + i * RELA_ENTRY_SIZE;
                // For our newly-introduced stub-init RELATIVE entry
                // we have to fill the r_offset (vaddr of slot 0)
                // and r_addend (link-time stub init VA) here, since
                // the layout vaddrs were unknown when collect_*
                // ran.
                let (r_offset, r_addend) = if e.is_stub_slot {
                    let stub_init_va =
                        upobf0_vaddr + PHDR_TABLE_RESERVE + self.stub_init_offset;
                    (new_init_array_vaddr, stub_init_va as i64)
                } else if e.is_old_init_slot {
                    // Rewrite r_offset from old init_array slot to
                    // the new slot. We slot index is encoded in
                    // r_addend_extra so we can compute new vaddr.
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

        // Payload bytes go into .upobf1.
        if have_upobf1 {
            let off = upobf1_file_off as usize;
            out[off..off + payload_bytes.len()].copy_from_slice(payload_bytes);
        }

        // ---- 5. Patch ELF header ----------------------------------------
        // e_phoff -> upobf0_file_off
        LittleEndian::write_u64(&mut out[0x20..0x28], upobf0_file_off);
        LittleEndian::write_u16(&mut out[0x38..0x3A], final_phnum as u16);

        // Phase I: e_entry redirect. The ELF header's e_entry field
        // (at offset 0x18, 8 bytes) is rewritten so the kernel
        // transfers control to the stub's trampoline first. The
        // trampoline runs `upobf_stub_init` (decompresses
        // .text + everything else) then jumps to the host's
        // original entry point.
        if let Some(tramp_off) = self.entry_trampoline_offset {
            let tramp_va = upobf0_vaddr + PHDR_TABLE_RESERVE + tramp_off;
            LittleEndian::write_u64(&mut out[0x18..0x20], tramp_va);
        }

        // ---- 6. Patch .dynamic -----------------------------------------
        if self.inject_init_array {
            patch_dynamic(
                &mut out,
                self.image,
                new_init_array_vaddr,
                8 * (1 + host_init_count as u64),
                new_rela_vaddr,
                new_rela_bytes_len,
                count_relative_prefix(&new_rela_entries) as u64,
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
/// place to point at the new arrays.
fn patch_dynamic(
    out: &mut [u8],
    image: &crate::ElfImage,
    new_init_va: u64,
    new_init_sz: u64,
    new_rela_va: u64,
    new_rela_sz: u64,
    new_relacount: u64,
) -> Result<()> {
    use crate::parse::dynamic::{
        DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_RELA, DT_RELACOUNT, DT_RELASZ, DT_ENTRY_SIZE,
    };

    let dyn_info = image
        .dynamic
        .as_ref()
        .ok_or_else(|| anyhow!("dynamic patch requires PT_DYNAMIC"))?;

    let base_off = dyn_info.file_offset as usize;
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
    fn phdr_reserve_holds_eighteen_entries() {
        // 18 phdrs * 56 bytes == 1008 < 1024.
        assert!(18 * PHDR64_SIZE as u64 <= PHDR_TABLE_RESERVE);
        // 19 phdrs would not fit.
        assert!(19 * PHDR64_SIZE as u64 > PHDR_TABLE_RESERVE);
    }
}
