//! Final PE writer (M4).
//!
//! Takes a parsed `PeImage`, a linked stub blob, and an opaque payload
//! and produces a new packed PE on disk.
//!
//! # Layout strategy
//!
//! Original sections keep their **virtual** layout (RVAs and VirtualSize)
//! exactly. Sections we decided to compress get `SizeOfRawData = 0` and
//! `PointerToRawData = 0`; the OS Loader maps them as zero-filled and
//! the stub writes back the decompressed contents during its TLS
//! callback. This is the same trick UPX uses for `UPX0`.
//!
//! Sections we keep verbatim (`.pdata`, `.rsrc`, `.reloc`, etc.) keep
//! their RVAs and contents but their `PointerToRawData` is recomputed
//! to pack tightly in the new file.
//!
//! Three or four new sections are appended:
//!
//! - `.upobf0` — RX, contains the linked stub bytes plus the new TLS
//!   directory and callback array.
//! - `.upobf1` — R, contains the encrypted payload blob.
//! - `.idata2` — R, contains the new IMAGE_IMPORT_DESCRIPTOR table.
//! - `.reloc2` — R/D (only if the stub has 8-byte ADDR64 fixups), a
//!   merged relocation table covering both the original `.reloc` and
//!   the stub's new ADDR64 sites.

use anyhow::{anyhow, bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};

use upobf_core::stub_link::{FixupTarget, LinkedStub};

use crate::parse::data_dir::{
    DataDirectory, IDX_BASERELOC, IDX_EXCEPTION, IDX_IAT, IDX_IMPORT, IDX_LOADCONFIG,
    IDX_RESOURCE, IDX_TLS,
};
use crate::parse::PeImage;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SECTION_HEADER_SIZE: usize = 40;

// IMAGE_SCN_*
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

// IMAGE_REL_BASED_*
const IMAGE_REL_BASED_DIR64: u16 = 10;

// PE protect codes (mirror `ChunkEntry.original_protect` used by stub).
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// One half-open range of host-image bytes that the packer absorbed
/// into the payload blob. Used for sub-section compression: a single
/// `.rdata` section may contribute several disjoint compressed runs
/// (one per "safe" page span) while keeping the rest of its raw
/// bytes verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedRange {
    pub rva: u32,
    pub len: u32,
}

impl CompressedRange {
    pub fn new(rva: u32, len: u32) -> Self {
        Self { rva, len }
    }
    pub fn end(&self) -> u32 {
        self.rva.saturating_add(self.len)
    }
}

/// Builder that owns the inputs and emits a final packed PE.
#[derive(Debug)]
pub struct PackedPeBuilder<'a> {
    pub original: &'a PeImage,
    pub stub: LinkedStub,
    pub payload_bytes: Vec<u8>,
    pub extra_imports: Vec<(String, Vec<String>)>,
    /// Half-open RVA ranges that were absorbed into the payload (so
    /// their on-disk bytes can be dropped from the packed image).
    /// Phase E grew this from `Vec<u32>` to support sub-section
    /// compression: a `.rdata` section may contribute several
    /// disjoint chunks while keeping its forbidden pages (Import
    /// table, IAT, LoadConfig, etc.) intact.
    pub compressed_ranges: Vec<CompressedRange>,
    /// Per-build polymorphic section names for the three appended
    /// sections (stub text / payload / aux reloc). All callers should
    /// override these via [`PackedPeBuilder::set_section_names`]; the
    /// defaults below are kept ONLY so old tests keep compiling and
    /// they will be flagged by every signature DB on the planet.
    pub stub_section_name: [u8; 8],
    pub payload_section_name: [u8; 8],
    pub reloc_section_name: [u8; 8],
    /// If `Some`, the packer will overwrite the host's
    /// `FileHeader.TimeDateStamp` with this value.
    pub override_timedate_stamp: Option<u32>,
    /// If `Some`, the packer will overwrite the host's
    /// `OptionalHeader.MajorLinkerVersion / MinorLinkerVersion` with
    /// this `(major, minor)` pair.
    pub override_linker_version: Option<(u8, u8)>,
    /// If true, the packer will zero out the Rich Header block (the
    /// MS-toolchain build fingerprint that lives between the DOS stub
    /// and the NT headers).
    pub strip_rich_header: bool,
}

impl<'a> PackedPeBuilder<'a> {
    pub fn new(original: &'a PeImage, stub: LinkedStub, payload_bytes: Vec<u8>) -> Self {
        Self {
            original,
            stub,
            payload_bytes,
            extra_imports: Vec::new(),
            compressed_ranges: Vec::new(),
            stub_section_name: pad_name(b".upobf0"),
            payload_section_name: pad_name(b".upobf1"),
            reloc_section_name: pad_name(b".reloc2"),
            override_timedate_stamp: None,
            override_linker_version: None,
            strip_rich_header: false,
        }
    }

    pub fn add_import(&mut self, dll: impl Into<String>, fns: &[&str]) {
        self.extra_imports
            .push((dll.into(), fns.iter().map(|s| s.to_string()).collect()));
    }

    /// Mark an entire host section as absorbed into the payload.
    /// `len` is the number of contiguous bytes starting at `rva` to
    /// drop from the packed image; the typical caller passes the
    /// section's raw size so the section becomes zero-on-disk and
    /// the stub re-injects the bytes at runtime.
    pub fn mark_compressed_range(&mut self, rva: u32, len: u32) {
        if len > 0 {
            self.compressed_ranges
                .push(CompressedRange::new(rva, len));
        }
    }

    /// Backwards-compatible shim: marks the entire VirtualSize of the
    /// section that begins at `rva`. Used by tests and by callers
    /// that haven't migrated to per-range bookkeeping yet.
    pub fn mark_compressed_rva(&mut self, rva: u32) {
        if let Some(sec) = self.original.sections.iter().find(|s| s.virtual_address == rva) {
            let len = sec.virtual_size.min(sec.size_of_raw_data);
            self.mark_compressed_range(rva, len);
        }
    }

    /// Override the three appended-section names. Callers should pass
    /// per-build polymorphic names; see
    /// `upobf_core::obfuscate::section_names::pick_three`.
    pub fn set_section_names(
        &mut self,
        stub_name: [u8; 8],
        payload_name: [u8; 8],
        reloc_name: [u8; 8],
    ) {
        self.stub_section_name = stub_name;
        self.payload_section_name = payload_name;
        self.reloc_section_name = reloc_name;
    }

    /// Overwrite `FileHeader.TimeDateStamp` in the packed file.
    pub fn set_timedate_stamp(&mut self, ts: u32) {
        self.override_timedate_stamp = Some(ts);
    }

    /// Overwrite `OptionalHeader.{Major,Minor}LinkerVersion`.
    pub fn set_linker_version(&mut self, major: u8, minor: u8) {
        self.override_linker_version = Some((major, minor));
    }

    /// Zero out the Rich Header block (the MS-toolchain build
    /// fingerprint between DOS stub and NT headers).
    pub fn enable_strip_rich_header(&mut self, on: bool) {
        self.strip_rich_header = on;
    }

    pub fn build(self) -> Result<Vec<u8>> {
        BuildJob::run(self)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Translate `IMAGE_SCN_*` section characteristics to a Win32 protect
/// value matching what `VirtualProtect` accepts.
pub fn section_protect_for_chars(c: u32) -> u32 {
    let exec = c & IMAGE_SCN_MEM_EXECUTE != 0;
    let read = c & IMAGE_SCN_MEM_READ != 0;
    let write = c & 0x8000_0000 != 0; // IMAGE_SCN_MEM_WRITE
    match (exec, read, write) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, true, false) => PAGE_EXECUTE_READ,
        (true, false, false) => PAGE_EXECUTE,
        (false, true, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_READONLY,
        _ => PAGE_NOACCESS,
    }
}

fn align_up(v: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (v + align - 1) & !(align - 1)
}

fn pad_name(s: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    let n = s.len().min(8);
    out[..n].copy_from_slice(&s[..n]);
    out
}

fn write_data_directory(buf: &mut [u8], d: DataDirectory) {
    debug_assert_eq!(buf.len(), 8);
    LittleEndian::write_u32(&mut buf[0..4], d.virtual_address);
    LittleEndian::write_u32(&mut buf[4..8], d.size);
}

// ---------------------------------------------------------------------------
// Build job
// ---------------------------------------------------------------------------

/// One section as it will appear in the packed image. May reference the
/// original raw bytes (`OriginalRaw`) or own freshly-built bytes.
#[derive(Debug)]
struct PlannedSection {
    name: [u8; 8],
    virtual_address: u32,
    virtual_size: u32,
    characteristics: u32,
    /// Raw bytes to write to disk. Empty => `SizeOfRawData = 0`.
    raw: Vec<u8>,
    /// File offset (computed during `assign_offsets`).
    pointer_to_raw_data: u32,
    /// SizeOfRawData (= align_up(raw.len(), file_alignment) or 0).
    size_of_raw_data: u32,
}

struct BuildJob<'a> {
    builder: PackedPeBuilder<'a>,
    section_alignment: u32,
    file_alignment: u32,
    image_base: u64,

    /// Sections in final order: original first, then new ones appended.
    sections: Vec<PlannedSection>,
    /// Index in `sections` for the new `.upobf0`.
    upobf0_idx: usize,
    /// Index in `sections` for the new `.upobf1`.
    upobf1_idx: usize,
    /// Index in `sections` for the new `.idata2`.
    idata2_idx: usize,
    /// Optional `.reloc2`.
    reloc2_idx: Option<usize>,

    /// `__imp_<name>` -> RVA of its IAT slot.
    imp_thunk_rvas: std::collections::BTreeMap<String, u32>,

    /// RVA of the *real* stub TLS callback C function
    /// (= upobf0_rva + linked.tls_callback_offset).
    /// This is what gets written into the `__upobf_stub_self_rva`
    /// fixup so the stub can recover ImageBase from `&self - rva`.
    stub_callback_rva: u32,
    /// RVA of the stub entry point that the OS Loader actually
    /// invokes (= upobf0_rva + linked.entry_offset).
    /// Equals `stub_callback_rva` when no post-link polymorphism is
    /// applied; otherwise points at the trampoline that jumps into
    /// the real callback.
    stub_entry_rva: u32,
    /// RVA of new TLS Directory in `.upobf0`.
    new_tls_dir_rva: u32,

    new_reloc: Option<(u32, u32)>,
    /// RVA of the original TLS callback slot that we patched in place
    /// (so .reloc2 includes the new stub_va).
    patched_callback_slot_rva: Option<u32>,
}

impl<'a> BuildJob<'a> {
    fn run(builder: PackedPeBuilder<'a>) -> Result<Vec<u8>> {
        let oh = builder.original.nt.optional_header.clone();
        let mut job = BuildJob {
            section_alignment: oh.section_alignment,
            file_alignment: oh.file_alignment,
            image_base: oh.image_base,
            builder,
            sections: Vec::new(),
            upobf0_idx: usize::MAX,
            upobf1_idx: usize::MAX,
            idata2_idx: usize::MAX,
            reloc2_idx: None,
            imp_thunk_rvas: std::collections::BTreeMap::new(),
            stub_callback_rva: 0,
            stub_entry_rva: 0,
            new_tls_dir_rva: 0,
            new_reloc: None,
            patched_callback_slot_rva: None,
        };
        job.plan_original_sections()?;
        job.plan_new_sections()?;
        job.assign_offsets()?;
        // Step: build .idata2 and .upobf0 contents now that all RVAs known.
        job.materialize_idata2()?;
        job.materialize_upobf0()?;
        // Patch the original TLS callback array to inject our stub.
        job.patch_original_tls_callback_array()?;
        // Reloc2 depends on stub fixups + upobf0 RVA + idata2 RVA.
        job.maybe_build_reloc2()?;
        // Now apply fixups (mutates upobf0 raw bytes).
        job.apply_stub_fixups()?;
        // Assemble final file.
        job.serialize()
    }

    // ---------------------------------------------------------------
    // Planning
    // ---------------------------------------------------------------
    fn plan_original_sections(&mut self) -> Result<()> {
        let raw = &self.builder.original.raw;
        for sec in &self.builder.original.sections {
            let mut name = [0u8; 8];
            let nb = sec.name.as_bytes();
            let n = nb.len().min(8);
            name[..n].copy_from_slice(&nb[..n]);

            // Collect ranges intersecting this section.
            let sec_start = sec.virtual_address;
            let sec_end = sec_start
                .saturating_add(sec.virtual_size.max(sec.size_of_raw_data));
            let mut intersecting: Vec<CompressedRange> = self
                .builder
                .compressed_ranges
                .iter()
                .filter_map(|r| {
                    let lo = r.rva.max(sec_start);
                    let hi = r.end().min(sec_end);
                    if hi > lo {
                        Some(CompressedRange::new(lo, hi - lo))
                    } else {
                        None
                    }
                })
                .collect();
            intersecting.sort_by_key(|r| r.rva);

            // Detect "drop entire section": one range that spans
            // `[sec_start, sec_start + virtual_size)`. In that case
            // we emit zero raw bytes (UPX-style) and let the OS Loader
            // map the section as zero-filled. We compare against
            // virtual_size (not size_of_raw_data) because virtual_size
            // is the host's effective working set; size_of_raw_data
            // tends to be slightly larger due to file alignment
            // padding and that padding never holds data the host
            // reads.
            let effective = sec.virtual_size.min(sec.size_of_raw_data);
            let drop_entire = intersecting.len() == 1
                && intersecting[0].rva == sec_start
                && intersecting[0].len >= effective;

            if drop_entire {
                self.sections.push(PlannedSection {
                    name,
                    virtual_address: sec.virtual_address,
                    virtual_size: sec.virtual_size,
                    characteristics: sec.characteristics,
                    raw: Vec::new(),
                    pointer_to_raw_data: 0,
                    size_of_raw_data: 0,
                });
                continue;
            }

            if intersecting.is_empty() {
                // Verbatim copy of the original section.
                let off = sec.pointer_to_raw_data as usize;
                let len = sec.size_of_raw_data as usize;
                if off + len > raw.len() {
                    bail!(
                        "section '{}' raw range {:#x}+{} exceeds file len {}",
                        sec.name,
                        off,
                        len,
                        raw.len()
                    );
                }
                let raw_bytes = raw[off..off + len].to_vec();
                self.sections.push(PlannedSection {
                    name,
                    virtual_address: sec.virtual_address,
                    virtual_size: sec.virtual_size,
                    characteristics: sec.characteristics,
                    raw: raw_bytes,
                    pointer_to_raw_data: 0,
                    size_of_raw_data: 0,
                });
                continue;
            }

            // ----------------------------------------------------------
            // Sub-section absorption: split the host section into one
            // or more output sections so the absorbed bytes become
            // trailing zero-fill (excluded from `size_of_raw_data`).
            //
            // For an input layout like
            //   [head_orig] [absorbed_1] [middle_orig] [absorbed_2] [tail_orig]
            // we emit:
            //   Sec A: rva=head, virt_size=head_len + absorbed_1_len,
            //          raw_size=head_len, raw_bytes=head_orig
            //   Sec B: rva=middle, virt_size=middle_len + absorbed_2_len,
            //          raw_size=middle_len, raw_bytes=middle_orig
            //   Sec C: rva=tail, virt_size=tail_len, raw_size=tail_len,
            //          raw_bytes=tail_orig
            //
            // The effect: each absorbed run ends up as the trailing
            // virtual zero-fill of the preceding section, exactly the
            // mechanism the OS Loader provides for `.bss`-style
            // tails. The on-disk savings equal the sum of absorbed
            // bytes; the stub re-injects the actual content at run
            // time.
            //
            // Multiple consecutive absorbed runs (with no real bytes
            // between them) are merged into one zero-fill tail.
            // ----------------------------------------------------------
            let off = sec.pointer_to_raw_data as usize;
            let raw_len = sec.size_of_raw_data as usize;
            if off + raw_len > raw.len() {
                bail!(
                    "section '{}' raw range {:#x}+{} exceeds file len {}",
                    sec.name,
                    off,
                    raw_len,
                    raw.len()
                );
            }
            let sec_raw_bytes = &raw[off..off + raw_len];
            let initialised_end = sec_start.saturating_add(effective);

            let mut cursor = sec_start;
            let mut idx = 0usize;
            let bss_tail_len = sec
                .virtual_size
                .saturating_sub(effective);

            while idx < intersecting.len() {
                let r = intersecting[idx];

                // Skip absorbed ranges that are out-of-order or overlap;
                // the input is already sorted + non-overlapping, but be
                // defensive.
                if r.end() <= cursor {
                    idx += 1;
                    continue;
                }

                if cursor < r.rva {
                    // Emit a planned section covering the real bytes
                    // [cursor..r.rva), with trailing zero-fill of the
                    // absorbed range (and any consecutive absorbed
                    // runs that immediately follow).
                    let real_start = cursor;
                    let real_end = r.rva;
                    let mut zero_end = r.end();
                    let mut peek = idx + 1;
                    while peek < intersecting.len() && intersecting[peek].rva == zero_end {
                        zero_end = zero_end.max(intersecting[peek].end());
                        peek += 1;
                    }
                    self.push_split_section(
                        &name,
                        sec.characteristics,
                        sec_start,
                        sec_raw_bytes,
                        real_start,
                        real_end,
                        zero_end,
                        initialised_end,
                    );
                    cursor = zero_end;
                    idx = peek;
                } else {
                    // cursor sits inside or at the start of an absorbed
                    // range; just advance past it. No section emitted
                    // because it has no real bytes.
                    cursor = cursor.max(r.end());
                    idx += 1;
                }
            }

            // Trailing real bytes after the last absorbed run.
            if cursor < initialised_end {
                self.push_split_section(
                    &name,
                    sec.characteristics,
                    sec_start,
                    sec_raw_bytes,
                    cursor,
                    initialised_end,
                    initialised_end.saturating_add(bss_tail_len),
                    initialised_end,
                );
            }
            // If `cursor >= initialised_end`, the section ends with an
            // absorbed run — the previous push_split_section already
            // accounted for the zero-fill tail, but we still need a
            // final virtual zero-fill section if there was an
            // uninitialised BSS tail. We synthesise it here as a raw=0
            // section: virtual covers the BSS, no on-disk bytes.
            if bss_tail_len > 0 && cursor >= initialised_end {
                self.sections.push(PlannedSection {
                    name,
                    virtual_address: initialised_end,
                    virtual_size: bss_tail_len,
                    characteristics: sec.characteristics,
                    raw: Vec::new(),
                    pointer_to_raw_data: 0,
                    size_of_raw_data: 0,
                });
            }
        }
        Ok(())
    }

    /// Emit a split fragment: real bytes `[real_start..real_end)`
    /// drawn from the host section's raw image, with a trailing
    /// zero-fill that extends `virtual_size` to `zero_end`. Fragments
    /// with zero real-byte length are skipped.
    fn push_split_section(
        &mut self,
        name: &[u8; 8],
        characteristics: u32,
        sec_va: u32,
        sec_raw_bytes: &[u8],
        real_start: u32,
        real_end: u32,
        zero_end: u32,
        initialised_end: u32,
    ) {
        if real_end <= real_start {
            return;
        }
        let local_start = (real_start - sec_va) as usize;
        let local_end = (real_end - sec_va) as usize;
        let safe_end = local_end.min(sec_raw_bytes.len());
        if safe_end <= local_start {
            return;
        }
        let raw_bytes = sec_raw_bytes[local_start..safe_end].to_vec();
        let zero_end = zero_end.max(real_end).min(initialised_end.max(zero_end));
        let virtual_size = (zero_end - real_start).max(real_end - real_start);
        self.sections.push(PlannedSection {
            name: *name,
            virtual_address: real_start,
            virtual_size,
            characteristics,
            raw: raw_bytes,
            pointer_to_raw_data: 0,
            size_of_raw_data: 0,
        });
    }

    fn plan_new_sections(&mut self) -> Result<()> {
        // Determine first available RVA above all originals.
        let mut next_rva = self
            .sections
            .iter()
            .map(|s| {
                s.virtual_address
                    + align_up(s.virtual_size as usize, self.section_alignment as usize) as u32
            })
            .max()
            .unwrap_or(self.builder.original.nt.optional_header.size_of_headers);
        next_rva = align_up(next_rva as usize, self.section_alignment as usize) as u32;

        // ---- .upobf0: stub text only (no TLS directory rewrite). The
        // TLS Directory and callback array stay at their original RVAs;
        // we patch the existing callback array bytes (in `.rdata`) to
        // chain stub before the host's original TLS callback. This
        // avoids the headaches of rebuilding the TLS Directory entirely.
        let stub_text_len = self.builder.stub.text.len();
        let upobf0_vsize = stub_text_len as u32;
        let upobf0_rva = next_rva;
        next_rva = align_up(
            (next_rva + upobf0_vsize) as usize,
            self.section_alignment as usize,
        ) as u32;
        self.upobf0_idx = self.sections.len();
        self.sections.push(PlannedSection {
            name: self.builder.stub_section_name,
            virtual_address: upobf0_rva,
            virtual_size: upobf0_vsize,
            characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            raw: vec![0u8; upobf0_vsize as usize], // placeholder, filled in materialize
            pointer_to_raw_data: 0,
            size_of_raw_data: 0,
        });
        self.stub_callback_rva = upobf0_rva + self.builder.stub.tls_callback_offset;
        self.stub_entry_rva = upobf0_rva + self.builder.stub.entry_offset;
        // The TLS Directory does *not* move; signal that to the writer.
        self.new_tls_dir_rva = self
            .builder
            .original
            .data_dirs
            .get(IDX_TLS)
            .copied()
            .unwrap_or_default()
            .virtual_address;

        // ---- .upobf1: payload blob.
        let payload_size = self.builder.payload_bytes.len() as u32;
        let upobf1_rva = next_rva;
        next_rva = align_up(
            (next_rva + payload_size) as usize,
            self.section_alignment as usize,
        ) as u32;
        self.upobf1_idx = self.sections.len();
        self.sections.push(PlannedSection {
            name: self.builder.payload_section_name,
            virtual_address: upobf1_rva,
            virtual_size: payload_size,
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            raw: self.builder.payload_bytes.clone(),
            pointer_to_raw_data: 0,
            size_of_raw_data: 0,
        });

        // ---- .idata2: import descriptors + thunks + strings (only if
        // we actually have extra imports to add).
        if !self.builder.extra_imports.is_empty() {
            let idata2_rva = next_rva;
            let idata2_size_estimate = estimate_idata2_size(&self.builder.extra_imports);
            // Reserved for completeness; subsequent sections (.reloc2)
            // recompute their RVA dynamically.
            let _next_rva_after_idata = align_up(
                (next_rva + idata2_size_estimate) as usize,
                self.section_alignment as usize,
            ) as u32;
            self.idata2_idx = self.sections.len();
            self.sections.push(PlannedSection {
                name: pad_name(b".idata2"),
                virtual_address: idata2_rva,
                virtual_size: idata2_size_estimate,
                characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
                raw: vec![0u8; idata2_size_estimate as usize],
                pointer_to_raw_data: 0,
                size_of_raw_data: 0,
            });
        }

        // .reloc2 is sized in maybe_build_reloc2.
        let _ = upobf1_rva;
        Ok(())
    }

    fn assign_offsets(&mut self) -> Result<()> {
        // Compute SizeOfRawData and PointerToRawData for each section.
        // We start placement past the headers; the header reservation
        // grows on demand to fit a section table that exceeds the
        // host's original SizeOfHeaders. The extra reservation is
        // a single file_alignment step (typically 0x200), enough for
        // ~12 additional section headers — matches the worst case
        // when both .rdata and .data get split into two fragments
        // each on top of the existing stub / payload / reloc sections.
        let header_room = self.required_size_of_headers() as usize;
        let mut cursor = align_up(header_room, self.file_alignment as usize) as u32;
        for s in &mut self.sections {
            if s.raw.is_empty() {
                s.pointer_to_raw_data = 0;
                s.size_of_raw_data = 0;
                continue;
            }
            let size = align_up(s.raw.len(), self.file_alignment as usize) as u32;
            s.pointer_to_raw_data = cursor;
            s.size_of_raw_data = size;
            cursor += size;
        }
        Ok(())
    }

    /// Smallest SizeOfHeaders that still fits the new section table.
    /// Returns at least the host's original SizeOfHeaders so we never
    /// shrink a binary's header reservation; only grows when the new
    /// section count exceeds what the original headers had room for.
    fn required_size_of_headers(&self) -> u32 {
        let nt_off = self.builder.original.dos.e_lfanew as usize;
        let file_header_off = nt_off + 4;
        let size_of_optional_header =
            self.builder.original.nt.file_header.size_of_optional_header as usize;
        let section_table_off = file_header_off + 20 + size_of_optional_header;
        let needed = section_table_off + self.sections.len() * SECTION_HEADER_SIZE;
        let original = self.builder.original.nt.optional_header.size_of_headers as usize;
        let aligned = align_up(needed.max(original), self.file_alignment as usize);
        aligned as u32
    }

    // ---------------------------------------------------------------
    // .idata2 contents
    // ---------------------------------------------------------------
    fn materialize_idata2(&mut self) -> Result<()> {
        if self.idata2_idx == usize::MAX {
            return Ok(());
        }
        let idata2_rva = self.sections[self.idata2_idx].virtual_address;

        // Original Import Table: copy descriptors verbatim (excluding NULL
        // terminator), then append our new ones.
        let original_imp_dir = self.builder.original.data_dirs[IDX_IMPORT];
        let mut original_descs_real: Vec<u8> = Vec::new();
        if original_imp_dir.is_present() {
            let off = self
                .builder
                .original
                .rva_to_file_offset(original_imp_dir.virtual_address)
                .context("original Import Table file offset")?;
            let raw = &self.builder.original.raw;
            let mut cur = off;
            loop {
                if cur + 20 > raw.len() {
                    bail!("original Import Table truncated");
                }
                let chunk = &raw[cur..cur + 20];
                if chunk.iter().all(|&b| b == 0) {
                    break;
                }
                original_descs_real.extend_from_slice(chunk);
                cur += 20;
            }
        }
        let original_real_count = original_descs_real.len() / 20;

        let new_dlls: Vec<&(String, Vec<String>)> = self.builder.extra_imports.iter().collect();
        let new_count = new_dlls.len();
        let total_descs = original_real_count + new_count + 1;
        let desc_table_size = total_descs * 20;

        // Build strings region.
        let strings_off = desc_table_size;
        let mut strings = Vec::<u8>::new();
        let mut dll_name_off: Vec<usize> = Vec::with_capacity(new_count);
        let mut iibn_off: Vec<Vec<usize>> = Vec::with_capacity(new_count);
        for (dll, fns) in &new_dlls {
            while strings.len() % 2 != 0 {
                strings.push(0);
            }
            let off = strings_off + strings.len();
            strings.extend_from_slice(dll.as_bytes());
            strings.push(0);
            dll_name_off.push(off);

            let mut row = Vec::with_capacity(fns.len());
            for f in fns.iter() {
                while strings.len() % 2 != 0 {
                    strings.push(0);
                }
                let off = strings_off + strings.len();
                row.push(off);
                strings.extend_from_slice(&[0u8, 0u8]); // hint
                strings.extend_from_slice(f.as_bytes());
                strings.push(0);
            }
            iibn_off.push(row);
        }

        // Pad to 8-byte alignment for thunk arrays.
        while (strings_off + strings.len()) % 8 != 0 {
            strings.push(0);
        }

        let iat_off = strings_off + strings.len();
        let total_thunks: usize = new_dlls.iter().map(|(_, fns)| fns.len() + 1).sum();
        let iat_size = total_thunks * 8;
        let int_off = iat_off + iat_size;
        let int_size = total_thunks * 8;
        let total = int_off + int_size;

        let mut buf = vec![0u8; total];

        // Copy original descriptors.
        if original_real_count > 0 {
            buf[..original_descs_real.len()].copy_from_slice(&original_descs_real);
        }

        // Write new descriptors + thunks.
        let mut cursor = 0usize;
        for (i, (_, fns)) in new_dlls.iter().enumerate() {
            let count = fns.len() + 1;
            let iat_rva = idata2_rva + (iat_off + cursor * 8) as u32;
            let int_rva = idata2_rva + (int_off + cursor * 8) as u32;
            let dll_name_rva = idata2_rva + dll_name_off[i] as u32;

            let desc_off = (original_real_count + i) * 20;
            let desc = &mut buf[desc_off..desc_off + 20];
            LittleEndian::write_u32(&mut desc[0..4], int_rva);
            LittleEndian::write_u32(&mut desc[4..8], 0);
            LittleEndian::write_u32(&mut desc[8..12], 0);
            LittleEndian::write_u32(&mut desc[12..16], dll_name_rva);
            LittleEndian::write_u32(&mut desc[16..20], iat_rva);

            for (j, fname) in fns.iter().enumerate() {
                let iat_slot = iat_off + (cursor + j) * 8;
                let int_slot = int_off + (cursor + j) * 8;
                let iibn_rva: u64 = idata2_rva as u64 + iibn_off[i][j] as u64;
                LittleEndian::write_u64(&mut buf[int_slot..int_slot + 8], iibn_rva);
                LittleEndian::write_u64(&mut buf[iat_slot..iat_slot + 8], iibn_rva);
                let imp_rva = idata2_rva + iat_slot as u32;
                self.imp_thunk_rvas.insert(fname.clone(), imp_rva);
            }
            cursor += count;
        }

        // Strings region.
        buf[strings_off..strings_off + strings.len()].copy_from_slice(&strings);

        // If our estimate was generous, we may have allocated more
        // virtual size than needed. Resize the section's raw to the
        // exact computed `total`; the section header VirtualSize will
        // reflect that.
        let sec = &mut self.sections[self.idata2_idx];
        sec.raw = buf;
        sec.virtual_size = total as u32;
        Ok(())
    }

    // ---------------------------------------------------------------
    // .upobf0 contents
    // ---------------------------------------------------------------
    fn materialize_upobf0(&mut self) -> Result<()> {
        // Stub text only. The TLS Directory and callback array stay at
        // their original .rdata location; we patch the existing callback
        // array in place (see `patch_original_tls_callback_array`).
        let buf = self.builder.stub.text.clone();
        let sec = &mut self.sections[self.upobf0_idx];
        sec.raw = buf;
        sec.virtual_size = sec.raw.len() as u32;
        Ok(())
    }

    /// Patch the host's original TLS callback array in `.rdata` so the
    /// stub runs first, followed by the host's original first callback,
    /// followed by NULL. The original layout is `[orig_cb, NULL]` with
    /// at least one slot of trailing zero padding (verified at parse
    /// time by reading the next 8 bytes), giving us room to insert the
    /// stub callback.
    fn patch_original_tls_callback_array(&mut self) -> Result<()> {
        let tls = match &self.builder.original.tls {
            Some(t) => t,
            None => return Ok(()), // no TLS in original; nothing to patch
        };
        if tls.callbacks_va == 0 {
            return Ok(());
        }

        // Compute file offset of the callback array.
        let cb_array_rva =
            (tls.callbacks_va - self.image_base) as u32;

        // Find the section containing this RVA (in our planned section
        // list — they keep the same RVAs as the originals).
        let target_sec = self
            .sections
            .iter()
            .find(|s| {
                let end = s.virtual_address + s.virtual_size;
                cb_array_rva >= s.virtual_address && cb_array_rva < end
            })
            .ok_or_else(|| {
                anyhow!(
                    "TLS callback array RVA {:#x} not in any planned section",
                    cb_array_rva
                )
            })?;
        // The section is owned (not raw bytes from `original.raw`); we
        // clone the planned section's raw and patch it.
        let sec_idx = self
            .sections
            .iter()
            .position(|s| s.virtual_address == target_sec.virtual_address)
            .unwrap();
        let sec = &mut self.sections[sec_idx];
        let off_in_sec = (cb_array_rva - sec.virtual_address) as usize;
        if off_in_sec + 24 > sec.raw.len() {
            bail!(
                "TLS callback array at {:#x} doesn't fit in section '{}' raw bytes",
                cb_array_rva,
                std::str::from_utf8(&sec.name).unwrap_or("?")
            );
        }

        // Verify the original layout: callback[0] = orig, callback[1] = 0.
        let cb0 = LittleEndian::read_u64(&sec.raw[off_in_sec..off_in_sec + 8]);
        let cb1 = LittleEndian::read_u64(&sec.raw[off_in_sec + 8..off_in_sec + 16]);
        // We need at least 24 bytes of room for the new [stub, orig, NULL].
        // cb1 must be NULL (the original terminator); cb2 (slot we'll
        // overwrite as new NULL) must already be zero too.
        let cb2 = LittleEndian::read_u64(&sec.raw[off_in_sec + 16..off_in_sec + 24]);
        if cb1 != 0 || cb2 != 0 {
            bail!(
                "original TLS callback array has > 1 entry (cb1={:#x}, cb2={:#x}); chained injection unsupported",
                cb1, cb1
            );
        }

        // Layout: [stub_entry_va, orig_cb_va, NULL]
        // We register the *entry* (potentially a polymorphic
        // trampoline) — not the real C callback — as the first TLS
        // callback. The trampoline tail-jumps into the real callback,
        // so the OS Loader sees identical control flow. The stub still
        // recovers ImageBase via `__upobf_stub_self_rva`, which the
        // packer fills with `stub_callback_rva` (the real callback's
        // RVA) so that subtraction inside the C function is correct.
        let stub_entry_va = self.image_base + self.stub_entry_rva as u64;
        LittleEndian::write_u64(&mut sec.raw[off_in_sec..off_in_sec + 8], stub_entry_va);
        LittleEndian::write_u64(&mut sec.raw[off_in_sec + 8..off_in_sec + 16], cb0);
        LittleEndian::write_u64(&mut sec.raw[off_in_sec + 16..off_in_sec + 24], 0);

        // Record this site so we add an ASLR relocation for the stub_va.
        self.patched_callback_slot_rva = Some(cb_array_rva);
        Ok(())
    }

    // ---------------------------------------------------------------
    // .reloc2 (optional)
    // ---------------------------------------------------------------
    fn maybe_build_reloc2(&mut self) -> Result<()> {
        let upobf0_rva = self.sections[self.upobf0_idx].virtual_address;
        let mut new_addr64: Vec<u32> = Vec::new();
        for f in &self.builder.stub.abs_fixups {
            if f.width == 8 {
                // Skip StubSelfRva: the slot is 8 bytes but only the low
                // 32 bits are meaningful and they are not relocatable.
                if matches!(f.target, FixupTarget::StubSelfRva) {
                    continue;
                }
                new_addr64.push(upobf0_rva + f.offset);
            }
        }
        // Stub VA we wrote into the patched original callback array.
        // This 8-byte slot lives in the original .rdata (or wherever
        // the host kept it) and must be rebased under ASLR.
        if let Some(rva) = self.patched_callback_slot_rva {
            new_addr64.push(rva);
        }

        if new_addr64.is_empty() {
            return Ok(());
        }
        // Always emit .reloc2 once we have any new ADDR64 sites.

        // Read original .reloc bytes if present.
        let mut bytes = Vec::new();
        let dir = self.builder.original.data_dirs[IDX_BASERELOC];
        if dir.is_present() {
            let off = self
                .builder
                .original
                .rva_to_file_offset(dir.virtual_address)
                .context("original .reloc offset")?;
            if off + dir.size as usize > self.builder.original.raw.len() {
                bail!("original .reloc dir exceeds file");
            }
            bytes.extend_from_slice(&self.builder.original.raw[off..off + dir.size as usize]);
        }

        // Group new RVAs by 4 KiB page and append blocks.
        let mut new_pages: std::collections::BTreeMap<u32, Vec<u16>> = Default::default();
        for r in new_addr64 {
            let page = r & !0xFFF;
            let off = (r & 0xFFF) as u16;
            let entry = (IMAGE_REL_BASED_DIR64 << 12) | off;
            new_pages.entry(page).or_default().push(entry);
        }
        for (page, entries) in new_pages {
            let mut padded = entries;
            if padded.len() % 2 != 0 {
                padded.push(0);
            }
            let block_size = 8 + padded.len() * 2;
            let mut block = vec![0u8; block_size];
            LittleEndian::write_u32(&mut block[0..4], page);
            LittleEndian::write_u32(&mut block[4..8], block_size as u32);
            for (i, e) in padded.iter().enumerate() {
                LittleEndian::write_u16(&mut block[8 + i * 2..8 + i * 2 + 2], *e);
            }
            bytes.extend_from_slice(&block);
        }

        let next_rva = self
            .sections
            .iter()
            .map(|s| {
                s.virtual_address
                    + align_up(s.virtual_size as usize, self.section_alignment as usize) as u32
            })
            .max()
            .unwrap();
        let reloc2_rva = align_up(next_rva as usize, self.section_alignment as usize) as u32;

        self.reloc2_idx = Some(self.sections.len());
        self.sections.push(PlannedSection {
            name: self.builder.reloc_section_name,
            virtual_address: reloc2_rva,
            virtual_size: bytes.len() as u32,
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_DISCARDABLE,
            raw: bytes.clone(),
            pointer_to_raw_data: 0,
            size_of_raw_data: 0,
        });
        self.new_reloc = Some((reloc2_rva, bytes.len() as u32));

        // Recompute file offsets now that we have a new section.
        self.assign_offsets()?;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Apply stub fixups (mutates upobf0 raw bytes).
    // ---------------------------------------------------------------
    fn apply_stub_fixups(&mut self) -> Result<()> {
        let upobf0_rva = self.sections[self.upobf0_idx].virtual_address;
        let upobf1_rva = self.sections[self.upobf1_idx].virtual_address;
        let payload_va = self.image_base + upobf1_rva as u64;
        let original_oep_va: u64 = self.image_base
            + self.builder.original.nt.optional_header.address_of_entry_point as u64;
        let original_first_callback_va: u64 = self
            .builder
            .original
            .tls
            .as_ref()
            .and_then(|tls| tls.callbacks.first().copied())
            .map(|rva| self.image_base + rva as u64)
            .unwrap_or(0);

        let imp_thunk_rvas = self.imp_thunk_rvas.clone();
        let image_base = self.image_base;
        let stub_callback_rva = self.stub_callback_rva;
        let stub_base_va = image_base + upobf0_rva as u64;
        let fixups = self.builder.stub.abs_fixups.clone();
        let imp_sites = self.builder.stub.imp_rel32_sites.clone();

        // Build a fallback map: for each API the stub references via
        // __imp_*, look up an existing IAT slot for the same name in
        // the host's original Import Table. This way M4 can run with
        // no `extra_imports` (skipping the .idata2 rewrite) when the
        // original PE already imports all the APIs we need.
        let mut all_imp_rvas = imp_thunk_rvas.clone();
        for site in &imp_sites {
            if all_imp_rvas.contains_key(&site.api_name) {
                continue;
            }
            // Search the host's existing imports for a thunk to the
            // same function name.
            let mut found: Option<u32> = None;
            for dll in &self.builder.original.imports.dlls {
                let mut idx = 0usize;
                for func in &dll.functions {
                    if func.by_ordinal {
                        idx += 1;
                        continue;
                    }
                    if func.name.as_deref() == Some(site.api_name.as_str()) {
                        // The IAT thunk array is at FirstThunk_RVA;
                        // function `idx` corresponds to FirstThunk + idx*8.
                        let iat_rva = dll.first_thunk_rva + (idx as u32) * 8;
                        found = Some(iat_rva);
                        break;
                    }
                    idx += 1;
                }
                if found.is_some() {
                    break;
                }
            }
            let iat_rva = found.ok_or_else(|| {
                anyhow!(
                    "stub needs `{}` but no extra import descriptor was \
                     added and the host doesn't import it",
                    site.api_name
                )
            })?;
            all_imp_rvas.insert(site.api_name.clone(), iat_rva);
        }
        let imp_thunk_rvas = all_imp_rvas;

        let upobf0 = &mut self.sections[self.upobf0_idx];

        // Apply __imp_* REL32 patches: each site's `call qword ptr
        // [rip+disp]` must point at the IAT slot in .idata2.
        for site in imp_sites {
            let iat_rva = imp_thunk_rvas
                .get(&site.api_name)
                .copied()
                .ok_or_else(|| anyhow!("no IAT thunk for `{}`", site.api_name))?;
            // Site VA after the 4 displacement bytes the CPU consumes.
            let site_va = stub_base_va + site.offset as u64 + 4;
            let target_va = image_base + iat_rva as u64;
            let disp =
                (target_va as i64 - site_va as i64) + site.addend as i64;
            if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                bail!(
                    "REL32 to __imp_{} out of range ({})",
                    site.api_name,
                    disp
                );
            }
            let off = site.offset as usize;
            LittleEndian::write_i32(&mut upobf0.raw[off..off + 4], disp as i32);
        }

        for f in fixups {
            let value: u64 = match &f.target {
                FixupTarget::OriginalOep => original_oep_va,
                FixupTarget::OriginalTlsCallback => original_first_callback_va,
                FixupTarget::PayloadBlobVa => payload_va,
                FixupTarget::StubSelfRva => stub_callback_rva as u64,
                FixupTarget::ImportThunk(name) => {
                    let rva = imp_thunk_rvas
                        .get(name)
                        .copied()
                        .ok_or_else(|| anyhow!("no IAT thunk for `{}`", name))?;
                    image_base + rva as u64
                }
                FixupTarget::LocalSymbol(_) => stub_base_va,
            };
            let site = f.offset as usize;
            match f.width {
                4 => {
                    if value > u32::MAX as u64 {
                        bail!("fixup target {:#x} > 32 bits", value);
                    }
                    LittleEndian::write_u32(&mut upobf0.raw[site..site + 4], value as u32);
                }
                8 => {
                    let pre = LittleEndian::read_i64(&upobf0.raw[site..site + 8]);
                    let final_v = match &f.target {
                        FixupTarget::LocalSymbol(_) => {
                            (pre as i128 + stub_base_va as i128) as u64
                        }
                        _ => value,
                    };
                    LittleEndian::write_u64(&mut upobf0.raw[site..site + 8], final_v);
                }
                w => bail!("unexpected fixup width {}", w),
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------
    // Final serialization.
    // ---------------------------------------------------------------
    fn serialize(&self) -> Result<Vec<u8>> {
        let total_size: u32 = self
            .sections
            .iter()
            .map(|s| s.pointer_to_raw_data + s.size_of_raw_data)
            .max()
            .unwrap_or(self.builder.original.nt.optional_header.size_of_headers);

        let mut out = vec![0u8; total_size as usize];

        // Copy original headers unchanged. The new header reservation
        // may be larger than the host's original SizeOfHeaders if the
        // section count exceeded the original header capacity; the
        // extra bytes are left zero-initialised here and the section
        // table is rewritten in `rewrite_headers` below.
        let original_room = self.builder.original.nt.optional_header.size_of_headers as usize;
        let new_room = self.required_size_of_headers() as usize;
        out[..original_room].copy_from_slice(&self.builder.original.raw[..original_room]);
        // Bytes [original_room .. new_room) stay zero — the section
        // table writer will populate the entries that live there.
        let _ = new_room;

        // Write each section's raw bytes.
        for s in &self.sections {
            if s.size_of_raw_data == 0 {
                continue;
            }
            let off = s.pointer_to_raw_data as usize;
            let len = s.raw.len();
            out[off..off + len].copy_from_slice(&s.raw);
            // Tail to size_of_raw_data is already 0.
        }

        // Rewrite headers in `out`.
        self.rewrite_headers(&mut out)?;

        Ok(out)
    }

    fn rewrite_headers(&self, out: &mut [u8]) -> Result<()> {
        let nt_off = self.builder.original.dos.e_lfanew as usize;
        let file_header_off = nt_off + 4;
        let optional_header_off = file_header_off + 20;
        let dd_off = optional_header_off + 112;
        let size_of_optional_header =
            self.builder.original.nt.file_header.size_of_optional_header as usize;
        let section_table_off = file_header_off + 20 + size_of_optional_header;

        let new_section_count = self.sections.len();
        let new_size_of_headers = self.required_size_of_headers() as usize;
        let needed = section_table_off + new_section_count * SECTION_HEADER_SIZE;
        if needed > new_size_of_headers {
            bail!(
                "internal: required_size_of_headers ({:#x}) is below table end ({:#x})",
                new_size_of_headers,
                needed
            );
        }

        // OptionalHeader.SizeOfHeaders (offset +60 in the OptionalHeader,
        // PE32+ layout). Update if grew.
        LittleEndian::write_u32(
            &mut out[optional_header_off + 60..optional_header_off + 64],
            new_size_of_headers as u32,
        );

        // FileHeader.NumberOfSections
        LittleEndian::write_u16(
            &mut out[file_header_off + 2..file_header_off + 4],
            new_section_count as u16,
        );

        // OptionalHeader.SizeOfImage / SizeOfCode / SizeOfInitializedData.
        let size_of_image: u32 = self
            .sections
            .iter()
            .map(|s| {
                s.virtual_address
                    + align_up(s.virtual_size as usize, self.section_alignment as usize) as u32
            })
            .max()
            .unwrap();
        let mut size_of_code: u32 = 0;
        let mut size_of_init: u32 = 0;
        for s in &self.sections {
            if s.size_of_raw_data == 0 {
                continue;
            }
            if s.characteristics & IMAGE_SCN_CNT_CODE != 0 {
                size_of_code += s.size_of_raw_data;
            } else if s.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
                size_of_init += s.size_of_raw_data;
            }
        }
        LittleEndian::write_u32(
            &mut out[optional_header_off + 4..optional_header_off + 8],
            size_of_code,
        );
        LittleEndian::write_u32(
            &mut out[optional_header_off + 8..optional_header_off + 12],
            size_of_init,
        );
        LittleEndian::write_u32(
            &mut out[optional_header_off + 56..optional_header_off + 60],
            size_of_image,
        );
        // CheckSum
        LittleEndian::write_u32(
            &mut out[optional_header_off + 64..optional_header_off + 68],
            0,
        );

        // Force-disable ASLR (DYNAMIC_BASE / HIGH_ENTROPY_VA) so the OS
        // Loader keeps ImageBase fixed at 0x140000000. This sidesteps
        // the need to relocate the absolute VAs we baked into the new
        // TLS Directory, callback array and stub fixup slots — none of
        // which are listed in `.reloc2` correctly today. M5 will revisit.
        let dll_chars_off = optional_header_off + 70;
        let mut dll_chars = LittleEndian::read_u16(&out[dll_chars_off..dll_chars_off + 2]);
        // Clear DYNAMIC_BASE (0x40) and HIGH_ENTROPY_VA (0x20).
        dll_chars &= !(0x40u16 | 0x20u16);
        LittleEndian::write_u16(&mut out[dll_chars_off..dll_chars_off + 2], dll_chars);

        // DataDirectory updates.
        if !self.builder.extra_imports.is_empty() && self.idata2_idx != usize::MAX {
            let idata2 = &self.sections[self.idata2_idx];
            // Compute import directory size = total descriptor count * 20.
            let original_imp_real_count = self.count_original_imports()?;
            let total_descs = original_imp_real_count + self.builder.extra_imports.len() + 1;
            let import_size = (total_descs * 20) as u32;
            write_data_directory(
                &mut out[dd_off + IDX_IMPORT * 8..dd_off + IDX_IMPORT * 8 + 8],
                DataDirectory {
                    virtual_address: idata2.virtual_address,
                    size: import_size,
                },
            );
        }

        // TLS — we keep the host's original DataDirectory[9] intact.
        // The callback array bytes were patched in place to inject our
        // stub before the original callback. Do NOT rewrite this entry.

        // BaseReloc (only if .reloc2 was emitted).
        if let Some((rva, size)) = self.new_reloc {
            write_data_directory(
                &mut out[dd_off + IDX_BASERELOC * 8..dd_off + IDX_BASERELOC * 8 + 8],
                DataDirectory {
                    virtual_address: rva,
                    size,
                },
            );
        }

        // Other directories: keep originals.
        let _ = (IDX_EXCEPTION, IDX_RESOURCE, IDX_LOADCONFIG, IDX_IAT);

        // Section table.
        for (i, s) in self.sections.iter().enumerate() {
            let off = section_table_off + i * SECTION_HEADER_SIZE;
            let row = &mut out[off..off + SECTION_HEADER_SIZE];
            row[..8].copy_from_slice(&s.name);
            LittleEndian::write_u32(&mut row[8..12], s.virtual_size);
            LittleEndian::write_u32(&mut row[12..16], s.virtual_address);
            LittleEndian::write_u32(&mut row[16..20], s.size_of_raw_data);
            LittleEndian::write_u32(&mut row[20..24], s.pointer_to_raw_data);
            LittleEndian::write_u32(&mut row[24..28], 0);
            LittleEndian::write_u32(&mut row[28..32], 0);
            LittleEndian::write_u16(&mut row[32..34], 0);
            LittleEndian::write_u16(&mut row[34..36], 0);
            LittleEndian::write_u32(&mut row[36..40], s.characteristics);
        }

        // Zero out any leftover slots between (new section table end) and
        // SizeOfHeaders to avoid surprising the OS Loader with stale
        // section headers from the original file.
        let new_table_end = section_table_off + new_section_count * SECTION_HEADER_SIZE;
        if new_table_end < new_size_of_headers {
            for b in &mut out[new_table_end..new_size_of_headers] {
                *b = 0;
            }
        }

        // ---- Header sanitisation ------------------------------------
        //
        // These mutations are deliberately last so they can never
        // collide with anything above. They live in the DOS-to-NT gap
        // (Rich Header) and inside FileHeader / OptionalHeader, which
        // we have already authored earlier in this function.
        if let Some(ts) = self.builder.override_timedate_stamp {
            // FileHeader.TimeDateStamp lives at FileHeader+4 (after Machine).
            LittleEndian::write_u32(
                &mut out[file_header_off + 4..file_header_off + 8],
                ts,
            );
        }
        if let Some((major, minor)) = self.builder.override_linker_version {
            // OptionalHeader layout (PE32+):
            //   +0..+2  Magic (must stay 0x020B)
            //   +2      MajorLinkerVersion
            //   +3      MinorLinkerVersion
            out[optional_header_off + 2] = major;
            out[optional_header_off + 3] = minor;
        }
        if self.builder.strip_rich_header {
            // The Rich Header (if present) lives between the end of
            // the MS-DOS stub and `e_lfanew`. We can't trust the layout
            // beyond that, so we scan for the literal `Rich` marker
            // inside the gap and zero from `DanS` (xor-encoded) up to
            // and including the trailing `Rich`+XorKey (8 bytes).
            //
            // No Rich Header => nothing to do.
            self.strip_rich_header_in(&mut out[..nt_off]);
        }

        Ok(())
    }

    /// Zero out the Rich Header block, if any. Operates on the bytes
    /// preceding the NT headers (i.e. DOS header + DOS stub + Rich
    /// Header). Safe to call when no Rich Header is present.
    fn strip_rich_header_in(&self, dos_area: &mut [u8]) {
        // Lower bound: anything before `e_lfanew` could in principle
        // hold the Rich block. We only touch from offset 0x40 onward to
        // preserve the IMAGE_DOS_HEADER itself; the OS Loader still
        // requires `e_magic` and `e_lfanew` intact.
        if dos_area.len() < 0x80 {
            return;
        }

        // Find "Rich" marker.
        let mut rich_pos: Option<usize> = None;
        let scan_from = 0x40usize;
        let scan_to = dos_area.len().saturating_sub(8);
        for i in (scan_from..scan_to).step_by(4) {
            if &dos_area[i..i + 4] == b"Rich" {
                rich_pos = Some(i);
                break;
            }
        }
        let rich_end = match rich_pos {
            Some(p) => p + 8, // include the XorKey dword
            None => return,
        };
        // Read XorKey to recover encoded "DanS" pattern.
        let key = LittleEndian::read_u32(&dos_area[rich_pos.unwrap() + 4..rich_pos.unwrap() + 8]);
        let dans_enc: u32 = u32::from_le_bytes(*b"DanS") ^ key;
        // Locate DanS marker preceding "Rich" by scanning backwards on
        // 4-byte boundaries.
        let mut dans_pos: Option<usize> = None;
        let mut i = rich_pos.unwrap();
        while i >= scan_from + 4 {
            i -= 4;
            let w = LittleEndian::read_u32(&dos_area[i..i + 4]);
            if w == dans_enc {
                dans_pos = Some(i);
                break;
            }
        }
        // If we couldn't locate DanS, fall back to zeroing everything
        // between `scan_from` and `rich_end` (a Rich block without the
        // expected start marker is itself anomalous; safer to wipe the
        // whole DOS-stub padding).
        let dans = dans_pos.unwrap_or(scan_from);

        for b in &mut dos_area[dans..rich_end] {
            *b = 0;
        }
    }

    fn count_original_imports(&self) -> Result<usize> {
        let dir = self.builder.original.data_dirs[IDX_IMPORT];
        if !dir.is_present() {
            return Ok(0);
        }
        let off = self
            .builder
            .original
            .rva_to_file_offset(dir.virtual_address)
            .context("original import dir offset")?;
        let raw = &self.builder.original.raw;
        let mut count = 0usize;
        loop {
            let end = off + count * 20 + 20;
            if end > raw.len() {
                bail!("walking original import descriptors went past file");
            }
            let chunk = &raw[off + count * 20..off + count * 20 + 20];
            if chunk.iter().all(|&b| b == 0) {
                return Ok(count);
            }
            count += 1;
        }
    }
}

fn estimate_idata2_size(extra_imports: &[(String, Vec<String>)]) -> u32 {
    // descriptor table grows worst-case as (1 + N) * 20; new ones add 20 each.
    // strings: dll name (NUL) + per-fn (2 hint + name + NUL).
    let descs = (extra_imports.len() + 1) * 20;
    let mut strings = 0usize;
    let mut thunks = 0usize;
    for (dll, fns) in extra_imports {
        strings += dll.len() + 2;
        for f in fns {
            strings += 2 + f.len() + 2;
        }
        thunks += (fns.len() + 1) * 16; // both IAT and INT
    }
    // Plus padding.
    let est = descs + strings + 8 + thunks + 64;
    est as u32
}
