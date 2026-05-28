//! Mach-O writer: rebuilds a Mach-O binary with compressed sections,
//! injected stub and payload segments, and rewritten entry point.
//!
//! Strategy (mirrors ELF writer approach):
//! 1. Copy original segments, zeroing out compressed ranges (file-shrink).
//! 2. Drop LC_CODE_SIGNATURE.
//! 3. Append __UPOBF0 (stub, R+X) and __UPOBF1 (payload, R) segments.
//! 4. Rewrite LC_MAIN.entryoff to point at stub trampoline.
//! 5. Rebuild the load command table with updated offsets.
//! 6. All file offsets are 16 KB page-aligned (arm64 macOS requirement).

use anyhow::{bail, Context, Result};

use crate::parse::headers::{
    self, LoadCmdHeader, MachHeader64, LOAD_CMD_HEADER_SIZE, MACH_HEADER_64_SIZE,
    LC_BUILD_VERSION, LC_CODE_SIGNATURE, LC_DATA_IN_CODE, LC_DYLD_CHAINED_FIXUPS,
    LC_DYLD_EXPORTS_TRIE, LC_DYSYMTAB, LC_FUNCTION_STARTS, LC_LOAD_DYLIB,
    LC_LOAD_WEAK_DYLIB, LC_MAIN, LC_REEXPORT_DYLIB, LC_RPATH, LC_SEGMENT_64,
    LC_SYMTAB, LC_UUID,
};
use crate::parse::segments::{
    SECTION_64_SIZE, SEGMENT_CMD_64_SIZE, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use crate::parse::MachoImage;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// macOS arm64 page size (16 KB).
pub const PAGE_SIZE: u64 = 0x4000;

/// Align `val` up to the next multiple of `align`.
pub fn align_up(val: u64, align: u64) -> u64 {
    (val + align - 1) & !(align - 1)
}

// ---------------------------------------------------------------------------
// CompressedRange: describes a region that was compressed away
// ---------------------------------------------------------------------------

/// A range within the original file that has been compressed into the payload.
/// The writer will zero-fill this range in the output (file-shrink).
#[derive(Debug, Clone)]
pub struct CompressedRange {
    /// Segment name containing this range.
    pub segname: String,
    /// Section name (for diagnostics).
    pub sectname: String,
    /// File offset in the original binary.
    pub file_offset: u64,
    /// Size in bytes.
    pub size: u64,
}

// ---------------------------------------------------------------------------
// WriterConfig
// ---------------------------------------------------------------------------

/// Configuration for the Mach-O writer.
#[derive(Debug, Clone)]
pub struct WriterConfig {
    /// Stub code blob (contents of __UPOBF0 segment, R-X).
    /// If empty, no stub code segment is added.
    pub stub_code_blob: Vec<u8>,

    /// Stub data blob (contents of __UPOBF2 segment, RW-).
    /// If empty, no stub data segment is added.
    pub stub_data_blob: Vec<u8>,

    /// Encrypted/compressed payload blob (contents of __UPOBF1 segment).
    /// If empty, no payload segment is added.
    pub payload_blob: Vec<u8>,

    /// Ranges in the original binary that have been compressed.
    /// These will be zeroed out in the output file.
    pub compressed_ranges: Vec<CompressedRange>,

    /// New entry point offset (relative to __TEXT vmaddr).
    /// If None, LC_MAIN is left unchanged.
    pub new_entryoff: Option<u64>,
}

// ---------------------------------------------------------------------------
// MachoWriter
// ---------------------------------------------------------------------------

pub struct MachoWriter<'a> {
    img: &'a MachoImage,
    config: WriterConfig,
}

impl<'a> MachoWriter<'a> {
    pub fn new(img: &'a MachoImage, config: WriterConfig) -> Self {
        Self { img, config }
    }

    /// Build the output Mach-O binary.
    pub fn build(&self) -> Result<Vec<u8>> {
        // Phase 1: Plan the output layout.
        let layout = self.plan_layout()?;

        // Phase 2: Write the output.
        let mut out = vec![0u8; layout.total_file_size as usize];
        self.write_header(&mut out, &layout)?;
        self.write_load_commands(&mut out, &layout)?;
        self.write_segment_data(&mut out, &layout)?;
        self.write_upobf_segments(&mut out, &layout)?;

        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Layout planning
    // -----------------------------------------------------------------------

    fn plan_layout(&self) -> Result<OutputLayout> {
        // Collect original segments.
        let mut seg_layouts: Vec<SegLayout> = Vec::new();

        // Calculate how much space we need for the load command region.
        let lc_size = self.estimate_load_commands_size()?;

        // Layout strategy:
        // - __TEXT: fileoff=0, filesize=vmsize (AMFI requirement)
        // - __DATA_CONST, __DATA: placed after __TEXT
        // - __UPOBF0, __UPOBF1: placed BEFORE __LINKEDIT (codesign requires
        //   __LINKEDIT to be the last segment, and it expands vmsize for the
        //   code signature data)
        // - __LINKEDIT: always last, vmaddr after __UPOBF1

        let mut file_cursor: u64 = 0;
        let mut linkedit_seg: Option<&crate::parse::segments::SegmentCommand64> = None;

        for seg in &self.img.segments {
            if seg.filesize == 0 {
                seg_layouts.push(SegLayout {
                    segname: seg.segname.clone(),
                    original_fileoff: seg.fileoff,
                    original_filesize: seg.filesize,
                    new_fileoff: 0,
                    new_filesize: 0,
                    vmaddr: seg.vmaddr,
                    vmsize: seg.vmsize,
                });
                continue;
            }

            if seg.is_linkedit() {
                // Defer __LINKEDIT — it goes after __UPOBF0/__UPOBF1.
                linkedit_seg = Some(seg);
                continue;
            }

            if seg.is_text() {
                // __TEXT: AMFI requires filesize == vmsize.
                seg_layouts.push(SegLayout {
                    segname: seg.segname.clone(),
                    original_fileoff: seg.fileoff,
                    original_filesize: seg.filesize,
                    new_fileoff: 0,
                    new_filesize: seg.filesize,
                    vmaddr: seg.vmaddr,
                    vmsize: seg.vmsize,
                });
                file_cursor = seg.filesize;
            } else {
                // __DATA_CONST, __DATA, etc.
                // Compute shrunk filesize: if compressed ranges are at the tail
                // of this segment, we can reduce filesize (kernel zero-fills
                // the gap between filesize and vmsize).
                let shrunk_filesize = self.compute_data_shrunk_filesize(seg);
                let aligned_off = align_up(file_cursor, PAGE_SIZE);
                seg_layouts.push(SegLayout {
                    segname: seg.segname.clone(),
                    original_fileoff: seg.fileoff,
                    original_filesize: seg.filesize,
                    new_fileoff: aligned_off,
                    new_filesize: shrunk_filesize,
                    vmaddr: seg.vmaddr,
                    vmsize: seg.vmsize,
                });
                file_cursor = aligned_off + shrunk_filesize;
            }
        }

        // Insert __UPOBF0 and __UPOBF1 BEFORE __LINKEDIT.
        // VM addresses: after the last non-LINKEDIT segment's VM range.
        let last_vm_end_before_linkedit = seg_layouts
            .iter()
            .filter(|s| s.vmsize > 0)
            .map(|s| s.vmaddr + s.vmsize)
            .max()
            .unwrap_or(0);

        let upobf0_layout = if !self.config.stub_code_blob.is_empty() {
            let aligned_off = align_up(file_cursor, PAGE_SIZE);
            // Combine code + data into one contiguous segment.
            // The stub's ADRP instructions assume code and data are at fixed
            // relative offsets. We keep them together in __UPOBF0 (R-X).
            // This works because the stub no longer writes to its __DATA
            // (all mutable state is on the stack).
            let total_stub_size = self.config.stub_code_blob.len() as u64
                + self.config.stub_data_blob.len() as u64;
            let size = total_stub_size;
            let vmsize = align_up(size, PAGE_SIZE);
            let vmaddr = align_up(last_vm_end_before_linkedit, PAGE_SIZE);

            file_cursor = aligned_off + align_up(size, PAGE_SIZE);
            Some(SegLayout {
                segname: "__UPOBF0".to_string(),
                original_fileoff: 0,
                original_filesize: 0,
                new_fileoff: aligned_off,
                new_filesize: size,
                vmaddr,
                vmsize,
            })
        } else {
            None
        };

        // __UPOBF2 is no longer used — stub code+data are combined in __UPOBF0.
        // Keep the field for future use but always None.
        let upobf2_layout: Option<SegLayout> = None;

        let upobf1_layout = if !self.config.payload_blob.is_empty() {
            let aligned_off = align_up(file_cursor, PAGE_SIZE);
            let size = self.config.payload_blob.len() as u64;
            let vmsize = align_up(size, PAGE_SIZE);
            let prev_vm_end = upobf0_layout
                .as_ref()
                .map(|s| s.vmaddr + s.vmsize)
                .unwrap_or(last_vm_end_before_linkedit);
            let vmaddr = align_up(prev_vm_end, PAGE_SIZE);

            file_cursor = aligned_off + align_up(size, PAGE_SIZE);
            Some(SegLayout {
                segname: "__UPOBF1".to_string(),
                original_fileoff: 0,
                original_filesize: 0,
                new_fileoff: aligned_off,
                new_filesize: size,
                vmaddr,
                vmsize,
            })
        } else {
            None
        };

        // Now place __LINKEDIT last (after __UPOBF0/__UPOBF1).
        if let Some(seg) = linkedit_seg {
            let shrunk = self.compute_linkedit_shrunk_size(seg);
            let aligned_off = align_up(file_cursor, PAGE_SIZE);
            // VM address: after the last UPOBF segment.
            let prev_vm_end = upobf1_layout.as_ref()
                .map(|s| s.vmaddr + s.vmsize)
                .or_else(|| upobf0_layout.as_ref().map(|s| s.vmaddr + s.vmsize))
                .unwrap_or(last_vm_end_before_linkedit);
            let vmaddr = align_up(prev_vm_end, PAGE_SIZE);

            seg_layouts.push(SegLayout {
                segname: seg.segname.clone(),
                original_fileoff: seg.fileoff,
                original_filesize: seg.filesize,
                new_fileoff: aligned_off,
                new_filesize: shrunk,
                vmaddr,
                vmsize: seg.vmsize, // codesign will expand this
            });
            file_cursor = aligned_off + shrunk;
        }

        let total_file_size = align_up(file_cursor, PAGE_SIZE);

        Ok(OutputLayout {
            seg_layouts,
            upobf0: upobf0_layout,
            upobf1: upobf1_layout,
            upobf2: upobf2_layout,
            lc_region_size: lc_size,
            total_file_size,
        })
    }

    /// Compute shrunk filesize for a __DATA* segment.
    ///
    /// If compressed ranges form a contiguous tail of the segment's file
    /// data, we can reduce filesize (the kernel zero-fills the gap between
    /// filesize and vmsize). For ranges in the middle, we keep them as
    /// zeros in the file.
    fn compute_data_shrunk_filesize(&self, seg: &crate::parse::segments::SegmentCommand64) -> u64 {
        if self.config.compressed_ranges.is_empty() {
            return seg.filesize;
        }

        let seg_start = seg.fileoff;
        let seg_end = seg.fileoff + seg.filesize;

        // Collect compressed ranges within this segment.
        let mut ranges: Vec<(u64, u64)> = self.config.compressed_ranges.iter()
            .filter(|cr| cr.file_offset >= seg_start && cr.file_offset < seg_end)
            .map(|cr| (cr.file_offset, (cr.file_offset + cr.size).min(seg_end)))
            .collect();

        if ranges.is_empty() {
            return seg.filesize;
        }

        ranges.sort_by_key(|r| r.0);
        let ranges = merge_ranges(&ranges);

        // Find the highest compressed range that extends to the end of the segment.
        // We can only shrink if compressed ranges form a contiguous tail.
        let last_range_end = ranges.last().map(|r| r.1).unwrap_or(seg_start);

        if last_range_end >= seg_end {
            // The last compressed range reaches the end of the segment.
            // Find where the continuous tail of compressed ranges starts.
            let tail_start = find_continuous_tail_start(&ranges, seg_end);
            // New filesize = offset of tail start relative to segment start, page-aligned.
            let new_filesize = align_up(tail_start - seg_start, PAGE_SIZE);
            // Don't shrink below one page (segment must have some file backing).
            new_filesize.max(PAGE_SIZE)
        } else {
            // Compressed ranges don't reach the end — can't shrink.
            seg.filesize
        }
    }

    /// Compute __TEXT filesize after removing compressed holes.
    /// We keep all non-compressed bytes but pack them tightly:
    /// - Header + load commands region (always kept)
    /// - Non-compressed sections between/after compressed ones
    /// The result is page-aligned.
    fn compute_text_shrunk_filesize(&self, seg: &crate::parse::segments::SegmentCommand64) -> u64 {
        if self.config.compressed_ranges.is_empty() {
            return seg.filesize;
        }

        let seg_start = seg.fileoff;
        let seg_end = seg.fileoff + seg.filesize;

        // Sum up bytes that are NOT in any compressed range.
        let mut kept_bytes: u64 = 0;
        let mut pos = seg_start;

        // Sort compressed ranges within this segment.
        let mut ranges: Vec<(u64, u64)> = self.config.compressed_ranges.iter()
            .filter(|cr| cr.file_offset >= seg_start && cr.file_offset < seg_end)
            .map(|cr| (cr.file_offset, (cr.file_offset + cr.size).min(seg_end)))
            .collect();
        ranges.sort_by_key(|r| r.0);
        let ranges = merge_ranges(&ranges);

        for &(start, end) in &ranges {
            if start > pos {
                kept_bytes += start - pos;
            }
            pos = end;
        }
        // Trailing non-compressed bytes.
        if pos < seg_end {
            kept_bytes += seg_end - pos;
        }

        // Page-align the result.
        align_up(kept_bytes, PAGE_SIZE)
    }

    /// Compute __LINKEDIT size after removing code signature data.
    fn compute_linkedit_shrunk_size(&self, seg: &crate::parse::segments::SegmentCommand64) -> u64 {
        if let Some(ref cs) = self.img.code_signature {
            let cs_end = cs.dataoff as u64 + cs.datasize as u64;
            let seg_end = seg.fileoff + seg.filesize;
            if cs_end == seg_end {
                let new_size = cs.dataoff as u64 - seg.fileoff;
                return align_up(new_size, PAGE_SIZE).min(seg.filesize);
            }
        }
        seg.filesize
    }

    /// Estimate total size of the rebuilt load command region.
    fn estimate_load_commands_size(&self) -> Result<usize> {
        let mut size: usize = 0;

        for lc in &self.img.load_cmds {
            // Drop LC_CODE_SIGNATURE.
            if lc.cmd == LC_CODE_SIGNATURE {
                continue;
            }
            size += lc.cmdsize as usize;
        }

        // Add __UPOBF0 segment LC (no sections).
        if !self.config.stub_code_blob.is_empty() {
            size += SEGMENT_CMD_64_SIZE; // segment_command_64 with 0 sections
        }

        // Add __UPOBF1 segment LC (no sections).
        if !self.config.payload_blob.is_empty() {
            size += SEGMENT_CMD_64_SIZE;
        }

        Ok(size)
    }

    // -----------------------------------------------------------------------
    // Writing
    // -----------------------------------------------------------------------

    fn write_header(&self, out: &mut [u8], layout: &OutputLayout) -> Result<()> {
        use byteorder::{LittleEndian, WriteBytesExt};
        use std::io::Cursor;

        let mut c = Cursor::new(&mut out[..MACH_HEADER_64_SIZE]);
        c.write_u32::<LittleEndian>(self.img.header.magic)?;
        c.write_u32::<LittleEndian>(self.img.header.cputype)?;
        c.write_u32::<LittleEndian>(self.img.header.cpusubtype)?;
        c.write_u32::<LittleEndian>(self.img.header.filetype)?;

        // ncmds: original minus dropped + added.
        let dropped = self.img.load_cmds.iter()
            .filter(|lc| lc.cmd == LC_CODE_SIGNATURE)
            .count() as u32;
        let added = if self.config.stub_code_blob.is_empty() { 0u32 } else { 1 }
            + if self.config.payload_blob.is_empty() { 0u32 } else { 1 };
        let ncmds = self.img.header.ncmds - dropped + added;
        c.write_u32::<LittleEndian>(ncmds)?;

        c.write_u32::<LittleEndian>(layout.lc_region_size as u32)?;
        c.write_u32::<LittleEndian>(self.img.header.flags)?;
        c.write_u32::<LittleEndian>(self.img.header.reserved)?;

        Ok(())
    }

    fn write_load_commands(&self, out: &mut [u8], layout: &OutputLayout) -> Result<()> {
        let mut off = MACH_HEADER_64_SIZE;
        let mut seg_idx = 0usize;

        // Compute the __LINKEDIT file offset delta for patching LCs that
        // reference data inside __LINKEDIT.
        let linkedit_delta = self.compute_linkedit_delta(layout);

        for lc in &self.img.load_cmds {
            // Drop LC_CODE_SIGNATURE.
            if lc.cmd == LC_CODE_SIGNATURE {
                continue;
            }

            if lc.cmd == LC_SEGMENT_64 {
                // Check if this is __LINKEDIT — if so, insert __UPOBF0/__UPOBF1 first.
                let seg_name = crate::parse::reader::fixed_str(&self.img.raw, lc.offset + 8, 16)
                    .unwrap_or_default();
                if seg_name == "__LINKEDIT" {
                    // Insert __UPOBF0 and __UPOBF1 BEFORE __LINKEDIT LC.
                    if let Some(ref upobf0) = layout.upobf0 {
                        self.write_new_segment_lc(out, off, upobf0, VM_PROT_READ | VM_PROT_EXECUTE)?;
                        off += SEGMENT_CMD_64_SIZE;
                    }
                    if let Some(ref upobf1) = layout.upobf1 {
                        self.write_new_segment_lc(out, off, upobf1, VM_PROT_READ)?;
                        off += SEGMENT_CMD_64_SIZE;
                    }
                }

                // Rewrite segment command with updated file offsets.
                let seg_layout = &layout.seg_layouts[seg_idx];
                self.write_segment_lc(out, off, lc, seg_layout)?;
                seg_idx += 1;
            } else if lc.cmd == LC_MAIN && self.config.new_entryoff.is_some() {
                // Rewrite LC_MAIN with new entry offset.
                self.write_main_lc(out, off, lc)?;
            } else {
                // Copy original load command verbatim.
                let src = &self.img.raw[lc.offset..lc.offset + lc.cmdsize as usize];
                out[off..off + lc.cmdsize as usize].copy_from_slice(src);

                // Patch file offsets in LCs that reference __LINKEDIT data.
                if linkedit_delta != 0 {
                    self.patch_linkedit_lc(out, off, lc, linkedit_delta);
                }
            }

            off += lc.cmdsize as usize;
        }

        // If there was no __LINKEDIT (unlikely), append UPOBF LCs at the end.
        if self.img.segments.iter().all(|s| !s.is_linkedit()) {
            if let Some(ref upobf0) = layout.upobf0 {
                self.write_new_segment_lc(out, off, upobf0, VM_PROT_READ | VM_PROT_EXECUTE)?;
                off += SEGMENT_CMD_64_SIZE;
            }
            if let Some(ref upobf1) = layout.upobf1 {
                self.write_new_segment_lc(out, off, upobf1, VM_PROT_READ)?;
                off += SEGMENT_CMD_64_SIZE;
            }
        }

        Ok(())
    }

    /// Compute the delta between the original and new __LINKEDIT file offset.
    fn compute_linkedit_delta(&self, layout: &OutputLayout) -> i64 {
        // Find __LINKEDIT in the original and in the layout.
        let orig_linkedit = self.img.segments.iter()
            .find(|s| s.is_linkedit());
        let new_linkedit = layout.seg_layouts.iter()
            .find(|s| s.segname == "__LINKEDIT");

        match (orig_linkedit, new_linkedit) {
            (Some(orig), Some(new_l)) => new_l.new_fileoff as i64 - orig.fileoff as i64,
            _ => 0,
        }
    }

    /// Patch file offsets in load commands that reference __LINKEDIT data.
    /// These include LC_SYMTAB, LC_DYSYMTAB, LC_DYLD_CHAINED_FIXUPS,
    /// LC_DYLD_EXPORTS_TRIE, LC_FUNCTION_STARTS, LC_DATA_IN_CODE.
    fn patch_linkedit_lc(&self, out: &mut [u8], off: usize, lc: &LoadCmdHeader, delta: i64) {
        use byteorder::{LittleEndian, ByteOrder};

        match lc.cmd {
            LC_SYMTAB => {
                // symtab_command: cmd(4) + cmdsize(4) + symoff(4) + nsyms(4) + stroff(4) + strsize(4)
                let symoff = LittleEndian::read_u32(&out[off + 8..off + 12]);
                let stroff = LittleEndian::read_u32(&out[off + 16..off + 20]);
                if symoff != 0 {
                    LittleEndian::write_u32(&mut out[off + 8..off + 12], (symoff as i64 + delta) as u32);
                }
                if stroff != 0 {
                    LittleEndian::write_u32(&mut out[off + 16..off + 20], (stroff as i64 + delta) as u32);
                }
            }
            LC_DYSYMTAB => {
                // dysymtab_command has many offset fields. Patch the ones that
                // reference file offsets: indirectsymoff(56), extreloff(64), locreloff(72)
                let fields = [56usize, 64, 72];
                for &field_off in &fields {
                    let val = LittleEndian::read_u32(&out[off + field_off..off + field_off + 4]);
                    if val != 0 {
                        LittleEndian::write_u32(
                            &mut out[off + field_off..off + field_off + 4],
                            (val as i64 + delta) as u32,
                        );
                    }
                }
            }
            LC_DYLD_CHAINED_FIXUPS | LC_DYLD_EXPORTS_TRIE | LC_FUNCTION_STARTS
            | LC_DATA_IN_CODE => {
                // linkedit_data_command: cmd(4) + cmdsize(4) + dataoff(4) + datasize(4)
                let dataoff = LittleEndian::read_u32(&out[off + 8..off + 12]);
                if dataoff != 0 {
                    LittleEndian::write_u32(&mut out[off + 8..off + 12], (dataoff as i64 + delta) as u32);
                }
            }
            _ => {}
        }
    }

    fn write_segment_lc(
        &self,
        out: &mut [u8],
        off: usize,
        lc: &LoadCmdHeader,
        seg_layout: &SegLayout,
    ) -> Result<()> {
        use byteorder::{LittleEndian, ByteOrder};

        // Start by copying the original LC verbatim (preserves sections, flags, etc.).
        let src = &self.img.raw[lc.offset..lc.offset + lc.cmdsize as usize];
        out[off..off + lc.cmdsize as usize].copy_from_slice(src);

        // Patch vmaddr and vmsize (needed for __LINKEDIT which moves).
        LittleEndian::write_u64(&mut out[off + 24..off + 32], seg_layout.vmaddr);
        // Keep original vmsize (don't patch it — codesign may expand __LINKEDIT).

        // Patch fileoff and filesize in the segment_command_64.
        LittleEndian::write_u64(&mut out[off + 40..off + 48], seg_layout.new_fileoff);
        LittleEndian::write_u64(&mut out[off + 48..off + 56], seg_layout.new_filesize);

        // Patch section file offsets if this segment has file data.
        if seg_layout.new_filesize > 0 && seg_layout.original_filesize > 0 {
            let nsects = LittleEndian::read_u32(&out[off + 64..off + 68]);
            let delta = seg_layout.new_fileoff as i64 - seg_layout.original_fileoff as i64;

            let mut sect_off = off + SEGMENT_CMD_64_SIZE;
            for _ in 0..nsects {
                // section_64.offset is at byte 48 within the section struct.
                let orig_sect_offset = LittleEndian::read_u32(&out[sect_off + 48..sect_off + 52]);
                if orig_sect_offset != 0 {
                    let new_sect_offset = (orig_sect_offset as i64 + delta) as u32;
                    LittleEndian::write_u32(&mut out[sect_off + 48..sect_off + 52], new_sect_offset);
                }
                sect_off += SECTION_64_SIZE;
            }
        }

        Ok(())
    }

    fn write_main_lc(&self, out: &mut [u8], off: usize, lc: &LoadCmdHeader) -> Result<()> {
        use byteorder::{LittleEndian, ByteOrder};

        // Copy original.
        let src = &self.img.raw[lc.offset..lc.offset + lc.cmdsize as usize];
        out[off..off + lc.cmdsize as usize].copy_from_slice(src);

        // Patch entryoff.
        if let Some(new_entry) = self.config.new_entryoff {
            LittleEndian::write_u64(&mut out[off + 8..off + 16], new_entry);
        }

        Ok(())
    }

    fn write_new_segment_lc(
        &self,
        out: &mut [u8],
        off: usize,
        seg: &SegLayout,
        prot: u32,
    ) -> Result<()> {
        use byteorder::{LittleEndian, WriteBytesExt};
        use std::io::Cursor;

        let mut c = Cursor::new(&mut out[off..off + SEGMENT_CMD_64_SIZE]);
        c.write_u32::<LittleEndian>(LC_SEGMENT_64)?;           // cmd
        c.write_u32::<LittleEndian>(SEGMENT_CMD_64_SIZE as u32)?; // cmdsize
        // segname: 16 bytes, NUL-padded.
        let mut name_buf = [0u8; 16];
        let name_bytes = seg.segname.as_bytes();
        let copy_len = name_bytes.len().min(16);
        name_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        c.get_mut()[8..24].copy_from_slice(&name_buf);
        c.set_position(24);
        c.write_u64::<LittleEndian>(seg.vmaddr)?;              // vmaddr
        c.write_u64::<LittleEndian>(seg.vmsize)?;              // vmsize
        c.write_u64::<LittleEndian>(seg.new_fileoff)?;         // fileoff
        c.write_u64::<LittleEndian>(seg.new_filesize)?;        // filesize
        c.write_u32::<LittleEndian>(prot)?;                    // maxprot
        c.write_u32::<LittleEndian>(prot)?;                    // initprot
        c.write_u32::<LittleEndian>(0)?;                       // nsects
        c.write_u32::<LittleEndian>(0)?;                       // flags

        Ok(())
    }

    fn write_segment_data(&self, out: &mut [u8], layout: &OutputLayout) -> Result<()> {
        // The header + load commands region occupies the first N bytes.
        // We must NOT overwrite it when copying __TEXT segment data.
        let protected_region = MACH_HEADER_64_SIZE + layout.lc_region_size;

        for seg_layout in &layout.seg_layouts {
            if seg_layout.new_filesize == 0 || seg_layout.original_filesize == 0 {
                continue;
            }

            let dst_start = seg_layout.new_fileoff as usize;

            if seg_layout.segname == "__TEXT" {
                // __TEXT: copy all data, then zero-fill compressed ranges in-place.
                // (Cannot shrink filesize due to AMFI page verification.)
                self.write_text_segment_zerofill(out, seg_layout, protected_region)?;
            } else {
                // Other segments: copy verbatim at new_fileoff.
                let src_start = seg_layout.original_fileoff as usize;
                let copy_len = seg_layout.new_filesize.min(seg_layout.original_filesize) as usize;

                if src_start + copy_len > self.img.raw.len() {
                    bail!(
                        "segment '{}' original data past EOF: 0x{:X}+0x{:X}",
                        seg_layout.segname,
                        seg_layout.original_fileoff,
                        seg_layout.original_filesize
                    );
                }

                // Skip protected region if this segment overlaps it.
                let actual_dst_start;
                let actual_src_start;
                let actual_copy_len;
                if dst_start < protected_region {
                    let skip = protected_region - dst_start;
                    if skip >= copy_len {
                        continue;
                    }
                    actual_dst_start = dst_start + skip;
                    actual_src_start = src_start + skip;
                    actual_copy_len = copy_len - skip;
                } else {
                    actual_dst_start = dst_start;
                    actual_src_start = src_start;
                    actual_copy_len = copy_len;
                }

                out[actual_dst_start..actual_dst_start + actual_copy_len]
                    .copy_from_slice(&self.img.raw[actual_src_start..actual_src_start + actual_copy_len]);

                // Zero-fill compressed ranges within this segment.
                for cr in &self.config.compressed_ranges {
                    if cr.file_offset >= seg_layout.original_fileoff
                        && cr.file_offset < seg_layout.original_fileoff + seg_layout.original_filesize
                    {
                        let delta = (cr.file_offset - seg_layout.original_fileoff) as usize;
                        let zero_start = dst_start + delta;
                        let zero_end = (zero_start + cr.size as usize).min(dst_start + copy_len);
                        if zero_start >= protected_region && zero_start < zero_end {
                            out[zero_start..zero_end].fill(0);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Write __TEXT segment: copy all original data, then zero-fill compressed ranges.
    /// macOS AMFI requires filesize == vmsize for __TEXT, so we cannot shrink it.
    fn write_text_segment_zerofill(
        &self,
        out: &mut [u8],
        seg_layout: &SegLayout,
        protected_region: usize,
    ) -> Result<()> {
        let src_start = seg_layout.original_fileoff as usize;
        let dst_start = seg_layout.new_fileoff as usize;
        let copy_len = seg_layout.new_filesize as usize;

        if src_start + copy_len > self.img.raw.len() {
            bail!(
                "segment '{}' original data past EOF: 0x{:X}+0x{:X}",
                seg_layout.segname,
                seg_layout.original_fileoff,
                seg_layout.original_filesize
            );
        }

        // Copy all data, skipping the protected header+LC region.
        let skip = if dst_start < protected_region {
            protected_region - dst_start
        } else {
            0
        };

        if skip < copy_len {
            out[dst_start + skip..dst_start + copy_len]
                .copy_from_slice(&self.img.raw[src_start + skip..src_start + copy_len]);
        }

        // Zero-fill compressed ranges within __TEXT.
        for cr in &self.config.compressed_ranges {
            if cr.file_offset >= seg_layout.original_fileoff
                && cr.file_offset < seg_layout.original_fileoff + seg_layout.original_filesize
            {
                let zero_start = dst_start + (cr.file_offset - seg_layout.original_fileoff) as usize;
                let zero_end = (zero_start + cr.size as usize).min(dst_start + copy_len);
                if zero_start >= protected_region && zero_start < zero_end {
                    out[zero_start..zero_end].fill(0);
                }
            }
        }

        Ok(())
    }

    fn write_upobf_segments(&self, out: &mut [u8], layout: &OutputLayout) -> Result<()> {
        // Write __UPOBF0 (stub code + data combined, R-X).
        if let Some(ref upobf0) = layout.upobf0 {
            let dst = upobf0.new_fileoff as usize;
            let code_len = self.config.stub_code_blob.len();
            let data_len = self.config.stub_data_blob.len();
            out[dst..dst + code_len].copy_from_slice(&self.config.stub_code_blob);
            if data_len > 0 {
                out[dst + code_len..dst + code_len + data_len]
                    .copy_from_slice(&self.config.stub_data_blob);
            }
        }

        // Write __UPOBF1 (payload).
        if let Some(ref upobf1) = layout.upobf1 {
            let dst = upobf1.new_fileoff as usize;
            let len = self.config.payload_blob.len();
            out[dst..dst + len].copy_from_slice(&self.config.payload_blob);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal layout types
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SegLayout {
    segname: String,
    original_fileoff: u64,
    original_filesize: u64,
    new_fileoff: u64,
    new_filesize: u64,
    vmaddr: u64,
    vmsize: u64,
}

#[derive(Debug)]
struct OutputLayout {
    seg_layouts: Vec<SegLayout>,
    upobf0: Option<SegLayout>,
    upobf1: Option<SegLayout>,
    upobf2: Option<SegLayout>,
    lc_region_size: usize,
    total_file_size: u64,
}

// ---------------------------------------------------------------------------
// File-shrink helpers
// ---------------------------------------------------------------------------

/// Merge overlapping/adjacent ranges into a sorted, non-overlapping list.
fn merge_ranges(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    if ranges.is_empty() {
        return Vec::new();
    }
    let mut sorted = ranges.to_vec();
    sorted.sort_by_key(|r| r.0);
    let mut merged: Vec<(u64, u64)> = vec![sorted[0]];
    for &(start, end) in &sorted[1..] {
        let last = merged.last_mut().unwrap();
        if start <= last.1 {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

/// Find the start of the continuous compressed tail.
/// Returns the file offset where the continuous tail of compressed
/// ranges begins (i.e., from this point to `seg_end` is all compressed).
fn find_continuous_tail_start(merged: &[(u64, u64)], seg_end: u64) -> u64 {
    // Walk backwards from the end: find the longest continuous chain
    // of merged ranges that reaches seg_end.
    let mut tail_start = seg_end;
    for &(start, end) in merged.iter().rev() {
        if end >= tail_start {
            tail_start = start;
        } else {
            break;
        }
    }
    tail_start
}
