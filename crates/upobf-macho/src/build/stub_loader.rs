//! Mach-O stub blob loader.
//!
//! Loads the compiled `stub.dylib`, flattens its segments into a
//! contiguous byte buffer (vaddr == buffer offset), resolves
//! patcher-relevant symbol offsets, and provides a `patched()` method
//! that stamps the runtime slots before embedding.
//!
//! The stub dylib has two loadable segments:
//!   - `__TEXT` (R-X): code, cstrings, stubs
//!   - `__DATA` (RW-): globals, GOT, bss
//!
//! We flatten both into a single buffer but track the split point so
//! the writer can emit them as two separate segments:
//!   - `__UPOBF0` (R-X): code portion
//!   - `__UPOBF2` (RW-): data portion (mutable globals)
//!
//! Mirrors `crates/upobf-elf/src/build/stub_loader.rs`.

use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::parse::headers::{MachHeader64, MACH_HEADER_64_SIZE, LC_SEGMENT_64, LC_SYMTAB};
use crate::parse::reader;
use crate::parse::segments::{SegmentCommand64, SEGMENT_CMD_64_SIZE, SECTION_64_SIZE};
use crate::parse::symbols::{SymtabCmd, SYMTAB_CMD_SIZE, NLIST_64_SIZE};

// ---------------------------------------------------------------------------
// StubBlob
// ---------------------------------------------------------------------------

/// Maximum stub size we'll accept (1 MiB). Anything larger is likely a
/// mis-build or wrong file.
const MAX_STUB_SIZE: usize = 1024 * 1024;

/// A flattened stub blob with resolved symbol offsets, ready for patching
/// and embedding into the packed Mach-O's `__UPOBF0` segment.
#[derive(Debug, Clone)]
pub struct StubBlob {
    /// Flat byte buffer: vaddr == buffer offset (contains both code + data).
    pub bytes: Vec<u8>,

    /// Size of the code portion (first N bytes = __TEXT segment).
    /// Everything from 0..code_size goes into __UPOBF0 (R-X).
    pub code_size: usize,

    /// Size of the data portion (bytes from code_size..code_size+data_size).
    /// Goes into __UPOBF2 (RW-).
    pub data_size: usize,

    /// Offset of `_upobf_stub_init` in the flat buffer.
    pub stub_init_offset: u64,

    /// Offset of `_upobf_entry_trampoline` in the flat buffer.
    pub entry_trampoline_offset: u64,

    /// Offset of the `_g_payload_vaddr` 8-byte slot.
    pub payload_vaddr_offset: u64,

    /// Offset of the `_g_image_base_rva` 8-byte slot.
    pub image_base_rva_offset: u64,

    /// Offset of the `_g_image_base_anchor` single-byte marker.
    pub image_base_anchor_offset: u64,

    /// Offset of the `_g_original_entryoff` 8-byte slot.
    pub original_entryoff_offset: u64,

    /// Offset of the `_g_got_mmap_rva` 8-byte slot.
    pub got_mmap_rva_offset: u64,

    /// Offset of the `_g_got_mprotect_rva` 8-byte slot.
    pub got_mprotect_rva_offset: u64,

    /// Offset of the `_g_got_munmap_rva` 8-byte slot.
    pub got_munmap_rva_offset: u64,
}

impl StubBlob {
    /// Load a stub from a Mach-O dylib file on disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read(path)
            .with_context(|| format!("read stub from {}", path.display()))?;
        Self::from_bytes(&raw)
            .with_context(|| format!("parse stub {}", path.display()))
    }

    /// Load a stub from an in-memory Mach-O dylib buffer.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        // Parse mach_header_64.
        let header = MachHeader64::parse(raw).context("stub mach_header_64")?;

        // Walk load commands to find segments and symtab.
        let mut segments: Vec<SegmentCommand64> = Vec::new();
        let mut symtab_cmd: Option<SymtabCmd> = None;

        let mut lc_off = MACH_HEADER_64_SIZE;
        for i in 0..header.ncmds {
            let cmd = reader::u32(raw, lc_off)?;
            let cmdsize = reader::u32(raw, lc_off + 4)?;

            if cmd == LC_SEGMENT_64 {
                let seg = SegmentCommand64::parse(raw, lc_off, cmdsize)
                    .with_context(|| format!("stub LC_SEGMENT_64 #{}", i))?;
                segments.push(seg);
            } else if cmd == LC_SYMTAB {
                symtab_cmd = Some(SymtabCmd::parse(raw, lc_off).context("stub LC_SYMTAB")?);
            }

            lc_off += cmdsize as usize;
        }

        // Identify __TEXT and __DATA segments.
        let text_seg = segments.iter().find(|s| s.segname == "__TEXT")
            .context("stub has no __TEXT segment")?;
        let data_seg = segments.iter().find(|s| s.segname == "__DATA");

        // Code size = __TEXT vmsize (page-aligned).
        let code_size = text_seg.vmsize as usize;

        // Data size = __DATA vmsize (page-aligned), or 0 if no __DATA.
        let data_size = data_seg.map(|s| s.vmsize as usize).unwrap_or(0);

        // Compute flat buffer span: max(vmaddr + vmsize) across all segments
        // with file data (skip __PAGEZERO if present).
        let total_span = segments
            .iter()
            .filter(|s| s.filesize > 0 || s.segname == "__DATA") // include __DATA even if bss-only
            .map(|s| (s.vmaddr + s.vmsize) as usize)
            .max()
            .unwrap_or(0);

        if total_span == 0 {
            bail!("stub has no loadable segments with file data");
        }
        if total_span > MAX_STUB_SIZE {
            bail!(
                "stub flat span {} exceeds MAX_STUB_SIZE {}",
                total_span,
                MAX_STUB_SIZE
            );
        }

        // Flatten: allocate zero buffer, copy each segment's file data at its vmaddr.
        let mut flat = vec![0u8; total_span];
        for seg in &segments {
            if seg.filesize == 0 {
                continue;
            }
            let src_start = seg.fileoff as usize;
            let src_end = src_start + seg.filesize as usize;
            let dst_start = seg.vmaddr as usize;
            if src_end > raw.len() {
                bail!(
                    "stub segment '{}' file data past EOF: 0x{:X}+0x{:X}",
                    seg.segname,
                    seg.fileoff,
                    seg.filesize
                );
            }
            if dst_start + seg.filesize as usize > flat.len() {
                bail!(
                    "stub segment '{}' vmaddr+filesize exceeds flat span",
                    seg.segname
                );
            }
            flat[dst_start..dst_start + seg.filesize as usize]
                .copy_from_slice(&raw[src_start..src_end]);
        }

        // Resolve symbols from symtab.
        let symtab = symtab_cmd.context("stub has no LC_SYMTAB")?;

        let stub_init_offset = lookup_symbol(raw, &symtab, "_upobf_stub_init")
            .context("symbol _upobf_stub_init not found in stub")?;
        let entry_trampoline_offset = lookup_symbol(raw, &symtab, "_upobf_entry_trampoline")
            .context("symbol _upobf_entry_trampoline not found in stub")?;
        let payload_vaddr_offset = lookup_symbol(raw, &symtab, "_g_payload_vaddr")
            .context("symbol _g_payload_vaddr not found in stub")?;
        let image_base_rva_offset = lookup_symbol(raw, &symtab, "_g_image_base_rva")
            .context("symbol _g_image_base_rva not found in stub")?;
        let image_base_anchor_offset = lookup_symbol(raw, &symtab, "_g_image_base_anchor")
            .context("symbol _g_image_base_anchor not found in stub")?;
        let original_entryoff_offset = lookup_symbol(raw, &symtab, "_g_original_entryoff")
            .context("symbol _g_original_entryoff not found in stub")?;
        let got_mmap_rva_offset = lookup_symbol(raw, &symtab, "_g_got_mmap_rva")
            .context("symbol _g_got_mmap_rva not found in stub")?;
        let got_mprotect_rva_offset = lookup_symbol(raw, &symtab, "_g_got_mprotect_rva")
            .context("symbol _g_got_mprotect_rva not found in stub")?;
        let got_munmap_rva_offset = lookup_symbol(raw, &symtab, "_g_got_munmap_rva")
            .context("symbol _g_got_munmap_rva not found in stub")?;

        Ok(Self {
            bytes: flat,
            code_size,
            data_size,
            stub_init_offset,
            entry_trampoline_offset,
            payload_vaddr_offset,
            image_base_rva_offset,
            image_base_anchor_offset,
            original_entryoff_offset,
            got_mmap_rva_offset,
            got_mprotect_rva_offset,
            got_munmap_rva_offset,
        })
    }

    /// Produce a patched copy of the flat blob with the runtime slots filled in.
    ///
    /// Arguments:
    /// - `anchor_rva`: RVA of `g_image_base_anchor` in the output binary.
    /// - `payload_rva`: RVA of the payload header (or sentinel to skip).
    /// - `original_entryoff`: The host's original `LC_MAIN.entryoff` value.
    /// - `got_mmap_rva`: RVA of the host's GOT entry for `_mmap`.
    /// - `got_mprotect_rva`: RVA of the host's GOT entry for `_mprotect`.
    /// - `got_munmap_rva`: RVA of the host's GOT entry for `_munmap`.
    pub fn patched(
        &self,
        anchor_rva: u64,
        payload_rva: u64,
        original_entryoff: u64,
        got_mmap_rva: u64,
        got_mprotect_rva: u64,
        got_munmap_rva: u64,
    ) -> Vec<u8> {
        use byteorder::{ByteOrder, LittleEndian};

        let mut buf = self.bytes.clone();

        // Patch g_image_base_rva slot.
        let off = self.image_base_rva_offset as usize;
        LittleEndian::write_u64(&mut buf[off..off + 8], anchor_rva);

        // Patch g_payload_vaddr slot.
        let off = self.payload_vaddr_offset as usize;
        LittleEndian::write_u64(&mut buf[off..off + 8], payload_rva);

        // Patch g_original_entryoff slot.
        let off = self.original_entryoff_offset as usize;
        LittleEndian::write_u64(&mut buf[off..off + 8], original_entryoff);

        // Patch GOT RVA slots.
        let off = self.got_mmap_rva_offset as usize;
        LittleEndian::write_u64(&mut buf[off..off + 8], got_mmap_rva);

        let off = self.got_mprotect_rva_offset as usize;
        LittleEndian::write_u64(&mut buf[off..off + 8], got_mprotect_rva);

        let off = self.got_munmap_rva_offset as usize;
        LittleEndian::write_u64(&mut buf[off..off + 8], got_munmap_rva);

        buf
    }
}

// ---------------------------------------------------------------------------
// Symbol lookup helper
// ---------------------------------------------------------------------------

/// Look up a symbol by name in the stub's symtab. Returns the symbol's
/// `n_value` (which equals its vmaddr in the flat buffer for a dylib).
fn lookup_symbol(raw: &[u8], symtab: &SymtabCmd, name: &str) -> Result<u64> {
    let sym_off = symtab.symoff as usize;
    let str_off = symtab.stroff as usize;

    for i in 0..symtab.nsyms as usize {
        let entry_off = sym_off + i * NLIST_64_SIZE;
        let n_strx = reader::u32(raw, entry_off)? as usize;
        let n_value = reader::u64(raw, entry_off + 8)?;

        // Read the symbol name from the string table.
        let name_off = str_off + n_strx;
        if name_off >= raw.len() {
            continue;
        }
        let sym_name = reader::cstring_at(raw, name_off).unwrap_or_default();
        if sym_name == name {
            return Ok(n_value);
        }
    }

    bail!("symbol '{}' not found in stub symtab ({} entries)", name, symtab.nsyms);
}
