//! Stub blob loader: converts a PIE ELF shared object into a flat
//! byte buffer the writer can drop into `.upobf0`.
//!
//! The Linux stub is built as a freestanding `.so` with **zero
//! relocations** (`ld.lld -shared -Bsymbolic`). All internal
//! references are RIP-relative within the .so's LOAD segments, so
//! relocating the whole image to `.upobf0_vaddr + reserve_off`
//! requires nothing more than copying every LOAD segment's bytes
//! to the right offset within a flat buffer.
//!
//! Three packer-managed slots at the head of `.data`:
//!
//!   * `g_payload_vaddr`     — VA of the PayloadHeader (set per
//!     build by the packer once `.upobf1` is laid out).
//!   * `g_image_base_rva`    — RVA of `g_image_base_anchor` itself,
//!     used by the stub at runtime to recover the load slide.
//!   * `g_image_base_anchor` — a single byte at a known RVA the
//!     stub takes the address of for slide computation.
//!
//! Their byte offsets inside the flat blob are returned in
//! [`StubBlob`] so the writer can patch them after computing
//! final layout.

use anyhow::{anyhow, bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};

use crate::parse::headers::{
    parse_phdr_table, parse_shdr_table, Elf64Ehdr, Elf64Shdr, PT_LOAD,
};

/// Result of flattening a stub `.so`.
#[derive(Debug, Clone)]
pub struct StubBlob {
    /// Flat bytes covering `[0, span)` from the stub's LOAD
    /// segments. Holes between segments stay zero-filled (they
    /// correspond to BSS / RELRO padding inside the stub).
    pub bytes: Vec<u8>,
    /// Offset into `bytes` of `upobf_stub_init` (== `e_entry` of
    /// the stub `.so`).
    pub init_offset: u64,
    /// Offset of `g_payload_vaddr` slot (8 bytes, LE u64).
    pub payload_vaddr_offset: u64,
    /// Offset of `g_image_base_rva` slot (8 bytes, LE u64).
    pub image_base_rva_offset: u64,
    /// Offset of `g_image_base_anchor` byte.
    pub image_base_anchor_offset: u64,
    /// Offset of `upobf_entry_trampoline` (Phase I e_entry redirect
    /// target). The packer sets ELF header `e_entry` to
    /// `upobf0_vaddr + PHDR_TABLE_RESERVE + entry_trampoline_offset`
    /// when Phase I is enabled.
    pub entry_trampoline_offset: u64,
    /// Offset of `g_original_e_entry_rva` slot (8 bytes, LE u64).
    /// Filled with the host's pre-redirect `e_entry` so the
    /// trampoline can resume the host's startup after the stub
    /// returns.
    pub original_e_entry_rva_offset: u64,
}

impl StubBlob {
    /// Read a stub `.so` from disk and flatten it.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let raw = std::fs::read(path.as_ref())
            .with_context(|| format!("read {}", path.as_ref().display()))?;
        Self::from_bytes(&raw)
    }

    /// Flatten an in-memory stub `.so`.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let ehdr = Elf64Ehdr::parse(raw).context("stub Ehdr")?;
        let phdrs = parse_phdr_table(raw, ehdr.e_phoff, ehdr.e_phnum)
            .context("stub phdr table")?;
        let shdrs = parse_shdr_table(raw, ehdr.e_shoff, ehdr.e_shnum, ehdr.e_shstrndx)
            .context("stub shdr table")?;

        // Compute total span from the highest LOAD vaddr+memsz; we
        // address everything in vaddr space (= "virtual offsets")
        // since the stub is a relocatable PIE shared object.
        let span = phdrs
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .map(|p| p.p_vaddr + p.p_memsz)
            .max()
            .ok_or_else(|| anyhow!("stub has no PT_LOAD segments"))?;
        if span > 1 * 1024 * 1024 {
            bail!("stub blob span {} > 1 MiB; refusing to embed", span);
        }

        // Allocate flat buffer; copy each PT_LOAD into it at its
        // p_vaddr offset (so vaddr == flat-buffer offset).
        let mut bytes = vec![0u8; span as usize];
        for p in phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
            let src = p.p_offset as usize;
            let dst = p.p_vaddr as usize;
            let len = p.p_filesz as usize;
            if src + len > raw.len() {
                bail!(
                    "stub PT_LOAD past EOF: {:#x}+{:#x} > {:#x}",
                    src, len, raw.len()
                );
            }
            bytes[dst..dst + len].copy_from_slice(&raw[src..src + len]);
        }

        // Resolve symbol offsets via .symtab.
        let symtab = find_section(&shdrs, ".symtab")
            .ok_or_else(|| anyhow!("stub .symtab missing"))?;
        let strtab = shdrs
            .get(symtab.sh_link as usize)
            .ok_or_else(|| anyhow!("stub .strtab missing"))?;
        let strtab_off = strtab.sh_offset as usize;
        let strtab_end = strtab_off + strtab.sh_size as usize;

        let init_offset = lookup_symbol(raw, symtab, strtab_off, strtab_end, "upobf_stub_init")
            .ok_or_else(|| anyhow!("stub upobf_stub_init symbol missing"))?;
        let payload_vaddr_offset = lookup_symbol(
            raw, symtab, strtab_off, strtab_end, "g_payload_vaddr"
        )
        .ok_or_else(|| anyhow!("stub g_payload_vaddr symbol missing"))?;
        let image_base_rva_offset = lookup_symbol(
            raw, symtab, strtab_off, strtab_end, "g_image_base_rva"
        )
        .ok_or_else(|| anyhow!("stub g_image_base_rva symbol missing"))?;
        let image_base_anchor_offset = lookup_symbol(
            raw, symtab, strtab_off, strtab_end, "g_image_base_anchor"
        )
        .ok_or_else(|| anyhow!("stub g_image_base_anchor symbol missing"))?;
        let entry_trampoline_offset = lookup_symbol(
            raw, symtab, strtab_off, strtab_end, "upobf_entry_trampoline"
        )
        .ok_or_else(|| anyhow!("stub upobf_entry_trampoline symbol missing"))?;
        let original_e_entry_rva_offset = lookup_symbol(
            raw, symtab, strtab_off, strtab_end, "g_original_e_entry_rva"
        )
        .ok_or_else(|| anyhow!("stub g_original_e_entry_rva symbol missing"))?;

        Ok(StubBlob {
            bytes,
            init_offset,
            payload_vaddr_offset,
            image_base_rva_offset,
            image_base_anchor_offset,
            entry_trampoline_offset,
            original_e_entry_rva_offset,
        })
    }

    /// Patch the four packer-managed slots and produce the final
    /// blob bytes ready to embed into `.upobf0`.
    ///
    /// `original_e_entry_rva` is `0` when Phase I (e_entry redirect)
    /// is disabled; the trampoline never executes in that mode so
    /// the slot value is irrelevant, but we still write 0 to keep
    /// the sentinel from leaking into shipped artifacts.
    pub fn patched(
        &self,
        image_base_rva: u64,
        payload_vaddr: u64,
        original_e_entry_rva: u64,
    ) -> Vec<u8> {
        let mut out = self.bytes.clone();
        let off = self.image_base_rva_offset as usize;
        LittleEndian::write_u64(&mut out[off..off + 8], image_base_rva);
        let off = self.payload_vaddr_offset as usize;
        LittleEndian::write_u64(&mut out[off..off + 8], payload_vaddr);
        let off = self.original_e_entry_rva_offset as usize;
        LittleEndian::write_u64(&mut out[off..off + 8], original_e_entry_rva);
        out
    }
}

fn find_section<'a>(shdrs: &'a [Elf64Shdr], name: &str) -> Option<&'a Elf64Shdr> {
    shdrs.iter().find(|s| s.name == name)
}

/// Walk a `.symtab` section and return the symbol's `st_value`
/// (which equals the symbol's vaddr in our stub, == its offset in
/// the flat blob).
fn lookup_symbol(
    raw: &[u8],
    symtab: &Elf64Shdr,
    strtab_off: usize,
    strtab_end: usize,
    name: &str,
) -> Option<u64> {
    use crate::parse::symbols::SYM_ENTRY_SIZE;
    let count = (symtab.sh_size / SYM_ENTRY_SIZE as u64) as usize;
    for i in 0..count {
        let entry_off = symtab.sh_offset as usize + i * SYM_ENTRY_SIZE;
        if entry_off + SYM_ENTRY_SIZE > raw.len() {
            return None;
        }
        let st_name =
            LittleEndian::read_u32(&raw[entry_off..entry_off + 4]) as usize;
        let st_value =
            LittleEndian::read_u64(&raw[entry_off + 8..entry_off + 16]);
        if st_name == 0 {
            continue;
        }
        let abs = strtab_off + st_name;
        if abs >= strtab_end {
            continue;
        }
        let slice = &raw[abs..strtab_end];
        let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        let s = std::str::from_utf8(&slice[..nul]).ok()?;
        if s == name {
            return Some(st_value);
        }
    }
    None
}
