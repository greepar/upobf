//! `PT_LOAD`-driven RVA <-> file-offset translation.
//!
//! For ET_DYN (PIE) images the "RVA" is just a VA: ld.so picks the
//! base at run time. For ET_EXEC the program headers carry absolute
//! VAs. Either way, RVA == VA in our packer's RVA arithmetic — we
//! never emit absolute VAs into the packed output, only `e_entry`/
//! `p_vaddr`-style values that ld.so will adjust by the load slide.

use anyhow::{anyhow, Result};

use super::headers::{Elf64Phdr, PT_LOAD};

/// Translate a virtual address (== RVA in our terms) to a file offset
/// using the program-header table. Returns the offset *and* the index
/// of the segment that contained it.
pub fn vaddr_to_file_offset(phdrs: &[Elf64Phdr], vaddr: u64) -> Result<(u64, usize)> {
    for (i, p) in phdrs.iter().enumerate() {
        if p.p_type != PT_LOAD {
            continue;
        }
        if vaddr >= p.p_vaddr && vaddr < p.p_vaddr + p.p_filesz {
            let delta = vaddr - p.p_vaddr;
            return Ok((p.p_offset + delta, i));
        }
    }
    Err(anyhow!(
        "vaddr 0x{:X} not in any PT_LOAD segment ({} segments)",
        vaddr,
        phdrs.len()
    ))
}

/// Variant that also accepts addresses inside the BSS region (i.e.
/// after `p_filesz` but before `p_memsz`). Used by callers that want
/// to map a `.tbss`-style symbol into the file offset of the
/// preceding `.tdata`. Returns `None` if the address falls in the
/// non-file-backed tail.
pub fn vaddr_to_file_offset_or_bss(
    phdrs: &[Elf64Phdr],
    vaddr: u64,
) -> Result<Option<(u64, usize)>> {
    for (i, p) in phdrs.iter().enumerate() {
        if p.p_type != PT_LOAD {
            continue;
        }
        if vaddr >= p.p_vaddr && vaddr < p.p_vaddr + p.p_memsz {
            if vaddr < p.p_vaddr + p.p_filesz {
                let delta = vaddr - p.p_vaddr;
                return Ok(Some((p.p_offset + delta, i)));
            } else {
                return Ok(None);
            }
        }
    }
    Err(anyhow!("vaddr 0x{:X} not in any PT_LOAD segment", vaddr))
}

/// Highest end-of-segment file offset (for "where can the writer
/// safely append new sections?").
pub fn highest_file_end(phdrs: &[Elf64Phdr]) -> u64 {
    phdrs
        .iter()
        .filter(|p| p.p_type == PT_LOAD)
        .map(|p| p.p_offset + p.p_filesz)
        .max()
        .unwrap_or(0)
}

/// Highest end-of-segment virtual address.
pub fn highest_vaddr_end(phdrs: &[Elf64Phdr]) -> u64 {
    phdrs
        .iter()
        .filter(|p| p.p_type == PT_LOAD)
        .map(|p| p.p_vaddr + p.p_memsz)
        .max()
        .unwrap_or(0)
}
