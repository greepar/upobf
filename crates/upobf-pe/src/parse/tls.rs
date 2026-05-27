//! IMAGE_TLS_DIRECTORY64 (40 bytes) plus its callback list.
//!
//! Field layout:
//!
//! | Offset | Size | Field                        |
//! |-------:|-----:|------------------------------|
//! |   0    | 8    | StartAddressOfRawData (VA)   |
//! |   8    | 8    | EndAddressOfRawData (VA)     |
//! |  16    | 8    | AddressOfIndex (VA)          |
//! |  24    | 8    | AddressOfCallBacks (VA)      |
//! |  32    | 4    | SizeOfZeroFill               |
//! |  36    | 4    | Characteristics              |
//!
//! The callback array is a NULL-terminated list of 64-bit virtual addresses.

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::reader as r;
use super::sections::SectionHeader;

#[derive(Debug, Clone, Serialize)]
pub struct TlsDirectory {
    pub start_va: u64,
    pub end_va: u64,
    pub index_va: u64,
    pub callbacks_va: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    /// Callback entries, stored as **RVAs** (relative to ImageBase) for easier
    /// downstream rewriting. Computed as `va - image_base`.
    pub callbacks: Vec<u32>,
}

impl TlsDirectory {
    pub const SIZE: usize = 40;
    /// Hard cap to avoid pathological inputs.
    pub const MAX_CALLBACKS: usize = 256;

    /// Parse the TLS directory from the file image.
    ///
    /// `dir_rva` is the RVA of the TLS directory (DataDirectory[9]).
    /// `image_base` is the OptionalHeader64.ImageBase.
    pub fn parse(
        buf: &[u8],
        sections: &[SectionHeader],
        dir_rva: u32,
        image_base: u64,
    ) -> Result<Self> {
        let dir_off = rva_to_file_offset(sections, dir_rva)
            .with_context(|| format!("TLS directory RVA 0x{:08X}", dir_rva))?;
        let s = r::slice(buf, dir_off, Self::SIZE).context("TlsDirectory bytes")?;

        let start_va = r::u64(s, 0)?;
        let end_va = r::u64(s, 8)?;
        let index_va = r::u64(s, 16)?;
        let callbacks_va = r::u64(s, 24)?;
        let size_of_zero_fill = r::u32(s, 32)?;
        let characteristics = r::u32(s, 36)?;

        let mut callbacks: Vec<u32> = Vec::new();
        if callbacks_va != 0 {
            // Convert VA -> RVA -> file offset.
            let cb_array_rva = u64_to_rva(callbacks_va, image_base)
                .context("TLS.AddressOfCallBacks below ImageBase")?;
            let cb_array_off = rva_to_file_offset(sections, cb_array_rva)
                .with_context(|| format!("callback array RVA 0x{:08X}", cb_array_rva))?;
            for i in 0..Self::MAX_CALLBACKS {
                let entry_off = cb_array_off
                    .checked_add(i * 8)
                    .context("callback offset overflow")?;
                let cb_va = r::u64(buf, entry_off)
                    .with_context(|| format!("TLS callback[{}] @ 0x{:X}", i, entry_off))?;
                if cb_va == 0 {
                    break;
                }
                let cb_rva = u64_to_rva(cb_va, image_base)
                    .with_context(|| format!("TLS callback[{}] VA below ImageBase", i))?;
                callbacks.push(cb_rva);
                if i + 1 == Self::MAX_CALLBACKS {
                    bail!(
                        "TLS callback list not NULL-terminated within {} entries",
                        Self::MAX_CALLBACKS
                    );
                }
            }
        }

        Ok(Self {
            start_va,
            end_va,
            index_va,
            callbacks_va,
            size_of_zero_fill,
            characteristics,
            callbacks,
        })
    }
}

/// Helper: translate an RVA into a file offset by scanning the section table.
/// Lives here for the convenience of `tls`/`load_config`/etc.; identical logic
/// is exposed via `parse::PeImage::rva_to_file_offset` for external callers.
pub(crate) fn rva_to_file_offset(sections: &[SectionHeader], rva: u32) -> Result<usize> {
    for s in sections {
        if s.contains_rva(rva) {
            let delta = rva - s.virtual_address;
            if delta >= s.size_of_raw_data {
                bail!(
                    "RVA 0x{:08X} resolves into uninitialized tail of section '{}' \
                     (delta=0x{:X}, raw_size=0x{:X})",
                    rva,
                    s.name,
                    delta,
                    s.size_of_raw_data
                );
            }
            return Ok((s.pointer_to_raw_data + delta) as usize);
        }
    }
    bail!("RVA 0x{:08X} does not belong to any section", rva)
}

fn u64_to_rva(va: u64, image_base: u64) -> Result<u32> {
    if va < image_base {
        bail!(
            "VA 0x{:016X} is below ImageBase 0x{:016X}",
            va,
            image_base
        );
    }
    let delta = va - image_base;
    if delta > u32::MAX as u64 {
        bail!("VA 0x{:016X} - ImageBase yields > 4 GiB RVA", va);
    }
    Ok(delta as u32)
}
