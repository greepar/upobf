//! `.eh_frame_hdr` parser (just the 4-byte signature + lengths).
//!
//! glibc's unwinder reads `.eh_frame_hdr` *before* `.init_array`
//! callbacks fire (PT_GNU_EH_FRAME is consulted by `dl_iterate_phdr`
//! and the C++ runtime can land in `_Unwind_Backtrace` indirectly
//! via early TLS setup). This means the upobf packer must list
//! `.eh_frame_hdr` *and* `.eh_frame` as forbidden ranges — they must
//! arrive at the kernel mapping in their original byte form.
//!
//! For the inspector, parsing is shallow: we only confirm the
//! `version == 1` byte, capture the encoding bytes, and hand the
//! caller the raw byte range so safe_ranges can subtract it from
//! candidate compression windows.

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::reader;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct EhFrameHdr {
    /// File offset of the `.eh_frame_hdr` blob.
    pub file_offset: u64,
    /// Total size of `.eh_frame_hdr`.
    pub size: u64,
    pub version: u8,
    pub eh_frame_ptr_enc: u8,
    pub fde_count_enc: u8,
    pub table_enc: u8,
}

impl EhFrameHdr {
    pub fn parse(buf: &[u8], file_off: u64, size: u64) -> Result<Self> {
        if size < 4 {
            bail!(".eh_frame_hdr size {} < 4", size);
        }
        let s = reader::slice(buf, file_off as usize, 4)
            .context(".eh_frame_hdr first 4 bytes")?;
        let version = s[0];
        if version != 1 {
            bail!(".eh_frame_hdr version {} unsupported", version);
        }
        Ok(Self {
            file_offset: file_off,
            size,
            version,
            eh_frame_ptr_enc: s[1],
            fde_count_enc: s[2],
            table_enc: s[3],
        })
    }
}
