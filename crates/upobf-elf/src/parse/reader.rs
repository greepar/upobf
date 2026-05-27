//! Bounds-checked little-endian primitive readers shared by all ELF parsers.
//!
//! Identical surface to the PE crate's reader; kept duplicated rather than
//! shared so the two parsers can evolve independently (PE's reader could
//! grow PE-specific helpers, ELF's could grow leb128 helpers for
//! `.eh_frame`/`.debug_*`).

use anyhow::{bail, Result};
use byteorder::{ByteOrder, LittleEndian};

/// Borrow `len` bytes starting at `off` from `buf`, with a precise error if
/// the request runs past the end.
pub fn slice(buf: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    let end = off
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("offset overflow: 0x{:X}+{}", off, len))?;
    if end > buf.len() {
        bail!(
            "out of bounds: need 0x{:X}..0x{:X} ({} bytes) but buf len 0x{:X}",
            off,
            end,
            len,
            buf.len()
        );
    }
    Ok(&buf[off..end])
}

#[inline]
pub fn u8(buf: &[u8], off: usize) -> Result<u8> {
    let s = slice(buf, off, 1)?;
    Ok(s[0])
}

#[inline]
pub fn u16(buf: &[u8], off: usize) -> Result<u16> {
    let s = slice(buf, off, 2)?;
    Ok(LittleEndian::read_u16(s))
}

#[inline]
pub fn u32(buf: &[u8], off: usize) -> Result<u32> {
    let s = slice(buf, off, 4)?;
    Ok(LittleEndian::read_u32(s))
}

#[inline]
pub fn u64(buf: &[u8], off: usize) -> Result<u64> {
    let s = slice(buf, off, 8)?;
    Ok(LittleEndian::read_u64(s))
}

/// Read a NUL-terminated ASCII/UTF-8 string starting at the given file offset.
/// Caps the length at 4 KiB to avoid runaway scans on malformed images.
pub fn cstring_at(buf: &[u8], off: usize) -> Result<String> {
    const MAX_LEN: usize = 4096;
    if off >= buf.len() {
        bail!(
            "string offset 0x{:X} >= file len 0x{:X}",
            off,
            buf.len()
        );
    }
    let limit = (off + MAX_LEN).min(buf.len());
    let slice = &buf[off..limit];
    let nul = slice
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow::anyhow!("unterminated C-string @ 0x{:X}", off))?;
    Ok(String::from_utf8_lossy(&slice[..nul]).into_owned())
}
