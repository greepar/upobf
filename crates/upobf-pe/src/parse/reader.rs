//! Bounds-checked little-endian primitive readers shared by all PE parsers.
//!
//! All public helpers operate purely on `&[u8]` slices without `unsafe` and
//! return precise error messages so failures can be traced back to the exact
//! field name + offset in the calling parser.

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

/// Like [`u32`] but returns `None` instead of erroring on out-of-bounds.
#[inline]
pub fn u32_opt(buf: &[u8], off: usize) -> Option<u32> {
    let s = slice(buf, off, 4).ok()?;
    Some(LittleEndian::read_u32(s))
}

/// Like [`u64`] but returns `None` instead of erroring on out-of-bounds.
#[inline]
pub fn u64_opt(buf: &[u8], off: usize) -> Option<u64> {
    let s = slice(buf, off, 8).ok()?;
    Some(LittleEndian::read_u64(s))
}
