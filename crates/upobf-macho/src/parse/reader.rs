//! Bounds-checked little-endian primitive readers shared by all Mach-O parsers.
//!
//! Mirrors the ELF crate's reader; kept separate so the two can evolve
//! independently (Mach-O may grow ULEB128 helpers for export trie, etc.).

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
pub fn u8_at(buf: &[u8], off: usize) -> Result<u8> {
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
pub fn i32(buf: &[u8], off: usize) -> Result<i32> {
    let s = slice(buf, off, 4)?;
    Ok(LittleEndian::read_i32(s))
}

#[inline]
pub fn u64(buf: &[u8], off: usize) -> Result<u64> {
    let s = slice(buf, off, 8)?;
    Ok(LittleEndian::read_u64(s))
}

#[inline]
pub fn i64(buf: &[u8], off: usize) -> Result<i64> {
    let s = slice(buf, off, 8)?;
    Ok(LittleEndian::read_i64(s))
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
    let s = &buf[off..limit];
    let nul = s
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow::anyhow!("unterminated C-string @ 0x{:X}", off))?;
    Ok(String::from_utf8_lossy(&s[..nul]).into_owned())
}

/// Read a fixed-size byte array (e.g. segment name, section name — 16 bytes)
/// and trim trailing NUL bytes, returning as a String.
pub fn fixed_str(buf: &[u8], off: usize, len: usize) -> Result<String> {
    let s = slice(buf, off, len)?;
    let end = s.iter().position(|&b| b == 0).unwrap_or(len);
    Ok(String::from_utf8_lossy(&s[..end]).into_owned())
}

/// Decode a ULEB128 value starting at `off`. Returns (value, bytes_consumed).
pub fn uleb128(buf: &[u8], off: usize) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0usize;
    loop {
        if off + i >= buf.len() {
            bail!("ULEB128 truncated @ 0x{:X}+{}", off, i);
        }
        let byte = buf[off + i];
        i += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            bail!("ULEB128 overflow @ 0x{:X}", off);
        }
    }
    Ok((result, i))
}
