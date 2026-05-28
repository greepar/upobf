//! Parsers for miscellaneous load commands:
//! LC_LOAD_DYLIB, LC_MAIN, LC_BUILD_VERSION, LC_RPATH,
//! LC_DYLD_EXPORTS_TRIE, LC_CODE_SIGNATURE, LC_FUNCTION_STARTS, LC_UUID.
//!
//! Reference: <mach-o/loader.h>

use anyhow::{Context, Result};
use serde::Serialize;

use super::reader;

// ---------------------------------------------------------------------------
// LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB / LC_REEXPORT_DYLIB (dylib_command)
// ---------------------------------------------------------------------------

/// Minimum size of dylib_command: cmd(4) + cmdsize(4) + name_offset(4) +
/// timestamp(4) + current_version(4) + compat_version(4) = 24 bytes.
pub const DYLIB_CMD_MIN_SIZE: usize = 24;

#[derive(Debug, Clone, Serialize)]
pub struct DylibCmd {
    /// The load command type (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, etc.).
    pub cmd: u32,
    /// Resolved dylib path name.
    pub name: String,
    /// Offset of the name string within the load command.
    pub name_offset: u32,
    pub timestamp: u32,
    pub current_version: u32,
    pub compat_version: u32,
}

impl DylibCmd {
    /// Parse from the load command at `off`.
    pub fn parse(buf: &[u8], off: usize, cmd: u32, cmdsize: u32) -> Result<Self> {
        let s = reader::slice(buf, off, DYLIB_CMD_MIN_SIZE)
            .context("dylib_command bytes")?;
        let name_offset = reader::u32(s, 8)?;
        let timestamp = reader::u32(s, 12)?;
        let current_version = reader::u32(s, 16)?;
        let compat_version = reader::u32(s, 20)?;

        // Name is a NUL-terminated string at off + name_offset, bounded by cmdsize.
        let name_abs = off + name_offset as usize;
        let name = if name_abs < buf.len() {
            reader::cstring_at(buf, name_abs).unwrap_or_default()
        } else {
            String::new()
        };

        Ok(Self {
            cmd,
            name,
            name_offset,
            timestamp,
            current_version,
            compat_version,
        })
    }

    /// Format version as X.Y.Z (encoded as nibbles: XXXX.YY.ZZ).
    pub fn version_string(v: u32) -> String {
        let major = v >> 16;
        let minor = (v >> 8) & 0xFF;
        let patch = v & 0xFF;
        format!("{}.{}.{}", major, minor, patch)
    }
}

// ---------------------------------------------------------------------------
// LC_MAIN (entry_point_command: 24 bytes)
// ---------------------------------------------------------------------------

pub const MAIN_CMD_SIZE: usize = 24;

#[derive(Debug, Clone, Serialize)]
pub struct MainCmd {
    /// Offset of main() relative to __TEXT segment start (i.e., file offset
    /// from the beginning of __TEXT).
    pub entryoff: u64,
    /// Initial stack size (0 = default).
    pub stacksize: u64,
    /// File offset of this load command (for rewriting in writer).
    pub cmd_offset: usize,
}

impl MainCmd {
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, MAIN_CMD_SIZE).context("entry_point_command bytes")?;
        Ok(Self {
            entryoff: reader::u64(s, 8)?,
            stacksize: reader::u64(s, 16)?,
            cmd_offset: off,
        })
    }
}

// ---------------------------------------------------------------------------
// LC_BUILD_VERSION (build_version_command: 24+ bytes)
// ---------------------------------------------------------------------------

pub const BUILD_VERSION_CMD_MIN_SIZE: usize = 24;

// Platform constants.
pub const PLATFORM_MACOS: u32 = 1;
pub const PLATFORM_IOS: u32 = 2;
pub const PLATFORM_TVOS: u32 = 3;
pub const PLATFORM_WATCHOS: u32 = 4;
pub const PLATFORM_MACCATALYST: u32 = 6;

#[derive(Debug, Clone, Serialize)]
pub struct BuildVersionCmd {
    pub platform: u32,
    pub minos: u32,
    pub sdk: u32,
    pub ntools: u32,
    /// File offset of this load command.
    pub cmd_offset: usize,
}

impl BuildVersionCmd {
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, BUILD_VERSION_CMD_MIN_SIZE)
            .context("build_version_command bytes")?;
        Ok(Self {
            platform: reader::u32(s, 8)?,
            minos: reader::u32(s, 12)?,
            sdk: reader::u32(s, 16)?,
            ntools: reader::u32(s, 20)?,
            cmd_offset: off,
        })
    }

    pub fn platform_name(&self) -> &'static str {
        match self.platform {
            PLATFORM_MACOS => "macOS",
            PLATFORM_IOS => "iOS",
            PLATFORM_TVOS => "tvOS",
            PLATFORM_WATCHOS => "watchOS",
            PLATFORM_MACCATALYST => "Mac Catalyst",
            _ => "unknown",
        }
    }

    /// Format minos as X.Y.Z.
    pub fn minos_string(&self) -> String {
        DylibCmd::version_string(self.minos)
    }

    /// Format sdk as X.Y.Z.
    pub fn sdk_string(&self) -> String {
        DylibCmd::version_string(self.sdk)
    }
}

// ---------------------------------------------------------------------------
// LC_RPATH (rpath_command: 12+ bytes)
// ---------------------------------------------------------------------------

pub const RPATH_CMD_MIN_SIZE: usize = 12;

#[derive(Debug, Clone, Serialize)]
pub struct RpathCmd {
    pub path: String,
}

impl RpathCmd {
    pub fn parse(buf: &[u8], off: usize, _cmdsize: u32) -> Result<Self> {
        let s = reader::slice(buf, off, RPATH_CMD_MIN_SIZE)
            .context("rpath_command bytes")?;
        let path_offset = reader::u32(s, 8)?;
        let path_abs = off + path_offset as usize;
        let path = if path_abs < buf.len() {
            reader::cstring_at(buf, path_abs).unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Self { path })
    }
}

// ---------------------------------------------------------------------------
// LC_DYLD_EXPORTS_TRIE (linkedit_data_command: 16 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ExportsTrieCmd {
    /// File offset of the exports trie data in __LINKEDIT.
    pub dataoff: u32,
    /// Size of the exports trie data.
    pub datasize: u32,
}

impl ExportsTrieCmd {
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, 16).context("exports_trie linkedit_data_command")?;
        Ok(Self {
            dataoff: reader::u32(s, 8)?,
            datasize: reader::u32(s, 12)?,
        })
    }
}

// ---------------------------------------------------------------------------
// LC_CODE_SIGNATURE / LC_FUNCTION_STARTS / LC_DATA_IN_CODE
// (all use linkedit_data_command: 16 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct LinkEditDataCmd {
    pub cmd: u32,
    pub dataoff: u32,
    pub datasize: u32,
}

impl LinkEditDataCmd {
    pub fn parse(buf: &[u8], off: usize, cmd: u32) -> Result<Self> {
        let s = reader::slice(buf, off, 16).context("linkedit_data_command bytes")?;
        Ok(Self {
            cmd,
            dataoff: reader::u32(s, 8)?,
            datasize: reader::u32(s, 12)?,
        })
    }
}

// ---------------------------------------------------------------------------
// LC_UUID (uuid_command: 24 bytes)
// ---------------------------------------------------------------------------

pub const UUID_CMD_SIZE: usize = 24;

#[derive(Debug, Clone, Serialize)]
pub struct UuidCmd {
    pub uuid: [u8; 16],
}

impl UuidCmd {
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = reader::slice(buf, off, UUID_CMD_SIZE).context("uuid_command bytes")?;
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&s[8..24]);
        Ok(Self { uuid })
    }

    pub fn uuid_string(&self) -> String {
        format!(
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.uuid[0], self.uuid[1], self.uuid[2], self.uuid[3],
            self.uuid[4], self.uuid[5],
            self.uuid[6], self.uuid[7],
            self.uuid[8], self.uuid[9],
            self.uuid[10], self.uuid[11], self.uuid[12], self.uuid[13], self.uuid[14], self.uuid[15],
        )
    }
}
