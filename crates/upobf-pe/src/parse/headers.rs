//! DOS / NT / Optional headers (PE32+ only).
//!
//! All structures use little-endian field ordering as defined by the PE/COFF
//! specification. We deliberately mirror the layout of the on-disk records but
//! parse them through bounds-checked slice reads rather than `unsafe` casts so
//! that misaligned or truncated input cannot trigger UB.

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;

use super::reader as r;

/// IMAGE_DOS_HEADER (we only keep the two fields we actually need).
#[derive(Debug, Clone, Serialize)]
pub struct DosHeader {
    /// `0x5A4D` ("MZ").
    pub e_magic: u16,
    /// File offset of the PE signature (== `IMAGE_NT_HEADERS`).
    pub e_lfanew: u32,
}

impl DosHeader {
    pub const SIZE: usize = 64;
    pub const MAGIC: u16 = 0x5A4D; // "MZ"

    /// Parse a `IMAGE_DOS_HEADER` starting at offset 0 of `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            bail!(
                "DOS header truncated: need {} bytes, got {}",
                Self::SIZE,
                buf.len()
            );
        }
        let e_magic = r::u16(buf, 0).context("DOS.e_magic")?;
        if e_magic != Self::MAGIC {
            bail!(
                "DOS magic mismatch: expected 0x{:04X}, got 0x{:04X}",
                Self::MAGIC,
                e_magic
            );
        }
        let e_lfanew = r::u32(buf, 0x3C).context("DOS.e_lfanew")?;
        Ok(Self { e_magic, e_lfanew })
    }
}

/// IMAGE_FILE_HEADER (COFF). 20 bytes.
#[derive(Debug, Clone, Serialize)]
pub struct FileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl FileHeader {
    pub const SIZE: usize = 20;

    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = r::slice(buf, off, Self::SIZE).context("FileHeader bytes")?;
        Ok(Self {
            machine: r::u16(s, 0)?,
            number_of_sections: r::u16(s, 2)?,
            time_date_stamp: r::u32(s, 4)?,
            pointer_to_symbol_table: r::u32(s, 8)?,
            number_of_symbols: r::u32(s, 12)?,
            size_of_optional_header: r::u16(s, 16)?,
            characteristics: r::u16(s, 18)?,
        })
    }

    /// Decode the Characteristics bitmask into a list of names.
    pub fn characteristics_flags(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        let mut push = |bit: u16, name: &'static str| {
            if self.characteristics & bit != 0 {
                out.push(name);
            }
        };
        push(0x0001, "RELOCS_STRIPPED");
        push(0x0002, "EXECUTABLE_IMAGE");
        push(0x0004, "LINE_NUMS_STRIPPED");
        push(0x0008, "LOCAL_SYMS_STRIPPED");
        push(0x0010, "AGGRESIVE_WS_TRIM");
        push(0x0020, "LARGE_ADDRESS_AWARE");
        push(0x0080, "BYTES_REVERSED_LO");
        push(0x0100, "MACHINE_32BIT");
        push(0x0200, "DEBUG_STRIPPED");
        push(0x0400, "REMOVABLE_RUN_FROM_SWAP");
        push(0x0800, "NET_RUN_FROM_SWAP");
        push(0x1000, "SYSTEM");
        push(0x2000, "DLL");
        push(0x4000, "UP_SYSTEM_ONLY");
        push(0x8000, "BYTES_REVERSED_HI");
        out
    }
}

/// IMAGE_OPTIONAL_HEADER64. 240 bytes when `NumberOfRvaAndSizes == 16`.
///
/// The DataDirectory tail is parsed separately by `data_dir::parse`.
#[derive(Debug, Clone, Serialize)]
pub struct OptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

impl OptionalHeader64 {
    /// Fixed prefix size, before the DataDirectory array.
    pub const PREFIX_SIZE: usize = 112;
    pub const MAGIC_PE32_PLUS: u16 = 0x020B;
    pub const MAGIC_PE32: u16 = 0x010B;

    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let s = r::slice(buf, off, Self::PREFIX_SIZE).context("OptionalHeader64 prefix")?;
        let magic = r::u16(s, 0)?;
        if magic != Self::MAGIC_PE32_PLUS {
            bail!(
                "Optional header magic 0x{:04X} is not PE32+ (0x020B). PE32 (0x010B) is unsupported by upobf-pe.",
                magic
            );
        }
        Ok(Self {
            magic,
            major_linker_version: r::u8(s, 2)?,
            minor_linker_version: r::u8(s, 3)?,
            size_of_code: r::u32(s, 4)?,
            size_of_initialized_data: r::u32(s, 8)?,
            size_of_uninitialized_data: r::u32(s, 12)?,
            address_of_entry_point: r::u32(s, 16)?,
            base_of_code: r::u32(s, 20)?,
            image_base: r::u64(s, 24)?,
            section_alignment: r::u32(s, 32)?,
            file_alignment: r::u32(s, 36)?,
            major_operating_system_version: r::u16(s, 40)?,
            minor_operating_system_version: r::u16(s, 42)?,
            major_image_version: r::u16(s, 44)?,
            minor_image_version: r::u16(s, 46)?,
            major_subsystem_version: r::u16(s, 48)?,
            minor_subsystem_version: r::u16(s, 50)?,
            win32_version_value: r::u32(s, 52)?,
            size_of_image: r::u32(s, 56)?,
            size_of_headers: r::u32(s, 60)?,
            checksum: r::u32(s, 64)?,
            subsystem: r::u16(s, 68)?,
            dll_characteristics: r::u16(s, 70)?,
            size_of_stack_reserve: r::u64(s, 72)?,
            size_of_stack_commit: r::u64(s, 80)?,
            size_of_heap_reserve: r::u64(s, 88)?,
            size_of_heap_commit: r::u64(s, 96)?,
            loader_flags: r::u32(s, 104)?,
            number_of_rva_and_sizes: r::u32(s, 108)?,
        })
    }

    /// Decode subsystem code into a static name.
    pub fn subsystem_name(&self) -> &'static str {
        match self.subsystem {
            0 => "UNKNOWN",
            1 => "NATIVE",
            2 => "WINDOWS_GUI",
            3 => "WINDOWS_CUI",
            5 => "OS2_CUI",
            7 => "POSIX_CUI",
            8 => "NATIVE_WINDOWS",
            9 => "WINDOWS_CE_GUI",
            10 => "EFI_APPLICATION",
            11 => "EFI_BOOT_SERVICE_DRIVER",
            12 => "EFI_RUNTIME_DRIVER",
            13 => "EFI_ROM",
            14 => "XBOX",
            16 => "WINDOWS_BOOT_APPLICATION",
            _ => "OTHER",
        }
    }

    /// Decode the DllCharacteristics bitmask into a list of names.
    pub fn dll_characteristics_flags(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        let mut push = |bit: u16, name: &'static str| {
            if self.dll_characteristics & bit != 0 {
                out.push(name);
            }
        };
        push(0x0020, "HIGH_ENTROPY_VA");
        push(0x0040, "DYNAMIC_BASE");
        push(0x0080, "FORCE_INTEGRITY");
        push(0x0100, "NX_COMPAT");
        push(0x0200, "NO_ISOLATION");
        push(0x0400, "NO_SEH");
        push(0x0800, "NO_BIND");
        push(0x1000, "APPCONTAINER");
        push(0x2000, "WDM_DRIVER");
        push(0x4000, "GUARD_CF");
        push(0x8000, "TERMINAL_SERVER_AWARE");
        out
    }
}

/// IMAGE_NT_HEADERS64.
#[derive(Debug, Clone, Serialize)]
pub struct NtHeaders64 {
    pub signature: u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader64,
}

impl NtHeaders64 {
    pub const SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"

    /// Parse the NT headers (signature + FileHeader + OptionalHeader64 prefix)
    /// starting at `off`. Does *not* read the DataDirectory tail.
    pub fn parse(buf: &[u8], off: usize) -> Result<Self> {
        let signature = r::u32(buf, off)
            .with_context(|| format!("PE signature read @ 0x{:X}", off))?;
        if signature != Self::SIGNATURE {
            return Err(anyhow!(
                "PE signature mismatch @ 0x{:X}: expected 0x{:08X}, got 0x{:08X}",
                off,
                Self::SIGNATURE,
                signature
            ));
        }
        let file_header = FileHeader::parse(buf, off + 4)?;
        let optional_header = OptionalHeader64::parse(buf, off + 4 + FileHeader::SIZE)?;
        Ok(Self {
            signature,
            file_header,
            optional_header,
        })
    }
}
