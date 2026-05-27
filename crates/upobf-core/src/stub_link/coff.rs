//! Minimal COFF (x64 object file) parser.
//!
//! Scope: parse `clang -c` output for the upobf stub. Only IMAGE_FILE_MACHINE_AMD64
//! is accepted. The parser preserves symbol-table indices (including aux
//! records) so that relocation `symbol_index` lookups stay correct.
//!
//! Reference: Microsoft PE/COFF specification §3 (File Headers), §4 (Section
//! Table), §5 (Symbol Table), §6 (Relocations).

use anyhow::{anyhow, ensure, Context, Result};
use byteorder::{ByteOrder, LittleEndian};

pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

const COFF_FILE_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;
const SYMBOL_RECORD_SIZE: usize = 18;
const RELOCATION_SIZE: usize = 10;

// Section characteristics we care about.
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_LNK_INFO: u32 = 0x0000_0200;
pub const IMAGE_SCN_LNK_REMOVE: u32 = 0x0000_0800;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// Storage classes we recognise.
pub const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
pub const IMAGE_SYM_CLASS_STATIC: u8 = 3;
pub const IMAGE_SYM_CLASS_FILE: u8 = 0x67;
/// Synthetic class used for placeholder slots that occupy aux-record
/// indices in our flat `symbols` vector.
pub const IMAGE_SYM_CLASS_AUX_PLACEHOLDER: u8 = 0xff;

#[derive(Debug, Clone)]
pub struct CoffFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Debug, Clone)]
pub struct CoffSection {
    /// Resolved name (handles `/N` string-table pointers).
    pub name: String,
    /// Raw bytes (size = SizeOfRawData).
    pub data: Vec<u8>,
    pub virtual_size: u32,
    pub characteristics: u32,
    pub relocations: Vec<CoffRelocation>,
}

#[derive(Debug, Clone)]
pub struct CoffRelocation {
    /// Offset within the section's raw data.
    pub virtual_address: u32,
    /// Index into the parent object's `symbols` vector.
    pub symbol_index: u32,
    pub kind: CoffRelocKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoffRelocKind {
    Amd64Addr64,    // IMAGE_REL_AMD64_ADDR64    = 1
    Amd64Addr32,    // IMAGE_REL_AMD64_ADDR32    = 2
    Amd64Addr32Nb,  // IMAGE_REL_AMD64_ADDR32NB  = 3
    Amd64Rel32,     // IMAGE_REL_AMD64_REL32     = 4
    Amd64Section,   // IMAGE_REL_AMD64_SECTION   = 10
    Amd64SecRel,    // IMAGE_REL_AMD64_SECREL    = 11
    Other(u16),
}

impl CoffRelocKind {
    pub fn from_raw(value: u16) -> Self {
        match value {
            1 => Self::Amd64Addr64,
            2 => Self::Amd64Addr32,
            3 => Self::Amd64Addr32Nb,
            4 => Self::Amd64Rel32,
            10 => Self::Amd64Section,
            11 => Self::Amd64SecRel,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoffSymbol {
    pub name: String,
    pub value: u32,
    /// 1-based section number; 0 = undefined; -1 = absolute; -2 = debug.
    pub section_number: i16,
    pub storage_class: u8,
    pub aux_count: u8,
    /// Raw aux-record bytes immediately following this symbol. Empty for
    /// symbols without aux entries (and for the placeholder slots).
    pub raw_aux_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CoffObject {
    pub file_header: CoffFileHeader,
    pub sections: Vec<CoffSection>,
    /// Flat symbol vector; aux records occupy placeholder entries so that
    /// relocation `symbol_index` stays directly usable.
    pub symbols: Vec<CoffSymbol>,
    /// Raw string table (length-prefix-included, as on disk).
    pub strings: Vec<u8>,
}

/// Parse a COFF object file.
pub fn parse(bytes: &[u8]) -> Result<CoffObject> {
    ensure!(
        bytes.len() >= COFF_FILE_HEADER_SIZE,
        "COFF file too small ({} bytes)",
        bytes.len()
    );

    let machine = LittleEndian::read_u16(&bytes[0..2]);
    let number_of_sections = LittleEndian::read_u16(&bytes[2..4]);
    let time_date_stamp = LittleEndian::read_u32(&bytes[4..8]);
    let pointer_to_symbol_table = LittleEndian::read_u32(&bytes[8..12]);
    let number_of_symbols = LittleEndian::read_u32(&bytes[12..16]);
    let size_of_optional_header = LittleEndian::read_u16(&bytes[16..18]);
    let characteristics = LittleEndian::read_u16(&bytes[18..20]);

    ensure!(
        machine == IMAGE_FILE_MACHINE_AMD64,
        "unsupported COFF machine: 0x{:04x} (expected AMD64=0x8664)",
        machine
    );
    // Sanity-cap section count; the spec allows any u16 but real objects
    // never get close.
    ensure!(
        number_of_sections <= 96,
        "implausible NumberOfSections={}",
        number_of_sections
    );
    ensure!(
        size_of_optional_header == 0,
        "object files must have OptionalHeaderSize=0, got {}",
        size_of_optional_header
    );

    // Symbol + string tables.
    let symtab_off = pointer_to_symbol_table as usize;
    let symtab_len = (number_of_symbols as usize)
        .checked_mul(SYMBOL_RECORD_SIZE)
        .ok_or_else(|| anyhow!("symbol table size overflow"))?;
    let strtab_off = symtab_off
        .checked_add(symtab_len)
        .ok_or_else(|| anyhow!("symbol table offset overflow"))?;

    let strings = if number_of_symbols == 0 {
        Vec::new()
    } else {
        ensure!(
            strtab_off + 4 <= bytes.len(),
            "string table size out of range"
        );
        let total = LittleEndian::read_u32(&bytes[strtab_off..strtab_off + 4]) as usize;
        ensure!(total >= 4, "string table size {} < 4", total);
        ensure!(
            strtab_off + total <= bytes.len(),
            "string table extends past EOF"
        );
        bytes[strtab_off..strtab_off + total].to_vec()
    };

    // Section headers.
    let sec_table_off = COFF_FILE_HEADER_SIZE + size_of_optional_header as usize;
    let sec_table_end = sec_table_off
        .checked_add((number_of_sections as usize) * SECTION_HEADER_SIZE)
        .ok_or_else(|| anyhow!("section table overflow"))?;
    ensure!(sec_table_end <= bytes.len(), "section headers past EOF");

    let mut sections = Vec::with_capacity(number_of_sections as usize);
    for i in 0..number_of_sections as usize {
        let sh = &bytes[sec_table_off + i * SECTION_HEADER_SIZE..];
        let name = decode_section_name(&sh[0..8], &strings)
            .with_context(|| format!("section[{}] name decode", i))?;
        let virtual_size = LittleEndian::read_u32(&sh[8..12]);
        let _virtual_address = LittleEndian::read_u32(&sh[12..16]);
        let raw_size = LittleEndian::read_u32(&sh[16..20]);
        let raw_ptr = LittleEndian::read_u32(&sh[20..24]);
        let reloc_ptr = LittleEndian::read_u32(&sh[24..28]);
        let _ln_ptr = LittleEndian::read_u32(&sh[28..32]);
        let reloc_count = LittleEndian::read_u16(&sh[32..34]);
        let _ln_count = LittleEndian::read_u16(&sh[34..36]);
        let chars = LittleEndian::read_u32(&sh[36..40]);

        let data = if raw_size == 0 || raw_ptr == 0 {
            Vec::new()
        } else {
            let start = raw_ptr as usize;
            let end = start
                .checked_add(raw_size as usize)
                .ok_or_else(|| anyhow!("section[{}] raw data overflow", i))?;
            ensure!(
                end <= bytes.len(),
                "section[{}] `{}` raw data past EOF (start={} size={})",
                i,
                name,
                start,
                raw_size
            );
            bytes[start..end].to_vec()
        };

        let mut relocations = Vec::with_capacity(reloc_count as usize);
        if reloc_count > 0 {
            let start = reloc_ptr as usize;
            let total = (reloc_count as usize)
                .checked_mul(RELOCATION_SIZE)
                .ok_or_else(|| anyhow!("section[{}] reloc table size overflow", i))?;
            let end = start
                .checked_add(total)
                .ok_or_else(|| anyhow!("section[{}] reloc range overflow", i))?;
            ensure!(end <= bytes.len(), "section[{}] reloc table past EOF", i);
            for r in 0..reloc_count as usize {
                let rd = &bytes[start + r * RELOCATION_SIZE..];
                relocations.push(CoffRelocation {
                    virtual_address: LittleEndian::read_u32(&rd[0..4]),
                    symbol_index: LittleEndian::read_u32(&rd[4..8]),
                    kind: CoffRelocKind::from_raw(LittleEndian::read_u16(&rd[8..10])),
                });
            }
        }

        sections.push(CoffSection {
            name,
            data,
            virtual_size,
            characteristics: chars,
            relocations,
        });
    }

    // Symbol table. Aux records are absorbed as placeholder entries so that
    // relocation `symbol_index` keeps pointing at the right slot.
    let mut symbols: Vec<CoffSymbol> = Vec::with_capacity(number_of_symbols as usize);
    let mut i = 0usize;
    while i < number_of_symbols as usize {
        let rec_off = symtab_off + i * SYMBOL_RECORD_SIZE;
        ensure!(
            rec_off + SYMBOL_RECORD_SIZE <= bytes.len(),
            "symbol record {} past EOF",
            i
        );
        let sd = &bytes[rec_off..rec_off + SYMBOL_RECORD_SIZE];
        let name = decode_symbol_name(&sd[0..8], &strings)
            .with_context(|| format!("symbol[{}] name decode", i))?;
        let value = LittleEndian::read_u32(&sd[8..12]);
        let section_number = LittleEndian::read_i16(&sd[12..14]);
        let _typ = LittleEndian::read_u16(&sd[14..16]);
        let storage_class = sd[16];
        let aux_count = sd[17];

        let aux_total = aux_count as usize;
        let aux_end_idx = i + 1 + aux_total;
        ensure!(
            aux_end_idx <= number_of_symbols as usize,
            "aux records for symbol {} run past symbol table",
            i
        );
        let raw_aux_data = if aux_total > 0 {
            let start = symtab_off + (i + 1) * SYMBOL_RECORD_SIZE;
            let end = symtab_off + aux_end_idx * SYMBOL_RECORD_SIZE;
            bytes[start..end].to_vec()
        } else {
            Vec::new()
        };

        symbols.push(CoffSymbol {
            name,
            value,
            section_number,
            storage_class,
            aux_count,
            raw_aux_data,
        });
        for _ in 0..aux_total {
            symbols.push(CoffSymbol {
                name: String::new(),
                value: 0,
                section_number: 0,
                storage_class: IMAGE_SYM_CLASS_AUX_PLACEHOLDER,
                aux_count: 0,
                raw_aux_data: Vec::new(),
            });
        }
        i += 1 + aux_total;
    }

    Ok(CoffObject {
        file_header: CoffFileHeader {
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
        },
        sections,
        symbols,
        strings,
    })
}

fn decode_section_name(raw: &[u8], strings: &[u8]) -> Result<String> {
    debug_assert_eq!(raw.len(), 8);
    if raw[0] == b'/' {
        // Long name: `/<decimal offset>` into string table.
        let s = std::str::from_utf8(&raw[1..])
            .context("section name not UTF-8")?
            .trim_end_matches('\0');
        let off: usize = s
            .trim()
            .parse()
            .with_context(|| format!("invalid string-table offset `{}`", s))?;
        return read_string_at(strings, off);
    }
    let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Ok(String::from_utf8_lossy(&raw[..len]).into_owned())
}

fn decode_symbol_name(raw: &[u8], strings: &[u8]) -> Result<String> {
    debug_assert_eq!(raw.len(), 8);
    let zeros = LittleEndian::read_u32(&raw[0..4]);
    if zeros == 0 {
        let off = LittleEndian::read_u32(&raw[4..8]) as usize;
        return read_string_at(strings, off);
    }
    let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Ok(String::from_utf8_lossy(&raw[..len]).into_owned())
}

fn read_string_at(strings: &[u8], off: usize) -> Result<String> {
    ensure!(
        off < strings.len(),
        "string table offset {} OOB (len={})",
        off,
        strings.len()
    );
    let end = strings[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(strings.len());
    Ok(String::from_utf8_lossy(&strings[off..end]).into_owned())
}
