//! Unit tests covering header parsing edge cases and corrupted-image detection.

use crate::parse::data_dir::{self, DataDirectory};
use crate::parse::headers::{DosHeader, FileHeader, NtHeaders64, OptionalHeader64};
use crate::parse::sections::{self, SectionHeader};
use crate::PeImage;

// ---------- DosHeader ----------

#[test]
fn dos_header_parses_minimal_valid_stub() {
    // 64-byte DOS header with MZ + e_lfanew = 0x40.
    let mut buf = vec![0u8; 64];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C] = 0x40;
    buf[0x3D] = 0x00;
    buf[0x3E] = 0x00;
    buf[0x3F] = 0x00;
    let dos = DosHeader::parse(&buf).expect("parse minimal DOS header");
    assert_eq!(dos.e_magic, 0x5A4D);
    assert_eq!(dos.e_lfanew, 0x40);
}

#[test]
fn dos_header_rejects_truncated_input() {
    let buf = vec![0u8; 32];
    let err = DosHeader::parse(&buf).expect_err("must fail on short buf");
    assert!(
        err.to_string().contains("DOS header truncated"),
        "unexpected error: {err}"
    );
}

#[test]
fn dos_header_rejects_bad_magic() {
    let mut buf = vec![0u8; 64];
    buf[0] = b'P';
    buf[1] = b'E';
    let err = DosHeader::parse(&buf).expect_err("must fail on bad magic");
    assert!(
        err.to_string().contains("DOS magic mismatch"),
        "unexpected error: {err}"
    );
}

// ---------- Top-level corruption detection ----------

/// Build a synthetic, fully consistent minimal PE32+ image with one `.text`
/// section. Returns the raw byte vector.
fn build_minimal_pe() -> Vec<u8> {
    use byteorder::{LittleEndian, WriteBytesExt};

    let mut buf = vec![0u8; 0x600];
    // DOS
    buf[0] = b'M';
    buf[1] = b'Z';
    let e_lfanew: u32 = 0x80;
    (&mut buf[0x3C..0x40])
        .write_u32::<LittleEndian>(e_lfanew)
        .unwrap();

    // PE\0\0
    let nt_off = e_lfanew as usize;
    buf[nt_off] = b'P';
    buf[nt_off + 1] = b'E';

    // FileHeader
    let fh_off = nt_off + 4;
    (&mut buf[fh_off..fh_off + 2])
        .write_u16::<LittleEndian>(0x8664)
        .unwrap(); // Machine = AMD64
    (&mut buf[fh_off + 2..fh_off + 4])
        .write_u16::<LittleEndian>(1)
        .unwrap(); // NumberOfSections
    // SizeOfOptionalHeader
    let size_of_opt: u16 = (OptionalHeader64::PREFIX_SIZE + 16 * DataDirectory::SIZE) as u16;
    (&mut buf[fh_off + 16..fh_off + 18])
        .write_u16::<LittleEndian>(size_of_opt)
        .unwrap();
    (&mut buf[fh_off + 18..fh_off + 20])
        .write_u16::<LittleEndian>(0x0022)
        .unwrap(); // EXECUTABLE_IMAGE | LARGE_ADDR_AWARE

    // OptionalHeader64 prefix
    let oh_off = fh_off + FileHeader::SIZE;
    (&mut buf[oh_off..oh_off + 2])
        .write_u16::<LittleEndian>(OptionalHeader64::MAGIC_PE32_PLUS)
        .unwrap();
    // ImageBase @ +24, SectionAlignment @ +32, FileAlignment @ +36
    (&mut buf[oh_off + 24..oh_off + 32])
        .write_u64::<LittleEndian>(0x1_4000_0000)
        .unwrap();
    (&mut buf[oh_off + 32..oh_off + 36])
        .write_u32::<LittleEndian>(0x1000)
        .unwrap();
    (&mut buf[oh_off + 36..oh_off + 40])
        .write_u32::<LittleEndian>(0x200)
        .unwrap();
    // SizeOfImage @ +56, SizeOfHeaders @ +60
    (&mut buf[oh_off + 56..oh_off + 60])
        .write_u32::<LittleEndian>(0x2000)
        .unwrap();
    (&mut buf[oh_off + 60..oh_off + 64])
        .write_u32::<LittleEndian>(0x400)
        .unwrap();
    // Subsystem @ +68
    (&mut buf[oh_off + 68..oh_off + 70])
        .write_u16::<LittleEndian>(2)
        .unwrap();
    // NumberOfRvaAndSizes @ +108
    (&mut buf[oh_off + 108..oh_off + 112])
        .write_u32::<LittleEndian>(16)
        .unwrap();

    // DataDirectory[16] is left zeroed (no directories).

    // Section table: one .text section.
    let sect_off = oh_off + size_of_opt as usize;
    let name = b".text\0\0\0";
    buf[sect_off..sect_off + 8].copy_from_slice(name);
    (&mut buf[sect_off + 8..sect_off + 12])
        .write_u32::<LittleEndian>(0x100)
        .unwrap(); // VirtualSize
    (&mut buf[sect_off + 12..sect_off + 16])
        .write_u32::<LittleEndian>(0x1000)
        .unwrap(); // VirtualAddress
    (&mut buf[sect_off + 16..sect_off + 20])
        .write_u32::<LittleEndian>(0x200)
        .unwrap(); // SizeOfRawData
    (&mut buf[sect_off + 20..sect_off + 24])
        .write_u32::<LittleEndian>(0x400)
        .unwrap(); // PointerToRawData
    (&mut buf[sect_off + 36..sect_off + 40])
        .write_u32::<LittleEndian>(0x6000_0020)
        .unwrap(); // RX

    buf
}

#[test]
fn minimal_synthetic_pe_round_trips() {
    let buf = build_minimal_pe();
    let img = PeImage::from_bytes(buf).expect("synthetic PE parses");
    assert_eq!(img.nt.signature, NtHeaders64::SIGNATURE);
    assert_eq!(img.nt.file_header.machine, 0x8664);
    assert_eq!(img.nt.optional_header.image_base, 0x1_4000_0000);
    assert_eq!(img.sections.len(), 1);
    assert_eq!(img.sections[0].name, ".text");
    assert_eq!(
        img.data_dirs[data_dir::IDX_IMPORT].virtual_address, 0,
        "no import directory"
    );
    assert!(img.tls.is_none());
    assert!(img.load_config.is_none());
    assert!(img.pdata.is_none());
}

#[test]
fn corrupt_pe_signature_is_rejected() {
    let mut buf = build_minimal_pe();
    let nt_off = u32::from_le_bytes(buf[0x3C..0x40].try_into().unwrap()) as usize;
    buf[nt_off] = b'X'; // mangle the 'P' of "PE\0\0"
    let err = PeImage::from_bytes(buf).expect_err("bad PE sig must fail");
    let s = format!("{err:#}");
    assert!(
        s.contains("PE signature mismatch"),
        "expected signature error, got: {s}"
    );
}

#[test]
fn oversized_e_lfanew_is_rejected() {
    let mut buf = build_minimal_pe();
    // Point e_lfanew past EOF.
    let bad: u32 = (buf.len() as u32) + 0x1000;
    buf[0x3C..0x40].copy_from_slice(&bad.to_le_bytes());
    let err = PeImage::from_bytes(buf).expect_err("bad e_lfanew must fail");
    let s = format!("{err:#}");
    assert!(
        s.contains("e_lfanew") || s.contains("end of file"),
        "expected e_lfanew error, got: {s}"
    );
}

#[test]
fn implausible_section_count_is_rejected() {
    // Drive parse_table directly: anything > 96 must error.
    let buf = vec![0u8; 4096];
    let err = sections::parse_table(&buf, 0, 200).expect_err("must reject 200 sections");
    assert!(
        err.to_string().contains("implausible NumberOfSections"),
        "unexpected error: {err}"
    );
}

#[test]
fn data_dir_rejects_count_over_16() {
    let buf = vec![0u8; 256];
    let err = data_dir::parse(&buf, 0, 17).expect_err("count > 16 must fail");
    assert!(
        err.to_string()
            .contains("NumberOfRvaAndSizes=17 exceeds the architectural maximum"),
        "unexpected error: {err}"
    );
}

#[test]
fn pe32_magic_is_rejected_as_unsupported() {
    // Build a PE that claims to be PE32 (0x010B) instead of PE32+ (0x020B).
    let mut buf = build_minimal_pe();
    let e_lfanew = u32::from_le_bytes(buf[0x3C..0x40].try_into().unwrap()) as usize;
    let oh_off = e_lfanew + 4 + FileHeader::SIZE;
    buf[oh_off..oh_off + 2].copy_from_slice(&OptionalHeader64::MAGIC_PE32.to_le_bytes());
    let err = PeImage::from_bytes(buf).expect_err("PE32 must be rejected");
    let s = format!("{err:#}");
    assert!(s.contains("not PE32+"), "expected PE32+ rejection, got: {s}");
}

// ---------- SectionHeader behaviour ----------

#[test]
fn section_contains_rva_uses_max_of_virtual_and_raw() {
    let sec = SectionHeader {
        name: ".text".into(),
        virtual_address: 0x1000,
        virtual_size: 0x100,
        size_of_raw_data: 0x200,
        pointer_to_raw_data: 0x400,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: 0x6000_0020,
    };
    assert!(sec.contains_rva(0x1000));
    assert!(sec.contains_rva(0x10FF));
    assert!(sec.contains_rva(0x11FF));
    assert!(!sec.contains_rva(0x1200));
    assert!(!sec.contains_rva(0x0FFF));
}
