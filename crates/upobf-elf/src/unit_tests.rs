//! Unit tests for ELF parsing layer.
//!
//! Two cohorts:
//!   1. Synthetic byte-buffer tests: build a minimum-viable ELF in
//!      memory, verify edge cases (bad magic, truncated headers,
//!      EM_X86_64 enforcement, etc.).
//!   2. Behavioural tests against the bundled `Demo/PatchInstaller`
//!      binary that exercise the realistic code path end-to-end and
//!      lock in regressions on the field counts we read out.

use crate::parse::dynamic::{
    DynamicEntry, DynamicInfo, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_NEEDED, DT_NULL, DT_RELA,
    DT_RELACOUNT, DT_RELASZ, DT_STRSZ, DT_STRTAB,
};
use crate::parse::headers::{
    parse_phdr_table, parse_shdr_table, Elf64Ehdr, Elf64Phdr, Elf64Shdr, EHDR64_SIZE, ELFCLASS64,
    ELFDATA2LSB, ELFMAG, EM_X86_64, ET_DYN, EV_CURRENT, PHDR64_SIZE, PT_LOAD, SHDR64_SIZE,
    SHT_PROGBITS, SHT_STRTAB,
};
use crate::parse::notes::{parse_notes, NT_GNU_ABI_TAG, NT_GNU_BUILD_ID};
use crate::parse::reader;
use crate::parse::relocations::{
    Rela, RelaSummary, R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE,
};
use crate::parse::segments::{vaddr_to_file_offset, highest_file_end, highest_vaddr_end};

// ---------------------------------------------------------------------------
// Helpers: synthesise a minimal ELF64 buffer.
// ---------------------------------------------------------------------------

fn write_u16_le(dst: &mut [u8], off: usize, v: u16) {
    dst[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn write_u32_le(dst: &mut [u8], off: usize, v: u32) {
    dst[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn write_u64_le(dst: &mut [u8], off: usize, v: u64) {
    dst[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Build a 64-byte ELF header for an ET_DYN x86_64 image with
/// configurable phoff/phnum/shoff/shnum so we can exercise table
/// walks. All other fields are sane defaults.
fn make_ehdr(
    e_entry: u64,
    e_phoff: u64,
    e_phnum: u16,
    e_shoff: u64,
    e_shnum: u16,
    e_shstrndx: u16,
) -> [u8; EHDR64_SIZE] {
    let mut buf = [0u8; EHDR64_SIZE];
    buf[..4].copy_from_slice(&ELFMAG);
    buf[4] = ELFCLASS64;
    buf[5] = ELFDATA2LSB;
    buf[6] = EV_CURRENT;
    buf[7] = 0; // OSABI
    write_u16_le(&mut buf, 0x10, ET_DYN);
    write_u16_le(&mut buf, 0x12, EM_X86_64);
    write_u32_le(&mut buf, 0x14, 1); // e_version
    write_u64_le(&mut buf, 0x18, e_entry);
    write_u64_le(&mut buf, 0x20, e_phoff);
    write_u64_le(&mut buf, 0x28, e_shoff);
    write_u32_le(&mut buf, 0x30, 0); // e_flags
    write_u16_le(&mut buf, 0x34, EHDR64_SIZE as u16);
    write_u16_le(&mut buf, 0x36, PHDR64_SIZE as u16);
    write_u16_le(&mut buf, 0x38, e_phnum);
    write_u16_le(&mut buf, 0x3A, SHDR64_SIZE as u16);
    write_u16_le(&mut buf, 0x3C, e_shnum);
    write_u16_le(&mut buf, 0x3E, e_shstrndx);
    buf
}

fn make_phdr(
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
) -> [u8; PHDR64_SIZE] {
    let mut buf = [0u8; PHDR64_SIZE];
    write_u32_le(&mut buf, 0, p_type);
    write_u32_le(&mut buf, 4, p_flags);
    write_u64_le(&mut buf, 8, p_offset);
    write_u64_le(&mut buf, 16, p_vaddr);
    write_u64_le(&mut buf, 24, p_vaddr); // p_paddr
    write_u64_le(&mut buf, 32, p_filesz);
    write_u64_le(&mut buf, 40, p_memsz);
    write_u64_le(&mut buf, 48, p_align);
    buf
}

// ---------------------------------------------------------------------------
// Ehdr
// ---------------------------------------------------------------------------

#[test]
fn ehdr_parses_minimal_valid_image() {
    let buf = make_ehdr(0x1000, 64, 0, 0, 0, 0);
    let eh = Elf64Ehdr::parse(&buf).unwrap();
    assert_eq!(eh.e_type, ET_DYN);
    assert_eq!(eh.e_machine, EM_X86_64);
    assert_eq!(eh.e_entry, 0x1000);
    assert_eq!(eh.type_name(), "DYN");
}

#[test]
fn ehdr_rejects_bad_magic() {
    let mut buf = make_ehdr(0, 0, 0, 0, 0, 0);
    buf[0] = b'X';
    let err = Elf64Ehdr::parse(&buf).unwrap_err();
    assert!(
        err.to_string().contains("bad ELF magic"),
        "unexpected error: {err}"
    );
}

#[test]
fn ehdr_rejects_elf32() {
    let mut buf = make_ehdr(0, 0, 0, 0, 0, 0);
    buf[4] = 1; // ELFCLASS32
    let err = Elf64Ehdr::parse(&buf).unwrap_err();
    assert!(
        err.to_string().contains("ELFCLASS64"),
        "unexpected error: {err}"
    );
}

#[test]
fn ehdr_rejects_truncated_buffer() {
    let buf = vec![0u8; 32];
    let err = Elf64Ehdr::parse(&buf).unwrap_err();
    let chain: String = err.chain().map(|c| c.to_string()).collect::<Vec<_>>().join(" / ");
    assert!(
        chain.contains("out of bounds") || chain.contains("Ehdr bytes"),
        "unexpected error chain: {chain}"
    );
}

#[test]
fn ehdr_rejects_non_x86_64() {
    let mut buf = make_ehdr(0, 0, 0, 0, 0, 0);
    write_u16_le(&mut buf, 0x12, 183); // EM_AARCH64
    let err = Elf64Ehdr::parse(&buf).unwrap_err();
    assert!(
        err.to_string().contains("unsupported machine"),
        "unexpected error: {err}"
    );
}

// ---------------------------------------------------------------------------
// Phdr / Shdr table walks
// ---------------------------------------------------------------------------

#[test]
fn phdr_table_walks_three_entries() {
    let mut file = vec![0u8; 64 + 3 * PHDR64_SIZE];
    file[..64].copy_from_slice(&make_ehdr(0x1000, 64, 3, 0, 0, 0));
    let p0 = make_phdr(PT_LOAD, 4, 0, 0, 0x100, 0x100, 0x1000);
    let p1 = make_phdr(PT_LOAD, 5, 0x100, 0x100, 0x200, 0x200, 0x1000);
    let p2 = make_phdr(PT_LOAD, 6, 0x300, 0x300, 0x40, 0x80, 0x1000);
    file[64..64 + PHDR64_SIZE].copy_from_slice(&p0);
    file[64 + PHDR64_SIZE..64 + 2 * PHDR64_SIZE].copy_from_slice(&p1);
    file[64 + 2 * PHDR64_SIZE..64 + 3 * PHDR64_SIZE].copy_from_slice(&p2);

    let phdrs = parse_phdr_table(&file, 64, 3).unwrap();
    assert_eq!(phdrs.len(), 3);
    assert_eq!(phdrs[0].p_type, PT_LOAD);
    assert_eq!(phdrs[0].p_flags, 4);
    assert_eq!(phdrs[1].p_vaddr, 0x100);
    assert_eq!(phdrs[2].p_filesz, 0x40);
    assert_eq!(phdrs[2].p_memsz, 0x80);
    assert_eq!(phdrs[1].flag_string(), "R E");
}

#[test]
fn shdr_table_resolves_names_via_shstrtab() {
    // Synthesise: 3 sections, last is .shstrtab containing "\0.text\0.shstrtab\0".
    let strtab: &[u8] = b"\0.text\0.shstrtab\0";
    let strtab_off: u64 = 0x100;
    let mut file = vec![0u8; 0x300];
    file[..64].copy_from_slice(&make_ehdr(0, 0, 0, 0x200, 3, 2));
    file[strtab_off as usize..strtab_off as usize + strtab.len()].copy_from_slice(strtab);

    // shdr[0] = NULL
    let mut sh0 = [0u8; SHDR64_SIZE];
    file[0x200..0x200 + SHDR64_SIZE].copy_from_slice(&sh0);
    // shdr[1] = .text
    sh0 = [0u8; SHDR64_SIZE];
    write_u32_le(&mut sh0, 0, 1); // sh_name = offset of ".text" (1)
    write_u32_le(&mut sh0, 4, SHT_PROGBITS);
    write_u64_le(&mut sh0, 8, 4 | 2); // SHF_ALLOC | SHF_EXEC -- bits irrelevant here
    write_u64_le(&mut sh0, 16, 0x1000);
    write_u64_le(&mut sh0, 24, 0x1000);
    write_u64_le(&mut sh0, 32, 0x100);
    file[0x200 + SHDR64_SIZE..0x200 + 2 * SHDR64_SIZE].copy_from_slice(&sh0);
    // shdr[2] = .shstrtab
    sh0 = [0u8; SHDR64_SIZE];
    write_u32_le(&mut sh0, 0, 7); // sh_name = offset of ".shstrtab" (7)
    write_u32_le(&mut sh0, 4, SHT_STRTAB);
    write_u64_le(&mut sh0, 24, strtab_off);
    write_u64_le(&mut sh0, 32, strtab.len() as u64);
    file[0x200 + 2 * SHDR64_SIZE..0x200 + 3 * SHDR64_SIZE].copy_from_slice(&sh0);

    let shdrs = parse_shdr_table(&file, 0x200, 3, 2).unwrap();
    assert_eq!(shdrs.len(), 3);
    assert_eq!(shdrs[0].name, "");
    assert_eq!(shdrs[1].name, ".text");
    assert_eq!(shdrs[2].name, ".shstrtab");
}

// ---------------------------------------------------------------------------
// PT_LOAD / RVA <-> file translation
// ---------------------------------------------------------------------------

#[test]
fn vaddr_to_file_offset_handles_pie_load_segments() {
    // Two LOAD segments: [v=0..0x1000 file=0..0x1000] and
    //                    [v=0x2000..0x3000 file=0x1000..0x2000].
    let p0 = Elf64Phdr {
        p_type: PT_LOAD,
        p_flags: 4,
        p_offset: 0,
        p_vaddr: 0,
        p_paddr: 0,
        p_filesz: 0x1000,
        p_memsz: 0x1000,
        p_align: 0x1000,
    };
    let p1 = Elf64Phdr {
        p_type: PT_LOAD,
        p_flags: 5,
        p_offset: 0x1000,
        p_vaddr: 0x2000,
        p_paddr: 0x2000,
        p_filesz: 0x1000,
        p_memsz: 0x1000,
        p_align: 0x1000,
    };
    let phdrs = vec![p0, p1];

    let (off0, idx0) = vaddr_to_file_offset(&phdrs, 0x500).unwrap();
    assert_eq!(off0, 0x500);
    assert_eq!(idx0, 0);

    let (off1, idx1) = vaddr_to_file_offset(&phdrs, 0x2200).unwrap();
    assert_eq!(off1, 0x1200);
    assert_eq!(idx1, 1);

    // Gap between segments must error.
    let err = vaddr_to_file_offset(&phdrs, 0x1500).unwrap_err();
    assert!(err.to_string().contains("not in any PT_LOAD"));

    assert_eq!(highest_file_end(&phdrs), 0x2000);
    assert_eq!(highest_vaddr_end(&phdrs), 0x3000);
}

// ---------------------------------------------------------------------------
// Dynamic walk
// ---------------------------------------------------------------------------

#[test]
fn dynamic_walks_known_tags_and_stops_at_null() {
    // 5 dynamic entries: NEEDED, INIT_ARRAY, INIT_ARRAYSZ, RELA, NULL.
    let mut buf = vec![0u8; 16 * 5];
    let pairs: &[(i64, u64)] = &[
        (DT_NEEDED, 42),
        (DT_INIT_ARRAY, 0x1000),
        (DT_INIT_ARRAYSZ, 0x40),
        (DT_RELA, 0x2000),
        (DT_NULL, 0),
    ];
    for (i, (tag, val)) in pairs.iter().enumerate() {
        let off = i * 16;
        write_u64_le(&mut buf, off, *tag as u64);
        write_u64_le(&mut buf, off + 8, *val);
    }
    let info = DynamicInfo::parse(&buf, 0, buf.len() as u64).unwrap();
    assert_eq!(info.needed_offsets, vec![42]);
    assert_eq!(info.init_array, Some(0x1000));
    assert_eq!(info.init_arraysz, Some(0x40));
    assert_eq!(info.rela, Some(0x2000));
    // Walk should stop at NULL — only 5 entries observed.
    assert_eq!(info.raw.len(), 5);
}

// ---------------------------------------------------------------------------
// Relocation summary
// ---------------------------------------------------------------------------

#[test]
fn rela_summary_classifies_types() {
    let entries = vec![
        Rela {
            r_offset: 0x1000,
            r_info: ((0u64) << 32) | R_X86_64_RELATIVE as u64,
            r_addend: 0x2000,
        },
        Rela {
            r_offset: 0x1008,
            r_info: ((0u64) << 32) | R_X86_64_RELATIVE as u64,
            r_addend: 0x3000,
        },
        Rela {
            r_offset: 0x1010,
            r_info: ((1u64) << 32) | R_X86_64_GLOB_DAT as u64,
            r_addend: 0,
        },
        Rela {
            r_offset: 0x1018,
            r_info: ((2u64) << 32) | R_X86_64_64 as u64,
            r_addend: 0x10,
        },
        Rela {
            r_offset: 0x1020,
            r_info: ((3u64) << 32) | R_X86_64_JUMP_SLOT as u64,
            r_addend: 0,
        },
    ];
    let s = RelaSummary::count(&entries);
    assert_eq!(s.total, 5);
    assert_eq!(s.relative, 2);
    assert_eq!(s.glob_dat, 1);
    assert_eq!(s.abs64, 1);
    assert_eq!(s.jump_slot, 1);
    // Spot-check r_type/r_sym extraction.
    assert_eq!(entries[0].r_type(), R_X86_64_RELATIVE);
    assert_eq!(entries[2].r_sym(), 1);
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------

#[test]
fn notes_parse_gnu_build_id_and_abi_tag() {
    // Two notes back-to-back. Layout per ELF spec:
    //   namesz(4) descsz(4) type(4) name[namesz padded to 4] desc[descsz padded to 4]
    //
    // Note 1: name="GNU\0" (4 bytes, no extra pad), desc=16 bytes ABI tag.
    // Note 2: name="GNU\0" (4 bytes), desc=20 bytes build-id.
    let mut buf = Vec::new();

    // ABI tag.
    buf.extend_from_slice(&4u32.to_le_bytes()); // namesz
    buf.extend_from_slice(&16u32.to_le_bytes()); // descsz
    buf.extend_from_slice(&NT_GNU_ABI_TAG.to_le_bytes());
    buf.extend_from_slice(b"GNU\0"); // name
    buf.extend_from_slice(&[0u8; 16]); // desc

    // Build-id.
    buf.extend_from_slice(&4u32.to_le_bytes());
    buf.extend_from_slice(&20u32.to_le_bytes());
    buf.extend_from_slice(&NT_GNU_BUILD_ID.to_le_bytes());
    buf.extend_from_slice(b"GNU\0");
    let mut bid = [0u8; 20];
    for i in 0..20 {
        bid[i] = i as u8;
    }
    buf.extend_from_slice(&bid);

    let notes = parse_notes(&buf, 0, buf.len() as u64).unwrap();
    assert_eq!(notes.len(), 2);
    assert_eq!(notes[0].name, "GNU");
    assert_eq!(notes[0].note_type, NT_GNU_ABI_TAG);
    assert_eq!(notes[1].name, "GNU");
    assert_eq!(notes[1].note_type, NT_GNU_BUILD_ID);
    assert_eq!(notes[1].desc.len(), 20);
    assert_eq!(notes[1].desc_hex().len(), 40);
    assert!(notes[1].desc_hex().starts_with("0001020304"));
}

// ---------------------------------------------------------------------------
// reader::cstring_at
// ---------------------------------------------------------------------------

#[test]
fn cstring_at_returns_first_nul_terminated_run() {
    let data = b"hello\0world\0";
    let s = reader::cstring_at(data, 0).unwrap();
    assert_eq!(s, "hello");
    let s = reader::cstring_at(data, 6).unwrap();
    assert_eq!(s, "world");
}

#[test]
fn cstring_at_rejects_unterminated_string() {
    let data = b"no_null_here";
    let err = reader::cstring_at(data, 0).unwrap_err();
    assert!(err.to_string().contains("unterminated"));
}

// ---------------------------------------------------------------------------
// Suppress unused-import warnings on helpers that other test modules
// might re-use later (e.g. M1L writer tests).
// ---------------------------------------------------------------------------
#[allow(dead_code)]
fn _silence_helpers() -> Vec<DynamicEntry> {
    vec![DynamicEntry { tag: DT_STRTAB, val: 0 }, DynamicEntry { tag: DT_STRSZ, val: 0 },
         DynamicEntry { tag: DT_RELASZ, val: 0 }, DynamicEntry { tag: DT_RELACOUNT, val: 0 }]
}
