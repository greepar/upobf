//! M3 stub_link integration tests.
//!
//! Test 1 hand-builds a tiny COFF object so the parser is exercised
//! without requiring the stub toolchain.
//! Test 2 consumes `stubs/pe-x64/build/*.obj` if those files have been
//! produced by `stubs/pe-x64/build.ps1`. When they are absent (e.g. in
//! a CI environment without clang), the test logs a notice and exits
//! cleanly so `cargo test` stays green.
//! Test 3 covers a couple of malformed-COFF rejections.

use byteorder::{ByteOrder, LittleEndian};
use std::path::{Path, PathBuf};

use upobf_core::stub_link::{
    self, parse_coff, CoffRelocKind, FixupTarget, IMAGE_FILE_MACHINE_AMD64, SYM_ORIGINAL_OEP,
    SYM_ORIGINAL_TLS_CALLBACK, SYM_PAYLOAD_BLOB, SYM_STUB_SELF_RVA, SYM_TLS_CALLBACK,
};

// -------------------------------------------------------------------------
// Hand-rolled COFF object builder (test-only).
// -------------------------------------------------------------------------

const COFF_FILE_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;
const SYMBOL_RECORD_SIZE: usize = 18;
const RELOCATION_SIZE: usize = 10;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

/// Build a minimal x64 COFF object with one `.text` section and a
/// single `IMAGE_REL_AMD64_REL32` relocation against an external
/// symbol `__upobf_original_oep`. The text body is:
///   48 8B 05 00 00 00 00   mov rax, [rip+0]   ; reloc patches the disp32
///   C3                     ret
/// The defined entry symbol is `upobf_stub_tls_callback` at offset 0.
fn build_minimal_coff() -> Vec<u8> {
    let text: [u8; 8] = [0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3];

    // Symbol table layout (no aux records, all names short):
    //   [0] .text        static, sec=1
    //   [1] upobf_stub_tls_callback   external, sec=1, value=0
    //   [2] __upobf_original_oep      external, sec=0  (undefined)
    let symbol_count: u32 = 3;
    let strings_payload: Vec<u8> = {
        let mut s = Vec::new();
        // upobf_stub_tls_callback (>8 bytes) goes via the string table.
        s.extend_from_slice(b"upobf_stub_tls_callback\0");
        // __upobf_original_oep is exactly 20 bytes - also longer than 8.
        s.extend_from_slice(b"__upobf_original_oep\0");
        s
    };
    let str_off_callback: u32 = 4; // skip the 4-byte length prefix
    let str_off_oep: u32 = 4 + b"upobf_stub_tls_callback\0".len() as u32;

    let header_size = COFF_FILE_HEADER_SIZE + SECTION_HEADER_SIZE;
    let raw_data_off = header_size;
    let reloc_off = raw_data_off + text.len();
    let symtab_off = reloc_off + RELOCATION_SIZE;
    let strtab_off = symtab_off + (symbol_count as usize) * SYMBOL_RECORD_SIZE;
    let strtab_size = 4 + strings_payload.len() as u32;

    let total = strtab_off + strtab_size as usize;
    let mut out = vec![0u8; total];

    // ---- File header
    LittleEndian::write_u16(&mut out[0..2], 0x8664); // Machine = AMD64
    LittleEndian::write_u16(&mut out[2..4], 1); // NumberOfSections
    LittleEndian::write_u32(&mut out[4..8], 0); // TimeDateStamp
    LittleEndian::write_u32(&mut out[8..12], symtab_off as u32);
    LittleEndian::write_u32(&mut out[12..16], symbol_count);
    LittleEndian::write_u16(&mut out[16..18], 0); // OptionalHeaderSize
    LittleEndian::write_u16(&mut out[18..20], 0); // Characteristics

    // ---- Section header (.text)
    let sh = &mut out[COFF_FILE_HEADER_SIZE..COFF_FILE_HEADER_SIZE + SECTION_HEADER_SIZE];
    sh[..8].copy_from_slice(b".text\0\0\0");
    LittleEndian::write_u32(&mut sh[8..12], 0); // VirtualSize
    LittleEndian::write_u32(&mut sh[12..16], 0); // VirtualAddress
    LittleEndian::write_u32(&mut sh[16..20], text.len() as u32); // SizeOfRawData
    LittleEndian::write_u32(&mut sh[20..24], raw_data_off as u32);
    LittleEndian::write_u32(&mut sh[24..28], reloc_off as u32);
    LittleEndian::write_u32(&mut sh[28..32], 0);
    LittleEndian::write_u16(&mut sh[32..34], 1); // RelocationCount
    LittleEndian::write_u16(&mut sh[34..36], 0);
    LittleEndian::write_u32(
        &mut sh[36..40],
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    );

    // ---- Section raw data
    out[raw_data_off..raw_data_off + text.len()].copy_from_slice(&text);

    // ---- Relocation: AMD64_REL32 @ offset 3 (the disp32 of the mov)
    //                 -> symbol index 2 (__upobf_original_oep)
    let rel = &mut out[reloc_off..reloc_off + RELOCATION_SIZE];
    LittleEndian::write_u32(&mut rel[0..4], 3); // VirtualAddress
    LittleEndian::write_u32(&mut rel[4..8], 2); // SymbolTableIndex
    LittleEndian::write_u16(&mut rel[8..10], 4); // Type = IMAGE_REL_AMD64_REL32

    // ---- Symbol table
    // [0] .text (static)
    let s0 = &mut out[symtab_off..symtab_off + SYMBOL_RECORD_SIZE];
    s0[0..8].copy_from_slice(b".text\0\0\0");
    LittleEndian::write_u32(&mut s0[8..12], 0); // Value
    LittleEndian::write_i16(&mut s0[12..14], 1); // SectionNumber
    LittleEndian::write_u16(&mut s0[14..16], 0); // Type
    s0[16] = 3; // StorageClass = STATIC
    s0[17] = 0; // NumberOfAuxSymbols

    // [1] upobf_stub_tls_callback (external) -> string table
    let s1_off = symtab_off + SYMBOL_RECORD_SIZE;
    let s1 = &mut out[s1_off..s1_off + SYMBOL_RECORD_SIZE];
    LittleEndian::write_u32(&mut s1[0..4], 0); // Zeroes
    LittleEndian::write_u32(&mut s1[4..8], str_off_callback);
    LittleEndian::write_u32(&mut s1[8..12], 0); // Value
    LittleEndian::write_i16(&mut s1[12..14], 1); // SectionNumber
    LittleEndian::write_u16(&mut s1[14..16], 0x20); // Type=DT_FUNCTION (purely cosmetic)
    s1[16] = 2; // StorageClass = EXTERNAL
    s1[17] = 0;

    // [2] __upobf_original_oep (external, undefined)
    let s2_off = s1_off + SYMBOL_RECORD_SIZE;
    let s2 = &mut out[s2_off..s2_off + SYMBOL_RECORD_SIZE];
    LittleEndian::write_u32(&mut s2[0..4], 0);
    LittleEndian::write_u32(&mut s2[4..8], str_off_oep);
    LittleEndian::write_u32(&mut s2[8..12], 0);
    LittleEndian::write_i16(&mut s2[12..14], 0); // Undefined
    LittleEndian::write_u16(&mut s2[14..16], 0);
    s2[16] = 2;
    s2[17] = 0;

    // ---- String table: u32 length + payload
    LittleEndian::write_u32(&mut out[strtab_off..strtab_off + 4], strtab_size);
    out[strtab_off + 4..strtab_off + strtab_size as usize].copy_from_slice(&strings_payload);

    out
}

// -------------------------------------------------------------------------
// Test 1: parse a minimal hand-built COFF.
// -------------------------------------------------------------------------

#[test]
fn parse_minimal_coff_object() {
    let bytes = build_minimal_coff();
    let obj = parse_coff(&bytes).expect("parse minimal coff");

    assert_eq!(obj.file_header.machine, IMAGE_FILE_MACHINE_AMD64);
    assert_eq!(obj.file_header.number_of_sections, 1);
    assert_eq!(obj.sections.len(), 1);

    let sec = &obj.sections[0];
    assert_eq!(sec.name, ".text");
    assert_eq!(sec.data.len(), 8);
    assert_eq!(sec.relocations.len(), 1);

    let r = &sec.relocations[0];
    assert_eq!(r.virtual_address, 3);
    assert_eq!(r.kind, CoffRelocKind::Amd64Rel32);

    // Symbol table sanity.
    let names: Vec<&str> = obj.symbols.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&".text"));
    assert!(names.contains(&"upobf_stub_tls_callback"));
    assert!(names.contains(&"__upobf_original_oep"));
}

// -------------------------------------------------------------------------
// Test 2: link the real stub objects if they exist.
// -------------------------------------------------------------------------

fn stub_build_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/upobf-core; walk up two levels.
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(Path::parent)
        .map(|workspace| workspace.join("stubs").join("pe-x64").join("build"))
        .expect("workspace root")
}

#[test]
fn link_real_stub_objects_if_present() {
    let dir = stub_build_dir();
    if !dir.exists() {
        eprintln!(
            "skipping: stub build dir not found ({}); run stubs/pe-x64/build.ps1 first",
            dir.display()
        );
        return;
    }

    let mut obj_paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("read stub build dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("obj"))
                .unwrap_or(false)
        })
        .collect();
    obj_paths.sort();

    if obj_paths.is_empty() {
        eprintln!(
            "skipping: no .obj files under {}; run stubs/pe-x64/build.ps1 first",
            dir.display()
        );
        return;
    }

    let mut objects = Vec::with_capacity(obj_paths.len());
    for path in &obj_paths {
        let bytes = std::fs::read(path).expect("read .obj");
        let obj = parse_coff(&bytes)
            .unwrap_or_else(|e| panic!("parse {}: {:?}", path.display(), e));
        assert_eq!(obj.file_header.machine, IMAGE_FILE_MACHINE_AMD64);
        objects.push(obj);
    }

    let linked = stub_link::link(&objects).expect("link stub");

    assert!(!linked.text.is_empty(), "linked stub has empty text");
    assert!(
        (linked.tls_callback_offset as usize) < linked.text.len(),
        "tls_callback_offset {:#x} out of stub bounds {:#x}",
        linked.tls_callback_offset,
        linked.text.len()
    );
    // The TLS callback must coincide with the address recorded for the
    // exported symbol.
    let recorded = linked
        .local_symbols
        .get(SYM_TLS_CALLBACK)
        .copied()
        .expect("TLS callback symbol present");
    assert_eq!(recorded, linked.tls_callback_offset);

    // We expect at least one PayloadBlob and one StubSelfRva fixup,
    // since entry.c references both.  (M4-Stub no longer references
    // OriginalOep — the OS Loader still walks to OEP naturally.)
    let payload_fixups: Vec<_> = linked
        .abs_fixups
        .iter()
        .filter(|f| matches!(f.target, FixupTarget::PayloadBlobVa))
        .collect();
    assert!(
        !payload_fixups.is_empty(),
        "expected at least one PayloadBlobVa fixup"
    );
    let stub_self_fixups: Vec<_> = linked
        .abs_fixups
        .iter()
        .filter(|f| matches!(f.target, FixupTarget::StubSelfRva))
        .collect();
    assert!(
        !stub_self_fixups.is_empty(),
        "expected at least one StubSelfRva fixup"
    );
    for f in payload_fixups.iter().chain(stub_self_fixups.iter()) {
        assert!(
            (f.offset as usize) + (f.width as usize) <= linked.text.len(),
            "fixup site OOB"
        );
        assert!(f.width == 4 || f.width == 8, "unexpected fixup width {}", f.width);
    }

    // Each external symbol the stub needs must be declared so the packer
    // knows what to fill in.
    for required in [
        SYM_PAYLOAD_BLOB,
        SYM_STUB_SELF_RVA,
        SYM_ORIGINAL_TLS_CALLBACK,
    ] {
        assert!(
            linked
                .external_symbols
                .iter()
                .any(|e| e.name == required),
            "missing external symbol declaration: {}",
            required
        );
    }
    // OriginalOep is *not* expected for the M4 stub.
    let _ = SYM_ORIGINAL_OEP;
}

// -------------------------------------------------------------------------
// Test 3: malformed COFF rejection.
// -------------------------------------------------------------------------

#[test]
fn rejects_wrong_machine() {
    let mut bytes = build_minimal_coff();
    LittleEndian::write_u16(&mut bytes[0..2], 0x014C); // i386
    let err = parse_coff(&bytes).expect_err("must reject non-AMD64");
    assert!(
        err.to_string().to_lowercase().contains("amd64")
            || err.to_string().contains("0x014c"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn rejects_implausible_section_count() {
    let mut bytes = build_minimal_coff();
    LittleEndian::write_u16(&mut bytes[2..4], 9999);
    let err = parse_coff(&bytes).expect_err("must reject huge NumberOfSections");
    let msg = err.to_string();
    assert!(
        msg.contains("NumberOfSections") || msg.contains("9999") || msg.contains("implausible"),
        "unexpected error: {}",
        msg
    );
}

#[test]
fn rejects_truncated_file() {
    let bytes = vec![0u8; 4];
    let err = parse_coff(&bytes).expect_err("must reject tiny input");
    assert!(err.to_string().contains("too small"), "got: {}", err);
}
