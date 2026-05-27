//! Integration test against the bundled `Demo/PatchInstaller`
//! (NativeAOT Avalonia build, ET_DYN/PIE, glibc).
//!
//! Locks in the exact field counts we read from the demo so a
//! parser regression in any one module is detected immediately.
//!
//! These numbers were cross-referenced against `readelf -hldS` and
//! `readelf -r --dynamic` on the same binary in the M0L bringup
//! session.

use std::path::PathBuf;

use upobf_elf::ElfImage;

fn demo_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("Demo");
    p.push("PatchInstaller");
    p
}

#[test]
fn inspect_demo_matches_baseline() {
    let path = demo_path();
    if !path.exists() {
        // Demo binary not present (e.g. cargo publish env). Skip
        // rather than fail the build.
        eprintln!(
            "skipping: demo binary not found at {} — set up Demo/ to enable",
            path.display()
        );
        return;
    }
    let img = ElfImage::from_file(&path).expect("parse demo");

    // ---- Ehdr ----
    assert!(img.is_pie(), "demo is built as ET_DYN/PIE");
    assert_eq!(img.ehdr.e_machine, upobf_elf::parse::headers::EM_X86_64);
    assert_eq!(img.ehdr.e_entry, 0xF8BAC0);
    assert_eq!(img.ehdr.e_phnum, 12);
    assert_eq!(img.ehdr.e_shnum, 38);

    // ---- Phdrs ----
    let load_count = img
        .phdrs
        .iter()
        .filter(|p| p.p_type == upobf_elf::parse::headers::PT_LOAD)
        .count();
    assert_eq!(load_count, 4, "expect 4 LOAD segments (R, RX, RW, RW)");

    // ---- Shdrs ----
    assert!(img.section(".text").is_some());
    assert!(img.section(".rodata").is_some());
    assert!(img.section(".init_array").is_some());
    assert!(img.section(".dynamic").is_some());
    assert!(img.section(".eh_frame_hdr").is_some());
    assert!(img.section(".eh_frame").is_some());

    // ---- Dynamic ----
    let dyn_info = img.dynamic.as_ref().expect("PT_DYNAMIC present");
    assert_eq!(dyn_info.raw.len(), 33);
    assert_eq!(dyn_info.init_array, Some(0x232C040));
    assert_eq!(dyn_info.init_arraysz, Some(0x30)); // 6 * 8 bytes
    assert!(dyn_info.rela.is_some());

    // ---- DT_NEEDED ----
    assert_eq!(img.needed.len(), 5);
    assert!(img.needed.iter().any(|n| n == "libc.so.6"));
    assert!(img.needed.iter().any(|n| n == "ld-linux-x86-64.so.2"));

    // ---- Relocations ----
    assert_eq!(img.rela_dyn.len(), 20566);
    assert_eq!(img.rela_dyn_summary.relative, 19471); // matches DT_RELACOUNT
    assert_eq!(img.rela_dyn_summary.glob_dat, 16);
    assert_eq!(img.rela_dyn_summary.abs64, 1079);

    assert_eq!(img.rela_plt.len(), 389);
    assert_eq!(img.rela_plt_summary.jump_slot, 389);

    // ---- DynSym ----
    assert_eq!(img.dynsym.len(), 414);

    // ---- eh_frame_hdr ----
    let eh = img.eh_frame_hdr.as_ref().expect(".eh_frame_hdr present");
    assert_eq!(eh.version, 1);
    assert_eq!(eh.size, 0xA4FAC);

    // ---- Notes ----
    assert!(img.notes.iter().any(
        |n| n.note_type == upobf_elf::parse::notes::NT_GNU_BUILD_ID && n.desc.len() == 20
    ));
}

#[test]
fn json_report_round_trips_for_demo() {
    let path = demo_path();
    if !path.exists() {
        return;
    }
    let img = ElfImage::from_file(&path).expect("parse demo");
    let json = img.to_json_report().expect("serialise");
    let v: serde_json::Value = serde_json::from_str(&json).expect("parse roundtrip");
    assert_eq!(v["header"]["is_pie"], serde_json::Value::Bool(true));
    assert!(v["needed"].as_array().unwrap().len() >= 4);
    assert_eq!(v["phdrs"].as_array().unwrap().len(), 12);
}
