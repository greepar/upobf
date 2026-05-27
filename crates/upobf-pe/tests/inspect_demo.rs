//! Integration tests against the real demo PE.
//!
//! These tests are skipped automatically if `demo/PatchInstaller.exe` is not
//! present (so CI machines without the corpus stay green).

use std::path::PathBuf;

use upobf_pe::PeImage;

fn demo_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("demo")
        .join("PatchInstaller.exe")
}

#[test]
fn inspect_patch_installer_matches_baseline() {
    let path = demo_path();
    if !path.exists() {
        eprintln!(
            "demo PE not found at {}, skipping integration test",
            path.display()
        );
        return;
    }

    let image = PeImage::from_file(&path).expect("parse demo PE");

    // ---- Header level ----
    assert_eq!(image.dos.e_magic, 0x5A4D, "DOS magic");
    assert_eq!(image.dos.e_lfanew, 0x138, "e_lfanew");
    assert_eq!(image.nt.signature, 0x0000_4550, "PE signature");
    assert_eq!(image.nt.file_header.machine, 0x8664, "machine x64");
    assert_eq!(image.nt.file_header.number_of_sections, 7);
    assert_eq!(image.nt.file_header.time_date_stamp, 0x6A16_6042);
    assert_eq!(image.nt.optional_header.major_linker_version, 14);
    assert_eq!(image.nt.optional_header.minor_linker_version, 50);
    assert_eq!(image.nt.optional_header.magic, 0x020B, "PE32+");

    // ---- Spec headline values ----
    assert_eq!(image.nt.optional_header.address_of_entry_point, 0x0178_3E10);
    assert_eq!(image.nt.optional_header.image_base, 0x1_4000_0000);
    assert_eq!(image.nt.optional_header.subsystem, 2, "Windows GUI");
    assert_eq!(image.nt.optional_header.dll_characteristics, 0x8160);
    assert_eq!(image.nt.optional_header.size_of_image, 0x02B2_C000);
    assert_eq!(image.nt.optional_header.size_of_headers, 0x400);
    assert_eq!(image.nt.optional_header.section_alignment, 0x1000);
    assert_eq!(image.nt.optional_header.file_alignment, 0x200);
    assert_eq!(image.nt.optional_header.size_of_stack_reserve, 0x180000);
    assert_eq!(image.nt.optional_header.size_of_heap_reserve, 0x100000);
    assert_eq!(image.nt.optional_header.number_of_rva_and_sizes, 16);

    // ---- Sections ----
    assert_eq!(image.sections.len(), 7);
    let names: Vec<_> = image.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        vec![".text", ".rdata", ".data", ".pdata", "_RDATA", ".rsrc", ".reloc"]
    );

    // ---- DataDirectory baselines ----
    let dd = &image.data_dirs;
    // [3] Exception (.pdata)
    assert_eq!(dd[3].virtual_address, 0x028D_0000);
    assert_eq!(dd[3].size, 1_264_896);
    // [9] TLS
    assert_eq!(dd[9].virtual_address, 0x0240_0800);
    assert_eq!(dd[9].size, 40);
    // [10] LoadConfig
    assert_eq!(dd[10].virtual_address, 0x0240_04C0);
    assert_eq!(dd[10].size, 320);
    // [12] IAT
    assert_eq!(dd[12].virtual_address, 0x017A_A000);
    assert_eq!(dd[12].size, 4384);
    // [13] DelayImport - absent
    assert_eq!(dd[13].virtual_address, 0);
    assert_eq!(dd[13].size, 0);
    // [14] CLR/COM - absent (confirms NativeAOT, not managed CLR header)
    assert_eq!(dd[14].virtual_address, 0);
    assert_eq!(dd[14].size, 0);

    // ---- TLS callbacks ----
    let tls = image.tls.as_ref().expect("TLS directory present");
    assert_eq!(tls.callbacks.len(), 1, "exactly one TLS callback");
    assert_eq!(tls.callbacks[0], 0x0178_4470, "callback[0] RVA");
    assert_eq!(tls.callbacks_va, 0x1_417A_BDD8);
    assert_eq!(tls.start_va, 0x1_4240_94F0);
    assert_eq!(tls.end_va, 0x1_4240_966D);
    assert_eq!(tls.index_va, 0x1_428C_E810);

    // ---- LoadConfig basics ----
    let lc = image.load_config.as_ref().expect("LoadConfig present");
    assert_eq!(lc.size, 320);

    // ---- Imports ----
    assert_eq!(image.imports.dlls.len(), 25, "25 statically-linked DLLs");
    let dll_names: Vec<&str> = image
        .imports
        .dlls
        .iter()
        .map(|d| d.name.as_str())
        .collect();
    let expected_subset = [
        "KERNEL32.dll",
        "ADVAPI32.dll",
        "USER32.dll",
        "ole32.dll",
        "OLEAUT32.dll",
        "Secur32.dll",
        "bcrypt.dll",
        "ncrypt.dll",
        "CRYPT32.dll",
        "WS2_32.dll",
        "IPHLPAPI.DLL",
    ];
    for needle in expected_subset {
        assert!(
            dll_names.contains(&needle),
            "expected DLL '{}' in imports list, got {:?}",
            needle,
            dll_names
        );
    }
    let api_ms_count = dll_names
        .iter()
        .filter(|n| n.starts_with("api-ms-win-"))
        .count();
    assert!(
        api_ms_count >= 11,
        "expected at least 11 api-ms-win-* DLLs, got {}",
        api_ms_count
    );

    // No delay imports.
    assert!(image.delay_imports.dlls.is_empty());
}

#[test]
fn json_report_round_trips_for_demo() {
    let path = demo_path();
    if !path.exists() {
        return;
    }
    let image = PeImage::from_file(&path).expect("parse demo PE");
    let s = image.to_json_report().expect("json report");
    // Sanity: it must be parseable JSON and contain a few headline fields.
    let v: serde_json::Value = serde_json::from_str(&s).expect("valid json");
    assert_eq!(v["optional_header"]["address_of_entry_point"], 0x0178_3E10);
    assert_eq!(v["optional_header"]["image_base"], 0x1_4000_0000_u64);
    assert_eq!(v["sections"].as_array().unwrap().len(), 7);
    assert_eq!(v["imports"]["dlls"].as_array().unwrap().len(), 25);
}
