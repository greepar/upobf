//! M1L writer integration test against `Demo/PatchInstaller`.
//!
//! Exercises the passthrough writer in three layered configurations:
//!   1. No stub, no payload (baseline phdr relocation only).
//!   2. With a fake stub blob.
//!   3. With a fake stub blob + payload + init_array injection.
//!
//! For each, we assert that the resulting bytes still parse cleanly
//! through `ElfImage::from_bytes` and that key invariants hold:
//! e_entry unchanged, original phdr count + new entries, init_array
//! correctly redirected when injection is enabled.

use std::path::PathBuf;

use upobf_elf::{
    build::PackedElfBuilder,
    parse::headers::PT_LOAD,
    ElfImage,
};

fn demo_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("Demo");
    p.push("PatchInstaller");
    p
}

#[test]
fn passthrough_round_trips_demo() {
    let path = demo_path();
    if !path.exists() {
        eprintln!("skipping: demo not present");
        return;
    }
    let img = ElfImage::from_file(&path).unwrap();
    let bytes = PackedElfBuilder::new(&img).build().unwrap();

    // Re-parse the output to confirm structural validity.
    let out = ElfImage::from_bytes(bytes.clone()).expect("packed re-parses");

    // e_entry must not move.
    assert_eq!(out.ehdr.e_entry, img.ehdr.e_entry);

    // PT_PHDR must point inside the new .upobf0 LOAD region.
    // Post-shrink, .upobf0 sits after the host's repacked LOAD
    // segments at the highest vaddr; we just confirm the new
    // PT_PHDR vaddr exceeds every original LOAD's vaddr+memsz.
    let new_phdr = out
        .phdrs
        .iter()
        .find(|p| p.p_type == upobf_elf::parse::headers::PT_PHDR)
        .expect("PT_PHDR present");
    let max_orig_load_end = img
        .phdrs
        .iter()
        .filter(|p| p.p_type == PT_LOAD)
        .map(|p| p.p_vaddr + p.p_memsz)
        .max()
        .unwrap();
    assert!(
        new_phdr.p_vaddr >= max_orig_load_end,
        "PT_PHDR vaddr {:#x} should be past the highest original LOAD end {:#x}",
        new_phdr.p_vaddr,
        max_orig_load_end,
    );

    // Original LOAD count + 1 new (.upobf0).
    let orig_loads = img.phdrs.iter().filter(|p| p.p_type == PT_LOAD).count();
    let new_loads = out.phdrs.iter().filter(|p| p.p_type == PT_LOAD).count();
    assert_eq!(new_loads, orig_loads + 1);

    // Dynamic section content unchanged (no injection requested).
    let orig_dyn = img.dynamic.as_ref().unwrap();
    let new_dyn = out.dynamic.as_ref().unwrap();
    assert_eq!(new_dyn.init_array, orig_dyn.init_array);
    assert_eq!(new_dyn.init_arraysz, orig_dyn.init_arraysz);
}

#[test]
fn passthrough_with_stub_appends_upobf0_with_stub_bytes() {
    let path = demo_path();
    if !path.exists() {
        return;
    }
    let img = ElfImage::from_file(&path).unwrap();
    let stub = vec![0xCCu8; 256]; // fake stub: 256 int3 bytes
    let bytes = PackedElfBuilder::new(&img)
        .with_stub(stub.clone(), 0)
        .build()
        .unwrap();

    let out = ElfImage::from_bytes(bytes.clone()).unwrap();
    // .upobf0 is the R+X PT_LOAD we appended (no .upobf2 without
    // injection, no .upobf1 without payload).
    use upobf_elf::parse::headers::{PF_R, PF_X};
    let upobf0 = out
        .phdrs
        .iter()
        .filter(|p| p.p_type == PT_LOAD && p.p_flags == PF_R | PF_X)
        .last()
        .unwrap();

    // Verify stub bytes are present at upobf0_off + PHDR_TABLE_RESERVE.
    let stub_off = (upobf0.p_offset + upobf_elf::build::writer::PHDR_TABLE_RESERVE) as usize;
    assert_eq!(
        &bytes[stub_off..stub_off + stub.len()],
        &stub[..],
        "stub bytes must be at upobf0+PHDR_TABLE_RESERVE"
    );
}

#[test]
fn injection_redirects_init_array_to_upobf2() {
    let path = demo_path();
    if !path.exists() {
        return;
    }
    let img = ElfImage::from_file(&path).unwrap();
    let stub = vec![0x90u8; 1024]; // fake stub: 1 KiB of NOPs
    // stub_init_offset = 0 means the init function lives right at the
    // start of the stub region. The packer writes (.upobf0 vaddr +
    // PHDR_TABLE_RESERVE + 0) into init_array slot 0.
    let bytes = PackedElfBuilder::new(&img)
        .with_stub(stub, 0)
        .enable_init_array_injection(true)
        .build()
        .unwrap();

    let out = ElfImage::from_bytes(bytes.clone()).unwrap();
    let dyn_info = out.dynamic.as_ref().unwrap();

    // Original init_array had 6 entries (48 bytes); our rebuilt one
    // adds 1 slot at the front -> 56 bytes.
    let orig_size = img.dynamic.as_ref().unwrap().init_arraysz.unwrap();
    assert_eq!(dyn_info.init_arraysz, Some(orig_size + 8));

    // Find .upobf2: the LOAD segment marked R+W appended after the
    // R+X .upobf0 segment. The new init_array vaddr should lie inside.
    use upobf_elf::parse::headers::{PF_R, PF_W, PF_X};
    let new_init_va = dyn_info.init_array.unwrap();
    let upobf2 = out
        .phdrs
        .iter()
        .filter(|p| p.p_type == PT_LOAD && p.p_flags == PF_R | PF_W)
        .last()
        .expect(".upobf2 (R+W) must be present");
    assert!(
        new_init_va >= upobf2.p_vaddr
            && new_init_va < upobf2.p_vaddr + upobf2.p_memsz,
        "new init_array vaddr {:#x} must lie inside .upobf2 [{:#x}..{:#x})",
        new_init_va,
        upobf2.p_vaddr,
        upobf2.p_vaddr + upobf2.p_memsz
    );
    let _ = (PF_R, PF_X); // imports used in this test elsewhere

    // Read the slot 0 contents from the packed bytes — should equal
    // (.upobf0 vaddr + PHDR_TABLE_RESERVE + stub_init_offset = 0).
    let init_file_off = upobf_elf::parse::segments::vaddr_to_file_offset(
        &out.phdrs,
        new_init_va,
    )
    .unwrap()
    .0 as usize;
    let slot0 = u64::from_le_bytes(
        bytes[init_file_off..init_file_off + 8].try_into().unwrap(),
    );
    // upobf0 is the R+X LOAD segment.
    let upobf0 = out
        .phdrs
        .iter()
        .filter(|p| p.p_type == PT_LOAD && p.p_flags == PF_R | PF_X)
        .last()
        .unwrap();
    let expected = upobf0.p_vaddr + upobf_elf::build::writer::PHDR_TABLE_RESERVE;
    assert_eq!(slot0, expected, "slot 0 must point at stub init function");
}

#[test]
fn payload_segment_is_appended_when_provided() {
    let path = demo_path();
    if !path.exists() {
        return;
    }
    let img = ElfImage::from_file(&path).unwrap();
    let payload: Vec<u8> = (0..1024u32).map(|x| (x & 0xFF) as u8).collect();
    let bytes = PackedElfBuilder::new(&img)
        .with_stub(vec![0x90u8; 64], 0)
        .with_payload(payload.clone())
        .build()
        .unwrap();

    let out = ElfImage::from_bytes(bytes.clone()).unwrap();

    // Original LOAD + 2 new ones (.upobf0 / .upobf1) when injection
    // is disabled (no .upobf2).
    let new_loads = out
        .phdrs
        .iter()
        .filter(|p| p.p_type == PT_LOAD)
        .count();
    let orig_loads = img.phdrs.iter().filter(|p| p.p_type == PT_LOAD).count();
    assert_eq!(new_loads, orig_loads + 2);

    // The trailing PT_LOAD .upobf1 (R-only) should host the payload
    // bytes verbatim at its file offset. The writer always sets
    // p_filesz = upobf1_size (page-aligned) and zero-pads the
    // tail; check that payload bytes match in the prefix.
    use upobf_elf::parse::headers::PF_R;
    let upobf1 = out
        .phdrs
        .iter()
        .filter(|p| p.p_type == PT_LOAD && p.p_flags == PF_R)
        .last()
        .unwrap();
    assert!(upobf1.p_filesz >= payload.len() as u64);
    assert_eq!(upobf1.p_filesz % 0x1000, 0, "filesz must be page-aligned");
    let off = upobf1.p_offset as usize;
    assert_eq!(&bytes[off..off + payload.len()], &payload[..]);
    // Tail padding must be zero.
    assert!(bytes[off + payload.len()..off + upobf1.p_filesz as usize]
        .iter()
        .all(|&b| b == 0));
}
