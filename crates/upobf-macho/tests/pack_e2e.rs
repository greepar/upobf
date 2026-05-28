//! Integration test: end-to-end pack of PatchInstaller.

use anyhow::Result;
use std::path::Path;
use upobf_macho::pack::{pack_macho, PackConfig};
use upobf_macho::parse::MachoImage;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/PatchInstaller.app/Contents/MacOS/PatchInstaller"
);

#[test]
fn pack_patch_installer_e2e() -> Result<()> {
    let config = PackConfig::default();
    let result = pack_macho(Path::new(FIXTURE), &config)?;

    println!("=== Pack Result ===");
    println!("  Original size: {} bytes ({:.1} MB)", result.original_size, result.original_size as f64 / 1048576.0);
    println!("  Packed size:   {} bytes ({:.1} MB)", result.packed_size, result.packed_size as f64 / 1048576.0);
    println!("  Chunks:        {}", result.chunk_count);
    println!("  Compressed:    {} bytes ({:.1} MB)", result.total_compressed_bytes, result.total_compressed_bytes as f64 / 1048576.0);

    // Basic sanity checks.
    assert!(result.packed_size > 0, "output should not be empty");

    // Re-parse the output to verify it's a valid Mach-O.
    let reparsed = MachoImage::from_bytes(result.bytes.clone())?;
    assert_eq!(reparsed.header.magic, 0xFEED_FACF);
    assert_eq!(reparsed.header.cputype, 0x0100_000C);
    assert_eq!(reparsed.header.filetype, 2); // MH_EXECUTE

    // Should have __UPOBF0 segment (stub).
    let upobf0 = reparsed.segment("__UPOBF0").expect("__UPOBF0 should exist");
    println!("  __UPOBF0: vmaddr=0x{:X} fileoff=0x{:X} filesize=0x{:X}", upobf0.vmaddr, upobf0.fileoff, upobf0.filesize);
    assert_eq!(upobf0.prot_string(), "R-X");

    // LC_MAIN should point into __UPOBF0.
    let main_cmd = reparsed.main_cmd.as_ref().expect("LC_MAIN");
    let text_vmaddr = reparsed.segment("__TEXT").unwrap().vmaddr;
    let entry_va = text_vmaddr + main_cmd.entryoff;
    assert!(
        entry_va >= upobf0.vmaddr && entry_va < upobf0.vmaddr + upobf0.vmsize,
        "LC_MAIN.entryoff should point into __UPOBF0: entry_va=0x{:X}, upobf0=[0x{:X}..0x{:X})",
        entry_va, upobf0.vmaddr, upobf0.vmaddr + upobf0.vmsize
    );

    // LC_CODE_SIGNATURE should be dropped.
    assert!(reparsed.code_signature.is_none(), "LC_CODE_SIGNATURE should be dropped");

    println!("  Entry:         0x{:X} (in __UPOBF0)", main_cmd.entryoff);
    println!("=== PASS ===");
    Ok(())
}

#[test]
fn pack_entry_redirect_valid() -> Result<()> {
    let config = PackConfig::default();
    let result = pack_macho(Path::new(FIXTURE), &config)?;

    // Verify the packed binary is a valid Mach-O that can be re-parsed.
    let reparsed = MachoImage::from_bytes(result.bytes.clone())?;

    // Verify stub is present and entry points to it.
    let upobf0 = reparsed.segment("__UPOBF0").expect("__UPOBF0");
    let main_cmd = reparsed.main_cmd.as_ref().expect("LC_MAIN");
    let text_vmaddr = reparsed.segment("__TEXT").unwrap().vmaddr;
    let entry_va = text_vmaddr + main_cmd.entryoff;

    assert!(entry_va >= upobf0.vmaddr, "entry should be in __UPOBF0");
    assert!(entry_va < upobf0.vmaddr + upobf0.vmsize, "entry should be in __UPOBF0");

    // Verify the original binary's entry point is different.
    let orig = MachoImage::from_file(FIXTURE)?;
    let orig_entryoff = orig.main_cmd.as_ref().unwrap().entryoff;
    assert_ne!(main_cmd.entryoff, orig_entryoff, "entry should be redirected");

    println!("Entry redirect OK: original=0x{:X} -> packed=0x{:X}", orig_entryoff, main_cmd.entryoff);
    Ok(())
}

#[test]
fn pack_with_compression_valid_macho() -> Result<()> {
    let config = PackConfig::default();
    let result = pack_macho(Path::new(FIXTURE), &config)?;

    // Should have compressed some chunks.
    assert!(result.chunk_count > 0, "should have compressed chunks");
    assert!(result.total_compressed_bytes > 0, "should have compressed bytes");
    println!("Compressed {} chunks, {} bytes total", result.chunk_count, result.total_compressed_bytes);

    // Re-parse the output.
    let reparsed = MachoImage::from_bytes(result.bytes.clone())?;

    // Should have __UPOBF0 (stub) and __UPOBF1 (payload).
    let upobf0 = reparsed.segment("__UPOBF0").expect("__UPOBF0");
    let upobf1 = reparsed.segment("__UPOBF1").expect("__UPOBF1");
    assert_eq!(upobf0.prot_string(), "R-X");
    assert_eq!(upobf1.prot_string(), "R--");

    // __UPOBF1 should contain the compressed payload (non-trivial size).
    assert!(upobf1.filesize > 1024, "payload should be non-trivial");

    // __DATA segment should still exist with same vmsize.
    let orig = MachoImage::from_file(FIXTURE)?;
    let orig_data = orig.segment("__DATA").expect("original __DATA");
    let new_data = reparsed.segment("__DATA").expect("packed __DATA");
    assert_eq!(new_data.vmsize, orig_data.vmsize, "__DATA vmsize should be preserved");
    assert_eq!(new_data.vmaddr, orig_data.vmaddr, "__DATA vmaddr should be preserved");

    // Verify compressed regions are zeroed in the output.
    let data_fileoff = new_data.fileoff as usize;
    // .dotnet_eh_table starts at a known offset within __DATA.
    // Check that some of the compressed region is zeroed.
    let eh_table_offset_in_seg = 0xA0usize; // __objc_selrefs(0x78) + __objc_classrefs(0x28)
    let check_start = data_fileoff + eh_table_offset_in_seg + 0x4000; // skip first page (may have fixups)
    let check_end = check_start + 0x4000; // check one page
    if check_end <= result.bytes.len() {
        let zeroed = result.bytes[check_start..check_end].iter().all(|&b| b == 0);
        assert!(zeroed, "compressed region should be zeroed in output file");
    }

    println!("Compression e2e OK: {} chunks, payload={} bytes",
        result.chunk_count, upobf1.filesize);
    Ok(())
}

#[test]
fn pack_no_compress_mode() -> Result<()> {
    let config = PackConfig {
        no_compress: true,
        ..Default::default()
    };
    let result = pack_macho(Path::new(FIXTURE), &config)?;

    // Should have zero compressed chunks.
    assert_eq!(result.chunk_count, 0, "no_compress should produce 0 chunks");
    assert_eq!(result.total_compressed_bytes, 0);

    // Should still have stub (__UPOBF0).
    let reparsed = MachoImage::from_bytes(result.bytes.clone())?;
    assert!(reparsed.segment("__UPOBF0").is_some(), "__UPOBF0 should exist");

    // Entry should still be redirected.
    let main_cmd = reparsed.main_cmd.as_ref().expect("LC_MAIN");
    let orig = MachoImage::from_file(FIXTURE)?;
    let orig_entryoff = orig.main_cmd.as_ref().unwrap().entryoff;
    assert_ne!(main_cmd.entryoff, orig_entryoff, "entry should be redirected");

    println!("no_compress mode OK: entry redirect only, {} bytes", result.packed_size);
    Ok(())
}
