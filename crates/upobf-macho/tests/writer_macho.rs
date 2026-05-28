//! Integration test: writer round-trip (output can be re-parsed).

use anyhow::Result;
use upobf_macho::build::writer::{CompressedRange, MachoWriter, WriterConfig};
use upobf_macho::parse::MachoImage;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/PatchInstaller.app/Contents/MacOS/PatchInstaller"
);

#[test]
fn writer_roundtrip_no_stub_no_payload() -> Result<()> {
    let img = MachoImage::from_file(FIXTURE)?;

    let config = WriterConfig {
        stub_code_blob: Vec::new(),
        stub_data_blob: Vec::new(),
        payload_blob: Vec::new(),
        compressed_ranges: Vec::new(),
        new_entryoff: None,
    };

    let writer = MachoWriter::new(&img, config);
    let output = writer.build()?;

    // Output should be re-parseable.
    let reparsed = MachoImage::from_bytes(output.clone())?;

    // Same number of segments (minus none added).
    assert_eq!(reparsed.segments.len(), img.segments.len());

    // Same header fields.
    assert_eq!(reparsed.header.magic, img.header.magic);
    assert_eq!(reparsed.header.cputype, img.header.cputype);
    assert_eq!(reparsed.header.filetype, img.header.filetype);

    // LC_CODE_SIGNATURE should be dropped.
    assert!(reparsed.code_signature.is_none(), "LC_CODE_SIGNATURE should be dropped");

    // ncmds should be original - 1 (dropped codesig).
    let expected_ncmds = img.header.ncmds - if img.code_signature.is_some() { 1 } else { 0 };
    assert_eq!(reparsed.header.ncmds, expected_ncmds);

    // LC_MAIN should be preserved.
    assert!(reparsed.main_cmd.is_some());
    assert_eq!(
        reparsed.main_cmd.as_ref().unwrap().entryoff,
        img.main_cmd.as_ref().unwrap().entryoff
    );

    println!("roundtrip OK: {} bytes -> {} bytes", img.raw.len(), output.len());
    Ok(())
}

#[test]
fn writer_with_stub_and_payload() -> Result<()> {
    let img = MachoImage::from_file(FIXTURE)?;

    // Fake stub and payload blobs.
    let stub_code_blob = vec![0xCC; 4096]; // 4 KB fake stub code
    let payload_blob = vec![0xAA; 8192]; // 8 KB fake payload

    let config = WriterConfig {
        stub_code_blob: stub_code_blob.clone(),
        stub_data_blob: Vec::new(),
        payload_blob: payload_blob.clone(),
        compressed_ranges: Vec::new(),
        new_entryoff: Some(0x12345), // fake new entry
    };

    let writer = MachoWriter::new(&img, config);
    let output = writer.build()?;

    let reparsed = MachoImage::from_bytes(output.clone())?;

    // Should have 2 extra segments.
    assert_eq!(reparsed.segments.len(), img.segments.len() + 2);

    // Find __UPOBF0 and __UPOBF1.
    let upobf0 = reparsed.segment("__UPOBF0").expect("__UPOBF0 should exist");
    let upobf1 = reparsed.segment("__UPOBF1").expect("__UPOBF1 should exist");

    assert_eq!(upobf0.prot_string(), "R-X");
    assert_eq!(upobf1.prot_string(), "R--");
    assert!(upobf0.filesize >= 4096);
    assert!(upobf1.filesize >= 8192);

    // Verify stub data is present.
    let stub_start = upobf0.fileoff as usize;
    assert_eq!(&output[stub_start..stub_start + 4096], &stub_code_blob[..]);

    // Verify payload data is present.
    let payload_start = upobf1.fileoff as usize;
    assert_eq!(&output[payload_start..payload_start + 8192], &payload_blob[..]);

    // LC_MAIN should be rewritten.
    let main = reparsed.main_cmd.as_ref().unwrap();
    assert_eq!(main.entryoff, 0x12345);

    println!(
        "writer with stub+payload OK: {} bytes -> {} bytes (upobf0 @ 0x{:X}, upobf1 @ 0x{:X})",
        img.raw.len(),
        output.len(),
        upobf0.fileoff,
        upobf1.fileoff
    );
    Ok(())
}

#[test]
fn writer_with_compressed_ranges() -> Result<()> {
    let img = MachoImage::from_file(FIXTURE)?;

    // Compress __TEXT,__text section.
    let text_sect = img.section("__TEXT", "__text").expect("__text section");
    let compressed_ranges = vec![CompressedRange {
        segname: "__TEXT".to_string(),
        sectname: "__text".to_string(),
        file_offset: text_sect.offset as u64,
        size: text_sect.size,
    }];

    let config = WriterConfig {
        stub_code_blob: Vec::new(),
        stub_data_blob: Vec::new(),
        payload_blob: Vec::new(),
        compressed_ranges,
        new_entryoff: None,
    };

    let writer = MachoWriter::new(&img, config);
    let output = writer.build()?;

    // With file-shrink, the compressed section is removed from the file.
    // The output should be smaller than the original.
    assert!(
        output.len() < img.raw.len(),
        "output ({}) should be smaller than original ({}) after compression",
        output.len(), img.raw.len()
    );

    // Verify the output is still parseable.
    let reparsed = MachoImage::from_bytes(output.clone())?;
    assert!(reparsed.segment("__TEXT").is_some());

    println!(
        "compressed ranges OK: {} -> {} bytes (shrunk by {} bytes)",
        img.raw.len(),
        output.len(),
        img.raw.len() - output.len()
    );
    Ok(())
}
