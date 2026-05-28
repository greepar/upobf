//! Integration test: parse the PatchInstaller arm64 Mach-O binary.

use anyhow::Result;
use upobf_macho::parse::MachoImage;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/PatchInstaller.app/Contents/MacOS/PatchInstaller"
);

#[test]
fn parse_patch_installer_header() -> Result<()> {
    let img = MachoImage::from_file(FIXTURE)?;

    // Basic header checks.
    assert_eq!(img.header.magic, 0xFEED_FACF, "MH_MAGIC_64");
    assert_eq!(img.header.cputype, 0x0100_000C, "CPU_TYPE_ARM64");
    assert_eq!(img.header.filetype, 2, "MH_EXECUTE");
    assert!(img.header.ncmds > 0, "should have load commands");
    assert!(img.is_pie(), "arm64 executables should be PIE");

    println!("header: {:?}", img.header);
    println!("ncmds: {}, sizeofcmds: {}", img.header.ncmds, img.header.sizeofcmds);
    Ok(())
}

#[test]
fn parse_patch_installer_segments() -> Result<()> {
    let img = MachoImage::from_file(FIXTURE)?;

    // Must have at least __TEXT, __DATA_CONST/__DATA, __LINKEDIT.
    assert!(img.segments.len() >= 3, "expected >= 3 segments, got {}", img.segments.len());

    let text = img.segment("__TEXT").expect("__TEXT segment");
    assert!(text.vmsize > 0);
    assert!(text.filesize > 0);
    assert_eq!(text.prot_string(), "R-X");

    let linkedit = img.segment("__LINKEDIT").expect("__LINKEDIT segment");
    assert!(linkedit.vmsize > 0);

    // Print all segments for inspection.
    for seg in &img.segments {
        println!(
            "  {} vmaddr=0x{:X} vmsize=0x{:X} fileoff=0x{:X} filesize=0x{:X} prot={}  nsects={}",
            seg.segname, seg.vmaddr, seg.vmsize, seg.fileoff, seg.filesize,
            seg.prot_string(), seg.nsects
        );
        for sect in &seg.sections {
            println!(
                "    {},{} addr=0x{:X} size=0x{:X} offset=0x{:X}",
                sect.segname, sect.sectname, sect.addr, sect.size, sect.offset
            );
        }
    }
    Ok(())
}

#[test]
fn parse_patch_installer_main_cmd() -> Result<()> {
    let img = MachoImage::from_file(FIXTURE)?;

    let main = img.main_cmd.as_ref().expect("LC_MAIN should exist");
    assert!(main.entryoff > 0, "entryoff should be non-zero");
    println!("LC_MAIN: entryoff=0x{:X} stacksize={}", main.entryoff, main.stacksize);
    Ok(())
}

#[test]
fn parse_patch_installer_dylibs() -> Result<()> {
    let img = MachoImage::from_file(FIXTURE)?;

    let needed = img.needed_dylibs();
    assert!(!needed.is_empty(), "should have at least one dylib dependency");

    // libSystem.B.dylib should be present (directly or via umbrella framework).
    let has_libsystem = needed.iter().any(|n| {
        n.contains("libSystem") || n.contains("Foundation") || n.contains("AppKit")
    });
    assert!(has_libsystem, "should depend on libSystem or a framework that re-exports it; got: {:?}", needed);

    println!("needed dylibs:");
    for d in &needed {
        println!("  {}", d);
    }
    Ok(())
}

#[test]
fn parse_patch_installer_symtab() -> Result<()> {
    let img = MachoImage::from_file(FIXTURE)?;

    let symtab = img.symtab.as_ref().expect("LC_SYMTAB should exist");
    assert!(symtab.cmd.nsyms > 0, "should have symbols");
    assert!(symtab.symbols.len() == symtab.cmd.nsyms as usize);

    // Count defined vs undefined.
    let defined = symtab.symbols.iter().filter(|s| s.is_defined()).count();
    let undefined = symtab.symbols.iter().filter(|s| s.is_undefined()).count();
    println!("symtab: {} total, {} defined, {} undefined", symtab.symbols.len(), defined, undefined);
    Ok(())
}

#[test]
fn parse_patch_installer_chained_fixups() -> Result<()> {
    let img = MachoImage::from_file(FIXTURE)?;

    // Modern arm64 binaries should use chained fixups.
    if let Some(cf) = &img.chained_fixups {
        println!(
            "chained fixups: imports_count={}, starts_seg_count={}",
            cf.imports_count, cf.starts.seg_count
        );
        assert!(cf.imports_count > 0, "should have imports");
        assert!(cf.starts.seg_count > 0, "should have segment starts");
    } else {
        // Some binaries might use LC_DYLD_INFO_ONLY instead; not fatal.
        println!("NOTE: no LC_DYLD_CHAINED_FIXUPS (may use LC_DYLD_INFO_ONLY)");
    }
    Ok(())
}

#[test]
fn parse_patch_installer_build_version() -> Result<()> {
    let img = MachoImage::from_file(FIXTURE)?;

    if let Some(bv) = &img.build_version {
        println!(
            "build_version: platform={} minos={} sdk={}",
            bv.platform_name(),
            bv.minos_string(),
            bv.sdk_string()
        );
        // Should be macOS.
        assert_eq!(bv.platform, 1, "expected PLATFORM_MACOS");
    } else {
        println!("NOTE: no LC_BUILD_VERSION (older binary?)");
    }
    Ok(())
}

#[test]
fn parse_patch_installer_json_report() -> Result<()> {
    let img = MachoImage::from_file(FIXTURE)?;
    let report = img.to_json_report()?;

    // Should be valid JSON and non-empty.
    assert!(report.len() > 100, "JSON report too short");
    let _: serde_json::Value = serde_json::from_str(&report)?;

    // Print first 2000 chars for inspection.
    let preview = &report[..report.len().min(2000)];
    println!("{}", preview);
    Ok(())
}

#[test]
fn parse_patch_installer_chained_fixup_chain_walk() -> Result<()> {
    use upobf_macho::parse::chained_fixups;

    let img = MachoImage::from_file(FIXTURE)?;
    let cf = img.chained_fixups.as_ref().expect("chained fixups");

    let pages = chained_fixups::walk_all_fixup_chains(&img.raw, &cf.cmd, &img.segments)?;

    // Should have fixup info for at least __DATA_CONST and __DATA.
    assert!(!pages.is_empty(), "should find fixup pages");

    let data_const = pages.iter().find(|p| p.segname == "__DATA_CONST");
    let data = pages.iter().find(|p| p.segname == "__DATA");

    // __DATA_CONST should have fixups (it contains __got).
    let dc = data_const.expect("__DATA_CONST fixup pages");
    assert!(dc.total_fixup_count > 0, "__DATA_CONST should have fixup entries");
    assert!(dc.page_has_fixups.iter().any(|&x| x), "__DATA_CONST should have pages with fixups");

    // __DATA should have fixups (chained rebase entries).
    let d = data.expect("__DATA fixup pages");
    assert!(d.total_fixup_count > 0, "__DATA should have fixup entries");
    let fixup_page_count: usize = d.page_has_fixups.iter().filter(|&&x| x).count();
    assert!(fixup_page_count > 0, "__DATA should have pages with fixups");
    // But not ALL pages should have fixups (most of .dotnet_eh_table is fixup-free).
    assert!(
        fixup_page_count < d.page_has_fixups.len(),
        "__DATA should have some pages WITHOUT fixups (got {} of {} with fixups)",
        fixup_page_count, d.page_has_fixups.len()
    );

    println!("chain walk: __DATA_CONST: {} entries on {} pages",
        dc.total_fixup_count, dc.page_has_fixups.iter().filter(|&&x| x).count());
    println!("chain walk: __DATA: {} entries on {}/{} pages",
        d.total_fixup_count, fixup_page_count, d.page_has_fixups.len());

    Ok(())
}

#[test]
fn parse_patch_installer_safe_ranges() -> Result<()> {
    use upobf_macho::layout::safe_ranges;

    let img = MachoImage::from_file(FIXTURE)?;
    let cf_cmd = img.chained_fixups.as_ref().map(|cf| &cf.cmd);

    let safe = safe_ranges::compute_safe_ranges(&img.raw, &img.segments, cf_cmd)?;

    // Should find compressible ranges in __DATA.
    assert!(!safe.is_empty(), "should find safe ranges");

    // .dotnet_eh_table should have at least one safe run.
    let eh_table_runs = safe.iter()
        .find(|(name, _)| name.contains(".dotnet_eh_table"));
    assert!(eh_table_runs.is_some(), ".dotnet_eh_table should have safe runs");

    let (_, runs) = eh_table_runs.unwrap();
    assert!(!runs.is_empty());

    // Total safe bytes should be significant (> 1 MB for PatchInstaller).
    let total_safe: u64 = safe.iter()
        .flat_map(|(_, runs)| runs.iter().map(|r| r.len))
        .sum();
    assert!(
        total_safe > 1024 * 1024,
        "total safe bytes should be > 1MB, got {} bytes",
        total_safe
    );

    // All safe ranges should be page-aligned (16 KB).
    for (name, runs) in &safe {
        for run in runs {
            assert_eq!(run.vaddr % 0x4000, 0,
                "{} run start 0x{:X} not page-aligned", name, run.vaddr);
            assert_eq!(run.len % 0x4000, 0,
                "{} run len 0x{:X} not page-aligned", name, run.len);
        }
    }

    println!("safe_ranges: {} sections, {} total safe bytes ({:.1} MB)",
        safe.len(), total_safe, total_safe as f64 / (1024.0 * 1024.0));

    Ok(())
}
