//! upobf-cli: command-line entry point.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "upobf", version, about = "Universal packer + obfuscator framework")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect a PE file and emit a structured report.
    Inspect {
        /// Path to PE input.
        input: PathBuf,
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Pack a PE file (compression + obfuscation).
    Pack {
        /// Path to PE input.
        input: PathBuf,
        /// Output path.
        #[arg(short, long)]
        output: PathBuf,
        /// Disable compression (passthrough mode for M3 testing).
        #[arg(long)]
        no_compress: bool,
        /// Disable encryption (M3 testing).
        #[arg(long)]
        no_encrypt: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Inspect { input, json } => cmd_inspect(input, json),
        Command::Pack {
            input,
            output,
            no_compress,
            no_encrypt,
        } => cmd_pack(input, output, no_compress, no_encrypt),
    }
}

fn cmd_inspect(input: PathBuf, json: bool) -> Result<()> {
    let image = upobf_pe::PeImage::from_file(&input)
        .with_context(|| format!("failed to parse {}", input.display()))?;

    if json {
        println!("{}", image.to_json_report()?);
        return Ok(());
    }

    let raw_len = image.raw.len();
    let oh = &image.nt.optional_header;
    let fh = &image.nt.file_header;

    println!(
        "File: {} ({} bytes / {:.2} MB)",
        input.display(),
        raw_len,
        raw_len as f64 / (1024.0 * 1024.0)
    );

    println!("DOS:");
    println!(
        "  e_magic   = 0x{:04X} ({})",
        image.dos.e_magic,
        if image.dos.e_magic == 0x5A4D { "MZ" } else { "??" }
    );
    println!("  e_lfanew  = 0x{:X}", image.dos.e_lfanew);

    println!("FileHeader:");
    println!("  Machine             = 0x{:04X}", fh.machine);
    println!("  TimeDateStamp       = 0x{:08X}", fh.time_date_stamp);
    println!(
        "  Linker              = {}.{}",
        oh.major_linker_version, oh.minor_linker_version
    );
    println!("  NumberOfSections    = {}", fh.number_of_sections);
    println!(
        "  Characteristics     = 0x{:04X} [{}]",
        fh.characteristics,
        fh.characteristics_flags().join(" | ")
    );

    println!("OptionalHeader (PE32+):");
    println!(
        "  Magic                = 0x{:04X} (PE32+)",
        oh.magic
    );
    println!("  ImageBase            = 0x{:016X}", oh.image_base);
    println!(
        "  AddressOfEntryPoint  = 0x{:08X}",
        oh.address_of_entry_point
    );
    println!(
        "  SectionAlignment     = 0x{:X}, FileAlignment = 0x{:X}",
        oh.section_alignment, oh.file_alignment
    );
    println!(
        "  SizeOfImage          = 0x{:X}, SizeOfHeaders = 0x{:X}",
        oh.size_of_image, oh.size_of_headers
    );
    println!(
        "  Subsystem            = {} ({}), version = {}.{}",
        oh.subsystem,
        oh.subsystem_name(),
        oh.major_subsystem_version,
        oh.minor_subsystem_version
    );
    println!(
        "  DllCharacteristics   = 0x{:04X} [{}]",
        oh.dll_characteristics,
        oh.dll_characteristics_flags().join(" | ")
    );
    println!(
        "  StackReserve = 0x{:X} ({} KB), StackCommit = 0x{:X}",
        oh.size_of_stack_reserve,
        oh.size_of_stack_reserve / 1024,
        oh.size_of_stack_commit
    );
    println!(
        "  HeapReserve  = 0x{:X} ({} KB), HeapCommit  = 0x{:X}",
        oh.size_of_heap_reserve,
        oh.size_of_heap_reserve / 1024,
        oh.size_of_heap_commit
    );
    println!(
        "  NumberOfRvaAndSizes  = {}",
        oh.number_of_rva_and_sizes
    );

    println!("DataDirectories:");
    for (i, d) in image.data_dirs.iter().enumerate() {
        println!(
            "  {:>2} {:<13} 0x{:08X}  {}",
            i,
            upobf_pe::parse::data_dir::DIRECTORY_NAMES[i],
            d.virtual_address,
            d.size
        );
    }

    println!("Sections:");
    println!(
        "  {:<8} {:<10} {:<10} {:<10} {:<10} Characteristics",
        "Name", "VAddr", "VSize", "RawPtr", "RawSize"
    );
    for s in &image.sections {
        println!(
            "  {:<8} 0x{:08X} 0x{:08X} 0x{:08X} 0x{:08X} 0x{:08X} [{}]",
            s.name,
            s.virtual_address,
            s.virtual_size,
            s.pointer_to_raw_data,
            s.size_of_raw_data,
            s.characteristics,
            s.protection_flags()
        );
    }

    if let Some(tls) = &image.tls {
        println!("TLS:");
        println!(
            "  StartAddressOfRawData = 0x{:016X}",
            tls.start_va
        );
        println!(
            "  EndAddressOfRawData   = 0x{:016X}",
            tls.end_va
        );
        println!("  AddressOfIndex        = 0x{:016X}", tls.index_va);
        println!(
            "  AddressOfCallBacks    = 0x{:016X}",
            tls.callbacks_va
        );
        for (i, cb) in tls.callbacks.iter().enumerate() {
            println!(
                "  Callback[{}] RVA       = 0x{:08X}  (VA = 0x{:016X})",
                i,
                cb,
                oh.image_base + *cb as u64
            );
        }
    } else {
        println!("TLS: <absent>");
    }

    if let Some(lc) = &image.load_config {
        println!("LoadConfig: {} bytes", lc.size);
        if let Some(v) = lc.security_cookie_va {
            println!("  SecurityCookie VA       = 0x{:016X}", v);
        }
        if let Some(v) = lc.guard_cf_check_function_pointer {
            println!("  GuardCFCheckFnPointer   = 0x{:016X}", v);
        }
        if let Some(v) = lc.guard_flags {
            println!("  GuardFlags              = 0x{:08X}", v);
        }
        let cfg_on = oh.dll_characteristics & 0x4000 != 0;
        println!(
            "  CFG enabled (DllCharacteristics & 0x4000) = {}",
            cfg_on
        );
    } else {
        println!("LoadConfig: <absent>");
    }

    if let Some(p) = &image.pdata {
        println!(
            ".pdata: {} entries, RVA 0x{:08X}..0x{:08X} (size {})",
            p.entry_count,
            p.directory_rva,
            p.directory_rva + p.directory_size,
            p.directory_size
        );
    }

    println!("Imports: {} DLL(s)", image.imports.dlls.len());
    for d in &image.imports.dlls {
        println!("  {} ({} fn)", d.name, d.functions.len());
    }

    if !image.delay_imports.dlls.is_empty() {
        println!("DelayImports: {} DLL(s)", image.delay_imports.dlls.len());
        for n in &image.delay_imports.dlls {
            println!("  {}", n);
        }
    } else {
        println!("DelayImports: <absent>");
    }

    if let Some(e) = &image.export {
        println!(
            "Export: name={:?}, ordinal_base={}, fns={}, names={}",
            e.name, e.ordinal_base, e.number_of_functions, e.number_of_names
        );
    } else {
        println!("Export: <absent>");
    }

    Ok(())
}

fn cmd_pack(input: PathBuf, output: PathBuf, _no_compress: bool, _no_encrypt: bool) -> Result<()> {
    use upobf_core::stub_link::{link, parse_coff};
    use upobf_core::crypto::prng::Polymorphic;
    use upobf_core::obfuscate::section_names;
    use upobf_pe::build::payload::{build_payload, PayloadInput};
    use upobf_pe::build::writer::{section_protect_for_chars, PackedPeBuilder};

    let image = upobf_pe::PeImage::from_file(&input)
        .with_context(|| format!("failed to parse {}", input.display()))?;

    // ---- Load and link stub objects -------------------------------------
    let stub_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("stubs")
        .join("pe-x64")
        .join("build");
    if !stub_dir.exists() {
        anyhow::bail!(
            "stub build dir not found: {}\nrun `stubs/pe-x64/build.ps1` first",
            stub_dir.display()
        );
    }
    let mut obj_paths: Vec<std::path::PathBuf> = std::fs::read_dir(&stub_dir)
        .with_context(|| format!("read stub dir {}", stub_dir.display()))?
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
        anyhow::bail!("no .obj files in {}", stub_dir.display());
    }

    let mut objects = Vec::with_capacity(obj_paths.len());
    for p in &obj_paths {
        let bytes = std::fs::read(p).with_context(|| format!("read {}", p.display()))?;
        let obj = parse_coff(&bytes).with_context(|| format!("parse COFF {}", p.display()))?;
        objects.push(obj);
    }
    let linked = link(&objects).context("link stub objects")?;
    tracing::info!(
        text_len = linked.text.len(),
        tls_callback_offset = format!("{:#x}", linked.tls_callback_offset),
        fixups = linked.abs_fixups.len(),
        externs = linked.external_symbols.len(),
        "stub linked",
    );

    // ---- Build payload --------------------------------------------------
    let poly = Polymorphic::from_os_rng();
    let mut inputs: Vec<PayloadInput> = Vec::new();
    let mut compressed_rvas: Vec<u32> = Vec::new();

    for sec in &image.sections {
        // M4 strategy: pack `.text` only.
        // If --no-compress, build a payload with zero chunks (stub
        // becomes a passthrough that just invokes the original TLS
        // callback). Useful to bisect crashes.
        if _no_compress {
            continue;
        }
        let target_for_pack = matches!(sec.name.as_str(), ".text");
        if !target_for_pack {
            continue;
        }
        let raw_off = sec.pointer_to_raw_data as usize;
        let raw_len = (sec.size_of_raw_data as usize)
            .min(image.raw.len().saturating_sub(raw_off));
        // For .data sections VirtualSize > RawSize is the BSS tail; we
        // only pack the initialized portion. For .text/.rdata the two
        // are typically equal modulo file alignment.
        let pack_len = (sec.virtual_size as usize).min(raw_len);
        if pack_len == 0 {
            continue;
        }
        let data = image.raw[raw_off..raw_off + pack_len].to_vec();
        inputs.push(PayloadInput {
            target_rva: sec.virtual_address,
            virtual_size: pack_len as u32,
            original_protect: section_protect_for_chars(sec.characteristics),
            data,
        });
        compressed_rvas.push(sec.virtual_address);
    }

    let payload = build_payload(&inputs, &poly).context("build payload")?;

    // ---- Assemble packed PE --------------------------------------------
    let mut builder = PackedPeBuilder::new(&image, linked, payload.bytes);
    for rva in &compressed_rvas {
        builder.mark_compressed_rva(*rva);
    }

    // Per-build polymorphic section names so static signatures keyed
    // on `.upobf0` / `.upobf1` / `.reloc2` no longer match.
    let host_section_names: Vec<[u8; 8]> = image
        .sections
        .iter()
        .map(|s| {
            let mut buf = [0u8; 8];
            let nb = s.name.as_bytes();
            let n = nb.len().min(8);
            buf[..n].copy_from_slice(&nb[..n]);
            buf
        })
        .collect();
    let mut name_rng = poly.rng("section.names");
    let (stub_name, payload_name, reloc_name) =
        section_names::pick_three(&mut name_rng, &host_section_names);
    builder.set_section_names(stub_name, payload_name, reloc_name);

    // Header sanitisation:
    //  - Wipe Rich Header (MS-toolchain build fingerprint). Useful even
    //    when host was built with a non-MSVC toolchain (the block may
    //    still be there, e.g. due to LIB inputs).
    //  - Randomise TimeDateStamp into a plausible window (last ~3
    //    years before the host's stamp) so two builds of the same
    //    source produce different stamps without raising obviously-old
    //    or future-dated red flags.
    //  - Randomise LinkerVersion into a plausible MSVC range
    //    (14.30 .. 14.40 == VS2022 LTSC family). The host itself ships
    //    with 14.50 today; we step it back a notch but keep it
    //    on-toolchain so heuristic scanners don't gain a tell.
    builder.enable_strip_rich_header(true);
    {
        let host_ts = image.nt.file_header.time_date_stamp as u64;
        // Pick a stamp uniformly inside [host_ts - 3y, host_ts]. If
        // host_ts is suspicious (== 0 / >= now), fall back to a fixed
        // window centred on Jan 2024.
        let now_epoch: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1_700_000_000);
        let upper = if host_ts > 0 && host_ts <= now_epoch {
            host_ts
        } else {
            now_epoch
        };
        let three_years: u64 = 3 * 365 * 24 * 60 * 60;
        let lower = upper.saturating_sub(three_years);
        let span = (upper - lower).max(1);
        let pick = lower + (poly.next_u64("pe.header.timedate") % span);
        builder.set_timedate_stamp(pick as u32);

        let major: u8 = 14;
        let minor: u8 = 30 + ((poly.next_u32("pe.header.linker") as u8) % 11); // 30..=40
        builder.set_linker_version(major, minor);
    }

    // M4 status: do NOT add extra imports yet. The host's existing
    // KERNEL32 import already brings in the APIs we need; the stub
    // resolves them by ordinal/name. Adding extra imports rewrites
    // DataDirectory[Import] which currently destabilises NativeAOT
    // startup. M5 will revisit.
    let _ = ();
    /*
    builder.add_import(
        "KERNEL32.dll",
        &[
            "GetModuleHandleA",
            "LoadLibraryA",
            "GetProcAddress",
            "VirtualProtect",
            "VirtualAlloc",
            "VirtualFree",
        ],
    );
    */
    let bytes = builder.build().context("build packed PE")?;
    std::fs::write(&output, &bytes)
        .with_context(|| format!("write {}", output.display()))?;

    let orig = std::fs::metadata(&input)?.len();
    let pkt = std::fs::metadata(&output)?.len();
    println!(
        "packed: {} -> {} ({} -> {} bytes, {:.1}%)",
        input.display(),
        output.display(),
        orig,
        pkt,
        pkt as f64 * 100.0 / orig as f64
    );
    Ok(())
}
