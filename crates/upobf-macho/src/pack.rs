//! End-to-end Mach-O packer: parse → compress → payload → stub → write.
//!
//! This is the top-level API for packing a macOS arm64 Mach-O binary.
//! It mirrors the ELF packer's `cmd_pack_elf` flow but adapted for
//! Mach-O specifics (LC_MAIN redirect, 16KB pages, libSystem APIs).

use anyhow::{bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};
use std::path::Path;

use upobf_core::crypto::prng::Polymorphic;
use upobf_core::payload::{self, PayloadInput};

use crate::build::stub_loader::StubBlob;
use crate::build::writer::{align_up, CompressedRange, MachoWriter, WriterConfig, PAGE_SIZE};
use crate::layout::safe_ranges;
use crate::parse::MachoImage;

// ---------------------------------------------------------------------------
// macOS API names for the stub resolver (Phase G)
// ---------------------------------------------------------------------------

/// API names the stub resolves from libSystem at runtime.
/// Order must match the enum in `stubs/macho-arm64/include/payload.h`.
pub const MACHO_API_NAMES: &[(&str, &str)] = &[
    ("libSystem.B.dylib", "pthread_create"),     // [0]
    ("libSystem.B.dylib", "pthread_detach"),      // [1]
    ("libSystem.B.dylib", "nanosleep"),           // [2]
    ("libSystem.B.dylib", "mach_absolute_time"),  // [3]
    ("libSystem.B.dylib", "mmap"),                // [4]
    ("libSystem.B.dylib", "mprotect"),            // [5]
    ("libSystem.B.dylib", "pthread_jit_write_protect_np"), // [6]
    ("libSystem.B.dylib", "munmap"),              // [7]
];

// ---------------------------------------------------------------------------
// Packer configuration
// ---------------------------------------------------------------------------

/// Configuration for the Mach-O packer.
#[derive(Debug, Clone)]
pub struct PackConfig {
    /// Path to the stub.dylib built by stubs/macho-arm64/build.sh.
    pub stub_path: Option<String>,
    /// Sections to compress (if empty, uses default tier-1 list).
    pub sections: Vec<String>,
    /// Whether to apply BCJ arm64 filter to executable sections.
    pub apply_bcj: bool,
    /// Disable compression (entry redirect only).
    pub no_compress: bool,
}

impl Default for PackConfig {
    fn default() -> Self {
        Self {
            stub_path: None,
            sections: Vec::new(),
            apply_bcj: false,
            no_compress: false,
        }
    }
}

/// Result of packing.
#[derive(Debug)]
pub struct PackResult {
    /// The packed binary bytes.
    pub bytes: Vec<u8>,
    /// Original file size.
    pub original_size: usize,
    /// Packed file size.
    pub packed_size: usize,
    /// Number of chunks compressed.
    pub chunk_count: usize,
    /// Total bytes compressed (original).
    pub total_compressed_bytes: u64,
}

// ---------------------------------------------------------------------------
// Main packer entry point
// ---------------------------------------------------------------------------

/// Pack a Mach-O binary: compress sections, embed stub + payload, rewrite entry.
pub fn pack_macho(input_path: &Path, config: &PackConfig) -> Result<PackResult> {
    // 1. Parse input.
    let img = MachoImage::from_file(input_path)
        .context("parse input Mach-O")?;
    let original_size = img.raw.len();

    // 2. Load and flatten stub blob.
    let stub = load_stub(config)?;

    // 3. Select sections to compress.
    let candidates = if config.no_compress {
        Vec::new()
    } else {
        select_compression_candidates(&img, config)
    };
    if candidates.is_empty() && stub.is_none() {
        bail!("no compressible sections found in input and no stub available");
    }

    // 4. Build payload inputs.
    let mut payload_inputs: Vec<PayloadInput> = Vec::new();
    let mut compressed_ranges: Vec<CompressedRange> = Vec::new();
    let mut total_compressed_bytes: u64 = 0;

    // Image base = __TEXT vmaddr (typically 0x100000000 for arm64 executables).
    let image_base = img.segment("__TEXT")
        .map(|s| s.vmaddr)
        .unwrap_or(0);

    for cand in &candidates {
        let data = extract_section_data(&img, cand)?;
        let prot = section_to_prot(cand);

        payload_inputs.push(PayloadInput {
            target_rva: (cand.vaddr - image_base) as u32,
            virtual_size: cand.size as u32,
            original_protect: prot,
            data,
            apply_bcj: config.apply_bcj && cand.is_executable,
        });

        compressed_ranges.push(CompressedRange {
            segname: cand.segname.clone(),
            sectname: cand.sectname.clone(),
            file_offset: cand.file_offset,
            size: cand.size,
        });

        total_compressed_bytes += cand.size;
    }

    // 5. Build payload blob.
    let master_seed: [u8; 32] = rand::random();
    let poly = Polymorphic::new(master_seed);
    let built_payload = payload::build_payload(&payload_inputs, MACHO_API_NAMES, &poly)
        .context("build payload")?;

    // 6. Compute layout to determine __UPOBF0 and __UPOBF1 vmaddrs.
    //    We need these to patch the stub slots before embedding.
    //    The stub code+data are combined into a single __UPOBF0 segment (R-X).
    //    The stub no longer writes to its __DATA (all mutable state is on stack).
    let (stub_code_bytes, stub_data_bytes) = if let Some(ref stub) = stub {
        // __UPOBF0 vmaddr = page-aligned past the last non-LINKEDIT segment's VM range.
        let last_vm_end = img.segments.iter()
            .filter(|s| !s.is_linkedit())
            .map(|s| s.vmaddr + s.vmsize)
            .max()
            .unwrap_or(0);
        let upobf0_vmaddr = align_up(last_vm_end, PAGE_SIZE);
        let total_stub_size = stub.code_size + stub.data_size;
        let upobf0_vmsize = align_up(total_stub_size as u64, PAGE_SIZE);

        // __UPOBF1 vmaddr = after __UPOBF0.
        let upobf1_vmaddr = align_up(upobf0_vmaddr + upobf0_vmsize, PAGE_SIZE);

        // Compute RVAs for stub patching.
        // The stub is flattened with code at offset 0 and data at offset code_size.
        // In the output, the entire blob is at upobf0_vmaddr, so:
        //   symbol at flat offset X → vmaddr = upobf0_vmaddr + X
        let anchor_rva = upobf0_vmaddr + stub.image_base_anchor_offset - image_base;

        // payload_rva = vmaddr of payload header = upobf1_vmaddr - image_base
        let payload_rva = if payload_inputs.is_empty() {
            0xDEADBEEFCAFEBABEu64
        } else {
            upobf1_vmaddr - image_base
        };

        // original_entryoff = the host's original LC_MAIN.entryoff
        let original_entryoff = img.main_cmd.as_ref()
            .map(|m| m.entryoff)
            .unwrap_or(0);

        // Resolve GOT entry RVAs for mmap/mprotect/munmap from host's chained fixups.
        let (got_mmap_rva, got_mprotect_rva, got_munmap_rva) =
            resolve_host_got_entries(&img, image_base)?;

        // Patch the stub with actual runtime values.
        let patched = stub.patched(anchor_rva, payload_rva, original_entryoff,
                     got_mmap_rva, got_mprotect_rva, got_munmap_rva);

        // Split into code and data portions for the writer (combined into one segment).
        let code_bytes = patched[..stub.code_size].to_vec();
        let data_bytes = if stub.data_size > 0 {
            patched[stub.code_size..stub.code_size + stub.data_size].to_vec()
        } else {
            Vec::new()
        };

        (code_bytes, data_bytes)
    } else {
        (Vec::new(), Vec::new())
    };

    // 7. Write packed binary with the patched stub.
    let writer_config = WriterConfig {
        stub_code_blob: stub_code_bytes,
        stub_data_blob: stub_data_bytes,
        payload_blob: built_payload.bytes,
        compressed_ranges,
        new_entryoff: None, // Will be patched after write
    };

    let writer = MachoWriter::new(&img, writer_config);
    let mut output = writer.build().context("write packed Mach-O")?;

    // 8. Patch LC_MAIN.entryoff to point at stub trampoline in __UPOBF0.
    if let Some(ref stub) = stub {
        patch_entry_point(&mut output, image_base, stub.entry_trampoline_offset)?;
    }

    let packed_size = output.len();

    Ok(PackResult {
        bytes: output,
        original_size,
        packed_size,
        chunk_count: payload_inputs.len(),
        total_compressed_bytes,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load the stub.dylib and flatten it into a StubBlob.
fn load_stub(config: &PackConfig) -> Result<Option<StubBlob>> {
    let default_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../stubs/macho-arm64/build/stub.dylib"
    );
    let path = config.stub_path.as_deref().unwrap_or(default_path);

    if !Path::new(path).exists() {
        tracing::warn!("stub not found at {}, packing without stub", path);
        return Ok(None);
    }

    let blob = StubBlob::from_file(path)
        .with_context(|| format!("load stub from {}", path))?;
    Ok(Some(blob))
}

/// A candidate section for compression.
#[derive(Debug, Clone)]
struct CompressionCandidate {
    segname: String,
    sectname: String,
    vaddr: u64,
    file_offset: u64,
    size: u64,
    is_executable: bool,
}

/// Select which sections to compress (Tier-1 defaults).
///
/// Uses safe_ranges to automatically identify compressible page-aligned
/// runs within __DATA* sections, avoiding chained fixup pages and other
/// forbidden regions.
fn select_compression_candidates(img: &MachoImage, config: &PackConfig) -> Vec<CompressionCandidate> {
    let mut candidates = Vec::new();

    if !config.sections.is_empty() {
        // User explicitly specified sections — use legacy whole-section mode.
        // This is opt-in and the user accepts the risk.
        for spec in &config.sections {
            // Parse "segname,sectname" format.
            let parts: Vec<&str> = spec.splitn(2, ',').collect();
            if parts.len() != 2 {
                continue;
            }
            let (segname, sectname) = (parts[0], parts[1]);
            if let Some(seg) = img.segment(segname) {
                if let Some(sect) = seg.section(sectname) {
                    if sect.size < 4096 || sect.is_zerofill() {
                        continue;
                    }
                    candidates.push(CompressionCandidate {
                        segname: segname.to_string(),
                        sectname: sectname.to_string(),
                        vaddr: sect.addr,
                        file_offset: sect.offset as u64,
                        size: sect.size,
                        is_executable: sect.is_executable(),
                    });
                }
            }
        }
        return candidates;
    }

    // Default mode: use safe_ranges to find compressible runs automatically.
    let chained_fixups_cmd = img.chained_fixups.as_ref().map(|cf| &cf.cmd);
    let safe = match safe_ranges::compute_safe_ranges(&img.raw, &img.segments, chained_fixups_cmd) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("safe_ranges computation failed: {:#}, falling back to no compression", e);
            return candidates;
        }
    };

    // Image base for file offset calculation.
    let image_base = img.segment("__TEXT").map(|s| s.vmaddr).unwrap_or(0);

    for (sect_name, runs) in &safe {
        for run in runs {
            // Convert vmaddr to file offset.
            let file_offset = match img.vaddr_to_file_offset(run.vaddr) {
                Ok(off) => off,
                Err(_) => continue,
            };

            // Determine which segment/section this run belongs to.
            let parts: Vec<&str> = sect_name.splitn(2, ',').collect();
            let (segname, sectname) = if parts.len() == 2 {
                (parts[0], parts[1])
            } else {
                continue;
            };

            // Check if section is executable.
            let is_executable = img.segment(segname)
                .and_then(|seg| seg.section(sectname))
                .map(|s| s.is_executable())
                .unwrap_or(false);

            candidates.push(CompressionCandidate {
                segname: segname.to_string(),
                sectname: sectname.to_string(),
                vaddr: run.vaddr,
                file_offset,
                size: run.len,
                is_executable,
            });
        }
    }

    if !candidates.is_empty() {
        let total: u64 = candidates.iter().map(|c| c.size).sum();
        tracing::info!(
            "safe_ranges: found {} compressible runs totaling {} bytes across {} sections",
            candidates.len(),
            total,
            safe.len()
        );
    }

    candidates
}

/// Extract raw bytes for a section from the image.
fn extract_section_data(img: &MachoImage, cand: &CompressionCandidate) -> Result<Vec<u8>> {
    let start = cand.file_offset as usize;
    let end = start + cand.size as usize;
    if end > img.raw.len() {
        bail!(
            "section {},{} extends past EOF: 0x{:X}+0x{:X} > 0x{:X}",
            cand.segname, cand.sectname, start, cand.size, img.raw.len()
        );
    }
    Ok(img.raw[start..end].to_vec())
}

/// Convert section characteristics to mprotect-style protection flags.
/// Must match the segment's initprot so the stub restores the correct
/// protection after decompression.
fn section_to_prot(cand: &CompressionCandidate) -> u32 {
    if cand.is_executable {
        // PROT_READ | PROT_EXEC = 0x01 | 0x04 = 5
        5
    } else if cand.segname.starts_with("__DATA") {
        // __DATA* segments are RW-: PROT_READ | PROT_WRITE = 0x01 | 0x02 = 3
        3
    } else {
        // PROT_READ = 0x01
        1
    }
}

/// Patch the output binary's LC_MAIN.entryoff to point at the stub
/// trampoline in __UPOBF0.
fn patch_entry_point(output: &mut [u8], image_base: u64, trampoline_offset: u64) -> Result<()> {
    // Re-parse the output to find __UPOBF0 vmaddr and LC_MAIN offset.
    let reparsed = MachoImage::from_bytes(output.to_vec())
        .context("re-parse output for entry patching")?;

    let upobf0 = reparsed.segment("__UPOBF0")
        .context("__UPOBF0 segment not found in output")?;

    // LC_MAIN.entryoff is relative to __TEXT vmaddr (which equals image_base).
    // The trampoline is at trampoline_offset within the __UPOBF0 blob.
    let new_entryoff = upobf0.vmaddr + trampoline_offset - image_base;

    // Find LC_MAIN in the output and patch it.
    let main_cmd = reparsed.main_cmd
        .context("LC_MAIN not found in output")?;

    // Patch the entryoff field (at cmd_offset + 8, 8 bytes).
    let patch_off = main_cmd.cmd_offset + 8;
    if patch_off + 8 > output.len() {
        bail!("LC_MAIN patch offset out of bounds");
    }
    LittleEndian::write_u64(&mut output[patch_off..patch_off + 8], new_entryoff);

    Ok(())
}

/// Resolve GOT entry RVAs for mmap/mprotect/munmap from the host binary's
/// chained fixups. Returns (mmap_rva, mprotect_rva, munmap_rva).
fn resolve_host_got_entries(img: &MachoImage, image_base: u64) -> Result<(u64, u64, u64)> {
    use crate::parse::chained_fixups::find_got_entry_for_symbol;

    let cf_cmd = match &img.chained_fixups {
        Some(cf) => &cf.cmd,
        None => return Ok((0, 0, 0)), // No chained fixups — can't resolve
    };

    // Find __DATA_CONST,__got section.
    let got_sect = img.section("__DATA_CONST", "__got")
        .context("__DATA_CONST,__got not found")?;
    let got_fileoff = got_sect.offset as u64;
    let got_vmaddr = got_sect.addr;
    let got_size = got_sect.size;

    let mmap_rva = find_got_entry_for_symbol(
        &img.raw, cf_cmd, got_fileoff, got_vmaddr, got_size, "_mmap",
    )?.map(|va| va - image_base).unwrap_or(0);

    let mprotect_rva = find_got_entry_for_symbol(
        &img.raw, cf_cmd, got_fileoff, got_vmaddr, got_size, "_mprotect",
    )?.map(|va| va - image_base).unwrap_or(0);

    let munmap_rva = find_got_entry_for_symbol(
        &img.raw, cf_cmd, got_fileoff, got_vmaddr, got_size, "_munmap",
    )?.map(|va| va - image_base).unwrap_or(0);

    Ok((mmap_rva, mprotect_rva, munmap_rva))
}
