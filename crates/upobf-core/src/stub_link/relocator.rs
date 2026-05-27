//! Stub linker.
//!
//! Takes one or more parsed COFF objects produced by `clang -c` for the
//! upobf stub and links them into a single contiguous blob (`text`) that
//! the PE writer can place at any RVA. Cross-object references are
//! resolved here. References to packer-supplied symbols (e.g. the
//! original entry point) are recorded as `AbsFixup`s so the PE writer
//! can patch them once the final layout is known.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, ensure, Context, Result};
use byteorder::{ByteOrder, LittleEndian};

use super::coff::{
    CoffObject, CoffRelocKind, CoffSection, IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_LNK_INFO,
    IMAGE_SCN_LNK_REMOVE, IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SYM_CLASS_AUX_PLACEHOLDER,
    IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_FILE,
};

/// Name of the packer-provided symbol that holds the absolute VA of the
/// original entry point. The C stub declares it as `extern volatile
/// uintptr_t`; the linker materialises an 8-byte slot for it and asks the
/// PE writer to fill that slot with the OEP at pack time.
pub const SYM_ORIGINAL_OEP: &str = "__upobf_original_oep";

/// Same idea for the original first TLS callback (used in later
/// milestones). Not required to be referenced; if absent it is skipped.
pub const SYM_ORIGINAL_TLS_CALLBACK: &str = "__upobf_original_tls_callback";

/// Absolute VA of the payload blob (PayloadHeader). 8-byte slot.
pub const SYM_PAYLOAD_BLOB: &str = "__upobf_payload_blob";

/// 32-bit RVA of the stub TLS callback function inside the final image.
/// stub_link still materialises an 8-byte slot but the writer fills only
/// the low 32 bits (zero-extended) so the stub can subtract it from
/// `&upobf_stub_tls_callback` to recover ImageBase.
pub const SYM_STUB_SELF_RVA: &str = "__upobf_stub_self_rva";

/// Name of the entry symbol that the packed PE registers as the first
/// TLS callback.
pub const SYM_TLS_CALLBACK: &str = "upobf_stub_tls_callback";

/// Prefix for IAT thunk references emitted by clang for `dllimport`
/// declared functions. The packer must materialise an IAT slot of this
/// name in the packed PE's import table; the value loaded by the call
/// site is the slot's VA itself, which the OS Loader fills with the
/// resolved API address.
pub const SYM_IMP_PREFIX: &str = "__imp_";

/// Alignment used between concatenated sections. 16 covers x64 code and
/// 8-byte data slots. We keep it constant for predictability; padding
/// bytes are zero (sufficient for both `.text` and read-only data).
const SECTION_ALIGN: usize = 16;

#[derive(Debug, Clone)]
pub struct LinkedStub {
    /// Final stub bytes that will be placed in the packed PE's
    /// `.text'` section.
    pub text: Vec<u8>,
    /// Offset within `text` where `upobf_stub_tls_callback` starts.
    pub tls_callback_offset: u32,
    /// Image-relative addressing patches that the PE writer must apply
    /// once the final stub RVA is decided.
    pub abs_fixups: Vec<AbsFixup>,
    /// REL32 sites that reference `__imp_*` symbols. The packer must
    /// patch each site so that the `call qword ptr [rip + disp]`
    /// instruction loads from the corresponding IAT thunk slot in
    /// `.idata2` (rather than from a local stub slot).
    pub imp_rel32_sites: Vec<ImpRel32Site>,
    /// Symbols that come from outside the stub (filled by upobf-pe at
    /// pack time). For M3 this is just `SYM_ORIGINAL_OEP` (resolved as a
    /// local slot, but exposed here so the writer knows what packer
    /// inputs are required).
    pub external_symbols: Vec<ExternalSymbol>,
    /// Map of every defined symbol -> its offset within `text`.
    /// Useful for later milestones that need to call into the stub.
    pub local_symbols: BTreeMap<String, u32>,
}

#[derive(Debug, Clone)]
pub struct ImpRel32Site {
    /// Offset within `text` of the 4-byte REL32 displacement to patch.
    pub offset: u32,
    /// API name (without the `__imp_` prefix).
    pub api_name: String,
    /// Addend originally encoded at the patch site.
    pub addend: i32,
}

#[derive(Debug, Clone)]
pub struct AbsFixup {
    /// Where in `text` to write the absolute value.
    pub offset: u32,
    /// Width in bytes (4 or 8).
    pub width: u8,
    /// What the writer should compute and store there.
    pub target: FixupTarget,
}

#[derive(Debug, Clone)]
pub enum FixupTarget {
    /// Absolute VA = stub_base_va + local_symbols[name].
    LocalSymbol(String),
    /// Absolute VA of the original entry point (packer input).
    OriginalOep,
    /// Absolute VA of the original first TLS callback, or 0 if absent.
    OriginalTlsCallback,
    /// Absolute VA of the payload blob (PayloadHeader start).
    PayloadBlobVa,
    /// 32-bit RVA of the stub TLS callback function. Written into the
    /// low 32 bits of the slot; high 32 bits are zero.
    StubSelfRva,
    /// Absolute VA of an IAT thunk slot. The string is the API name
    /// without the `__imp_` prefix (e.g. "GetProcAddress").
    ImportThunk(String),
}

#[derive(Debug, Clone)]
pub struct ExternalSymbol {
    pub name: String,
}

/// Link the given COFF objects into a single stub blob.
pub fn link(objects: &[CoffObject]) -> Result<LinkedStub> {
    ensure!(!objects.is_empty(), "stub_link::link called with no objects");

    // ---- Phase 1: pick sections and lay them out ------------------------
    // Each entry: (object_index, section_index, sort_key)
    let mut layout_inputs: Vec<(usize, usize, String)> = Vec::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            classify_section(sec)
                .with_context(|| format!("object {} section `{}`", oi, sec.name))?;
            if section_is_emitted(sec) {
                let key = section_sort_key(&sec.name);
                layout_inputs.push((oi, si, key));
            }
        }
    }

    // Sort emitted sections so `$`-grouped sections behave like the MSVC
    // linker: lexicographic on the name, with object order as tiebreaker
    // for stability.
    layout_inputs.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)).then(a.1.cmp(&b.1)));

    let mut text: Vec<u8> = Vec::new();
    // section_offsets[(obj_idx, sec_idx)] = offset_in_text
    let mut section_offsets: BTreeMap<(usize, usize), u32> = BTreeMap::new();
    for (oi, si, _) in &layout_inputs {
        align_to(&mut text, SECTION_ALIGN);
        let off = text.len() as u32;
        let sec = &objects[*oi].sections[*si];
        text.extend_from_slice(&sec.data);
        section_offsets.insert((*oi, *si), off);
    }

    // ---- Phase 2: collect defined / undefined symbols -------------------
    let mut local_symbols: BTreeMap<String, u32> = BTreeMap::new();
    // Per-symbol-index resolution within each object.
    // resolved[(obj, sym_idx)] = SymbolResolution
    let mut resolved: BTreeMap<(usize, u32), SymbolResolution> = BTreeMap::new();
    let mut undefined: BTreeMap<String, ()> = BTreeMap::new();

    for (oi, obj) in objects.iter().enumerate() {
        for (si, sym) in obj.symbols.iter().enumerate() {
            if sym.storage_class == IMAGE_SYM_CLASS_AUX_PLACEHOLDER
                || sym.storage_class == IMAGE_SYM_CLASS_FILE
            {
                continue;
            }
            let sym_idx = si as u32;
            let sn = sym.section_number;
            if sn > 0 {
                // Defined in this object.
                let sec_idx = (sn - 1) as usize;
                match section_offsets.get(&(oi, sec_idx)) {
                    Some(&sec_off) => {
                        let absolute = sec_off
                            .checked_add(sym.value)
                            .ok_or_else(|| anyhow!("symbol offset overflow for `{}`", sym.name))?;
                        resolved.insert((oi, sym_idx), SymbolResolution::Offset(absolute));

                        // Only register named externals as global names so we
                        // do not collide on the per-object `.text` static
                        // symbols.
                        if sym.storage_class == IMAGE_SYM_CLASS_EXTERNAL && !sym.name.is_empty() {
                            if let Some(prev) = local_symbols.insert(sym.name.clone(), absolute) {
                                if prev != absolute {
                                    bail!(
                                        "duplicate definition of `{}` (offsets {:#x} and {:#x})",
                                        sym.name,
                                        prev,
                                        absolute
                                    );
                                }
                            }
                        }
                    }
                    None => {
                        // Section was stripped (empty .data / .bss / debug).
                        // Definitions in such sections must never be the
                        // target of a relocation; we keep a Skip slot so a
                        // bug in the stub causes a precise error later
                        // instead of a silent miscompile.
                        resolved.insert((oi, sym_idx), SymbolResolution::Skip);
                    }
                }
            } else if sn == 0 {
                // Undefined external reference.
                if sym.storage_class == IMAGE_SYM_CLASS_EXTERNAL && !sym.name.is_empty() {
                    undefined.insert(sym.name.clone(), ());
                    resolved.insert((oi, sym_idx), SymbolResolution::External(sym.name.clone()));
                } else {
                    resolved.insert((oi, sym_idx), SymbolResolution::Skip);
                }
            } else {
                // Absolute (-1) or Debug (-2). Treat absolute as a constant
                // (uncommon in our stub); debug entries should not appear
                // as relocation targets.
                if sn == -1 {
                    resolved.insert((oi, sym_idx), SymbolResolution::Absolute(sym.value));
                } else {
                    resolved.insert((oi, sym_idx), SymbolResolution::Skip);
                }
            }
        }
    }

    // ---- Phase 3: materialise packer-provided symbols as local slots ---
    let mut abs_fixups: Vec<AbsFixup> = Vec::new();
    let mut external_symbols: Vec<ExternalSymbol> = Vec::new();

    let mut emitted_externs: BTreeMap<String, ()> = BTreeMap::new();
    let mut imp_externs: BTreeMap<String, ()> = BTreeMap::new();
    for name in undefined.keys() {
        // If another object in the link set defines this symbol, no
        // packer-side fixup is required. The relocation will resolve to
        // the local offset during phase 4.
        if local_symbols.contains_key(name) {
            continue;
        }
        // `__imp_*` symbols are *not* materialised as local slots. The
        // packer points each REL32 site directly at the IAT thunk in
        // `.idata2`. Just record that the stub needs that IAT slot to
        // exist.
        if name.starts_with(SYM_IMP_PREFIX) {
            imp_externs.insert(name.clone(), ());
            external_symbols.push(ExternalSymbol {
                name: name.clone(),
            });
            emitted_externs.insert(name.clone(), ());
            continue;
        }
        let target = match name.as_str() {
            SYM_ORIGINAL_OEP => FixupTarget::OriginalOep,
            SYM_ORIGINAL_TLS_CALLBACK => FixupTarget::OriginalTlsCallback,
            SYM_PAYLOAD_BLOB => FixupTarget::PayloadBlobVa,
            SYM_STUB_SELF_RVA => FixupTarget::StubSelfRva,
            other => bail!("unresolved external symbol `{}` in stub", other),
        };
        align_to(&mut text, 8);
        let slot_off = text.len() as u32;
        text.extend_from_slice(&[0u8; 8]);
        local_symbols.insert(name.clone(), slot_off);
        abs_fixups.push(AbsFixup {
            offset: slot_off,
            width: 8,
            target,
        });
        external_symbols.push(ExternalSymbol {
            name: name.clone(),
        });
        emitted_externs.insert(name.clone(), ());
    }

    // ---- Phase 4: apply relocations -------------------------------------
    let mut imp_rel32_sites: Vec<ImpRel32Site> = Vec::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            if !section_is_emitted(sec) {
                continue;
            }
            let sec_off = *section_offsets
                .get(&(oi, si))
                .expect("section offset must be known for emitted section");
            for r in &sec.relocations {
                let patch_site = sec_off
                    .checked_add(r.virtual_address)
                    .ok_or_else(|| anyhow!("reloc patch site overflow"))?;
                let target = resolved
                    .get(&(oi, r.symbol_index))
                    .ok_or_else(|| {
                        anyhow!(
                            "reloc in object {} section `{}` references unknown symbol #{}",
                            oi,
                            sec.name,
                            r.symbol_index
                        )
                    })?
                    .clone();

                // Special-case __imp_* REL32: defer to the packer.
                if let SymbolResolution::External(name) = &target {
                    if name.starts_with(SYM_IMP_PREFIX)
                        && r.kind == CoffRelocKind::Amd64Rel32
                    {
                        let p = patch_site as usize;
                        ensure!(p + 4 <= text.len(), "REL32 patch site OOB");
                        let addend = LittleEndian::read_i32(&text[p..p + 4]);
                        // Zero out the slot; the packer will fill in the
                        // final 32-bit displacement to .idata2.
                        LittleEndian::write_i32(&mut text[p..p + 4], 0);
                        imp_rel32_sites.push(ImpRel32Site {
                            offset: patch_site,
                            api_name: name[SYM_IMP_PREFIX.len()..].to_string(),
                            addend,
                        });
                        continue;
                    }
                }

                apply_relocation(
                    &mut text,
                    &mut abs_fixups,
                    patch_site,
                    r.kind,
                    &target,
                    &local_symbols,
                )
                .with_context(|| {
                    format!(
                        "applying reloc @{:#x} in object {} section `{}` -> {:?}",
                        r.virtual_address, oi, sec.name, target
                    )
                })?;
            }
        }
    }

    // ---- Phase 5: locate the TLS callback entry -------------------------
    let tls_callback_offset = *local_symbols
        .get(SYM_TLS_CALLBACK)
        .ok_or_else(|| anyhow!("stub does not define `{}`", SYM_TLS_CALLBACK))?;

    Ok(LinkedStub {
        text,
        tls_callback_offset,
        abs_fixups,
        imp_rel32_sites,
        external_symbols,
        local_symbols,
    })
}

#[derive(Debug, Clone)]
enum SymbolResolution {
    /// Defined within the linked stub at this offset in `text`.
    Offset(u32),
    /// Refers to an undefined external symbol of this name.
    External(String),
    /// Absolute / non-relocatable constant (rarely useful).
    Absolute(u32),
    /// Debug / placeholder entry. Should not be referenced by relocs.
    Skip,
}

fn section_is_emitted(sec: &CoffSection) -> bool {
    let c = sec.characteristics;
    if c & (IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_LNK_INFO | IMAGE_SCN_MEM_DISCARDABLE) != 0 {
        return false;
    }
    // Skip empty BSS / data placeholders that clang always emits.
    if sec.data.is_empty() && sec.virtual_size == 0 {
        return false;
    }
    true
}

fn classify_section(sec: &CoffSection) -> Result<()> {
    let c = sec.characteristics;
    if c & (IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_LNK_INFO | IMAGE_SCN_MEM_DISCARDABLE) != 0 {
        return Ok(());
    }
    let is_uninit = c & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0;
    let is_init_data = c & IMAGE_SCN_CNT_INITIALIZED_DATA != 0;
    let is_code = c & IMAGE_SCN_CNT_CODE != 0;

    if is_uninit && (sec.data.len() > 0 || sec.virtual_size > 0) {
        bail!(
            "stub may not contain BSS section `{}` (size={}); freestanding stubs cannot have writable globals",
            sec.name,
            sec.virtual_size.max(sec.data.len() as u32)
        );
    }
    if is_init_data && !sec.data.is_empty() {
        // We allow read-only data sections (rdata-style), but not
        // writable globals.
        if c & 0x8000_0000 != 0 {
            bail!(
                "stub may not contain writable data section `{}`",
                sec.name
            );
        }
    }
    let _ = is_code;
    Ok(())
}

/// Sort key for grouped sections such as `.text$AAA`. Returns the
/// section name as-is; lexicographic comparison gives the desired
/// ordering (`.text` < `.text$AAA` < `.text$AAB` < `.text$ZZZ`).
fn section_sort_key(name: &str) -> String {
    name.to_string()
}

fn align_to(buf: &mut Vec<u8>, align: usize) {
    let pad = (align - (buf.len() % align)) % align;
    if pad > 0 {
        buf.extend(std::iter::repeat(0u8).take(pad));
    }
}

fn apply_relocation(
    text: &mut Vec<u8>,
    abs_fixups: &mut Vec<AbsFixup>,
    patch_site: u32,
    kind: CoffRelocKind,
    target: &SymbolResolution,
    local_symbols: &BTreeMap<String, u32>,
) -> Result<()> {
    let p = patch_site as usize;
    match kind {
        CoffRelocKind::Amd64Rel32 => {
            ensure!(p + 4 <= text.len(), "REL32 patch site OOB");
            let addend = LittleEndian::read_i32(&text[p..p + 4]) as i64;
            let target_off = resolve_offset(target, local_symbols)? as i64;
            let value = target_off + addend - (patch_site as i64) - 4;
            ensure!(
                value >= i32::MIN as i64 && value <= i32::MAX as i64,
                "REL32 displacement {} out of range",
                value
            );
            LittleEndian::write_i32(&mut text[p..p + 4], value as i32);
        }
        CoffRelocKind::Amd64Addr64 => {
            ensure!(p + 8 <= text.len(), "ADDR64 patch site OOB");
            let addend = LittleEndian::read_i64(&text[p..p + 8]);
            // Pre-write the addend + target_offset; the writer will OR
            // in stub_base_va later.
            let target_off = resolve_offset(target, local_symbols)? as i64;
            let pre = target_off.wrapping_add(addend);
            LittleEndian::write_i64(&mut text[p..p + 8], pre);
            abs_fixups.push(AbsFixup {
                offset: patch_site,
                width: 8,
                target: target_to_fixup(target),
            });
        }
        CoffRelocKind::Amd64Addr32 => {
            ensure!(p + 4 <= text.len(), "ADDR32 patch site OOB");
            let addend = LittleEndian::read_i32(&text[p..p + 4]) as i64;
            let target_off = resolve_offset(target, local_symbols)? as i64;
            let pre = target_off.wrapping_add(addend) as i32;
            LittleEndian::write_i32(&mut text[p..p + 4], pre);
            abs_fixups.push(AbsFixup {
                offset: patch_site,
                width: 4,
                target: target_to_fixup(target),
            });
        }
        CoffRelocKind::Amd64Addr32Nb => {
            ensure!(p + 4 <= text.len(), "ADDR32NB patch site OOB");
            // Image-relative (RVA). For M3 we don't expect this; reject.
            bail!(
                "IMAGE_REL_AMD64_ADDR32NB not supported in M3 stub linking"
            );
        }
        CoffRelocKind::Amd64Section | CoffRelocKind::Amd64SecRel => {
            // Debug-only relocations from compiler-generated sections;
            // we already filter those sections out, so reaching here is
            // a parser bug.
            bail!("unexpected debug-only relocation reached emitted text");
        }
        CoffRelocKind::Other(raw) => {
            bail!("unsupported AMD64 relocation kind 0x{:04x}", raw);
        }
    }
    Ok(())
}

fn resolve_offset(
    target: &SymbolResolution,
    local_symbols: &BTreeMap<String, u32>,
) -> Result<u32> {
    match target {
        SymbolResolution::Offset(off) => Ok(*off),
        SymbolResolution::External(name) => local_symbols
            .get(name)
            .copied()
            .ok_or_else(|| anyhow!("external symbol `{}` was not materialised", name)),
        SymbolResolution::Absolute(v) => Ok(*v),
        SymbolResolution::Skip => bail!("relocation references a non-resolvable symbol slot"),
    }
}

fn target_to_fixup(target: &SymbolResolution) -> FixupTarget {
    match target {
        SymbolResolution::External(name) => match name.as_str() {
            SYM_ORIGINAL_OEP => FixupTarget::OriginalOep,
            SYM_ORIGINAL_TLS_CALLBACK => FixupTarget::OriginalTlsCallback,
            SYM_PAYLOAD_BLOB => FixupTarget::PayloadBlobVa,
            SYM_STUB_SELF_RVA => FixupTarget::StubSelfRva,
            other if other.starts_with(SYM_IMP_PREFIX) => {
                FixupTarget::ImportThunk(other[SYM_IMP_PREFIX.len()..].to_string())
            }
            _ => FixupTarget::LocalSymbol(name.clone()),
        },
        SymbolResolution::Offset(_) => {
            // Store as anonymous local; writer just adds stub_base_va.
            FixupTarget::LocalSymbol(String::new())
        }
        SymbolResolution::Absolute(_) | SymbolResolution::Skip => {
            FixupTarget::LocalSymbol(String::new())
        }
    }
}
