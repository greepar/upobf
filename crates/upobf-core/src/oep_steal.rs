//! OEP-stealing prologue analyzer (Phase I, cross-platform).
//!
//! Picks a prefix of the host's entry-point function and lifts it
//! into a heap trampoline so a memory dump captures `jmp <heap>` at
//! the OEP. Re-running the dump on a fresh process lands in unmapped
//! memory and crashes immediately.
//!
//! The analyzer accepts two classes of input bytes:
//!
//!   1. **Position-independent (PI)** instructions — copied
//!      verbatim into the trampoline.
//!
//!   2. **`call rel32` / `jmp rel32` / `jmp rel8`** — *rewritten*
//!      to absolute indirect form so the trampoline can run at any
//!      VA. Conditional branches are rejected (could be added with
//!      a slightly larger gadget; the current set already covers
//!      every NativeAOT shim entry we care about).
//!
//! The output describes both the **original** byte range we
//! covered (`steal_len`, the bytes the stub will overwrite with
//! its abs-jmp gadget) and the **encoded** trampoline body
//! (`encoded`, what the stub copies into the heap page). They are
//! distinct: rewriting `E8 disp32` (5 bytes) into `FF 15 ... .quad`
//! (16 bytes) inflates the encoded form.
//!
//! ## Rewrites
//!
//! | Source              | Bytes | Trampoline emits                                    | Bytes |
//! |---------------------|------:|-----------------------------------------------------|------:|
//! | PI instruction      |     n | verbatim copy                                       |     n |
//! | `call rel32` (E8)   |     5 | `FF 15 02 .. EB 08 .quad abs`                       |    16 |
//! | `jmp rel32` (E9)    |     5 | `FF 25 00 .. .quad abs`                              |    14 |
//! | `jmp rel8`  (EB)    |     2 | `FF 25 00 .. .quad abs`                              |    14 |
//!
//! The `call` rewrite needs an unconditional jump over the inline
//! abs target so fall-through after the call lands on the next
//! instruction in our stream — without it, the CPU would interpret
//! the .quad as code.
//!
//! ## Constraints
//!
//! - We never harvest more than [`OEP_STEAL_MAX`] *encoded* bytes,
//!   capped at 64 to fit the wire-format slot in `PayloadHeader`.
//! - We always harvest at least [`OEP_PATCH_GADGET_LEN`] *original*
//!   bytes, the size of the abs-jmp gadget the stub writes back
//!   into the host's OEP. If we can't reach 14 bytes of original
//!   coverage on instruction boundaries before encoding overflows
//!   64, we fail and the packer skips Phase I for this binary.
//!
//! Cross-platform: the analysis only depends on x86_64 ISA bytes; it
//! does not care whether the bytes come from a PE `.text` or an ELF
//! `.text`. PE callers pass `image_base = OptionalHeader.ImageBase`,
//! ELF callers pass `image_base = 0` for ET_DYN/PIE images (where
//! ld.so picks the actual base at run time and stub addends in the
//! VA space relative to ImageBase).

use anyhow::{anyhow, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};

/// Minimum original-byte coverage for the stub's abs-jmp gadget
/// (`FF 25 00 00 00 00` + 8-byte target).
pub const OEP_PATCH_GADGET_LEN: usize = 14;

/// Maximum encoded bytes we ever store. Mirrors the on-wire
/// `PayloadHeader.oep_stolen_bytes[64]` slot.
pub const OEP_STEAL_MAX: usize = 64;

/// Result of analysing the host's OEP prologue.
#[derive(Debug, Clone)]
pub struct StolenPrologue {
    /// Number of *original* bytes lifted out of the host's `.text`.
    /// The packer replaces this many bytes with `0xCC` int3 fillers
    /// before compression; the stub later patches them with its
    /// 14-byte abs-jmp gadget at run time.
    pub steal_len: usize,
    /// Encoded trampoline body: PI bytes copied verbatim and
    /// rel-branches rewritten to abs indirect form. Length is in
    /// `OEP_PATCH_GADGET_LEN..=OEP_STEAL_MAX`.
    pub encoded: Vec<u8>,
    /// RVA at which the stolen prologue started.
    pub rva: u32,
}

/// Analyse the prologue of the host's entry-point function.
pub fn analyze_oep_prologue(
    text_bytes: &[u8],
    oep_rva: u32,
    image_base: u64,
) -> Result<StolenPrologue> {
    if text_bytes.is_empty() {
        return Err(anyhow!("empty .text bytes for OEP analysis"));
    }
    let oep_va: u64 = image_base.wrapping_add(oep_rva as u64);

    let mut decoder = Decoder::with_ip(64, text_bytes, oep_va, DecoderOptions::NONE);
    let mut steal_len: usize = 0;
    let mut encoded: Vec<u8> = Vec::with_capacity(OEP_STEAL_MAX);

    while decoder.can_decode() {
        let mut insn = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        let len = insn.len();
        let next_steal = steal_len + len;

        // Decide encoding for this instruction.
        let mut emit: Vec<u8> = Vec::new();
        if is_position_independent(&insn) {
            emit.extend_from_slice(&text_bytes[steal_len..steal_len + len]);
        } else if let Some(target) = relbranch_target(&insn) {
            // Pick the right rewrite.
            let opcode_byte = text_bytes[steal_len];
            match opcode_byte {
                0xE8 => {
                    // call rel32 -> FF 15 02 .. EB 08 <abs>
                    emit.extend_from_slice(&[
                        0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, // call [rip+2]
                        0xEB, 0x08, // jmp +8 (skip the .quad)
                    ]);
                    emit.extend_from_slice(&target.to_le_bytes());
                }
                0xE9 | 0xEB => {
                    // jmp rel32 / rel8 -> FF 25 00 .. <abs>
                    emit.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
                    emit.extend_from_slice(&target.to_le_bytes());
                }
                _ => {
                    // Conditional / loop / xbegin etc. — rejection
                    // path. Stop accepting more bytes, but keep
                    // whatever we already have.
                    break;
                }
            }
        } else {
            // Cannot move and cannot rewrite — bail.
            break;
        }

        if encoded.len() + emit.len() > OEP_STEAL_MAX {
            break;
        }
        encoded.extend_from_slice(&emit);
        steal_len = next_steal;

        // Stop once we have enough original coverage. Lock to the
        // smallest accepted >= patch gadget length on an instruction
        // boundary; harvesting more strictly decreases dump
        // survivability margin (the post-gadget bytes we leave intact)
        // without RE benefit.
        if steal_len >= OEP_PATCH_GADGET_LEN {
            break;
        }
    }

    if steal_len < OEP_PATCH_GADGET_LEN {
        return Err(anyhow!(
            "could not harvest {} original bytes at OEP RVA {:#x} (got {} bytes / {} encoded)",
            OEP_PATCH_GADGET_LEN,
            oep_rva,
            steal_len,
            encoded.len(),
        ));
    }
    if encoded.len() < OEP_PATCH_GADGET_LEN || encoded.len() > OEP_STEAL_MAX {
        return Err(anyhow!(
            "encoded length {} out of range [{}..={}]",
            encoded.len(),
            OEP_PATCH_GADGET_LEN,
            OEP_STEAL_MAX
        ));
    }
    Ok(StolenPrologue {
        steal_len,
        encoded,
        rva: oep_rva,
    })
}

/// Return the absolute target VA if `insn` is a rewritable
/// `call rel*` / `jmp rel*`; otherwise `None`.
fn relbranch_target(insn: &Instruction) -> Option<u64> {
    if insn.flow_control() != FlowControl::UnconditionalBranch
        && insn.flow_control() != FlowControl::Call
    {
        return None;
    }
    for i in 0..insn.op_count() {
        match insn.op_kind(i) {
            OpKind::NearBranch16
            | OpKind::NearBranch32
            | OpKind::NearBranch64 => return Some(insn.near_branch_target()),
            _ => {}
        }
    }
    None
}

/// Return `true` if this single instruction can be moved to a
/// different VA without rewriting any of its operand bytes.
fn is_position_independent(insn: &Instruction) -> bool {
    if insn.is_ip_rel_memory_operand() {
        return false;
    }
    for i in 0..insn.op_count() {
        if insn.op_kind(i) == OpKind::Memory && insn.memory_base() == Register::RIP {
            return false;
        }
    }
    match insn.flow_control() {
        FlowControl::Next
        | FlowControl::Return
        | FlowControl::IndirectBranch
        | FlowControl::IndirectCall => {}
        _ => return false,
    }
    for i in 0..insn.op_count() {
        match insn.op_kind(i) {
            OpKind::NearBranch16
            | OpKind::NearBranch32
            | OpKind::NearBranch64
            | OpKind::FarBranch16
            | OpKind::FarBranch32 => return false,
            _ => {}
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harvests_clean_pi_prologue() {
        // sub rsp,0x28; mov [rsp+0x20],rcx; xor eax,eax; mov rax,rcx (14 bytes total)
        let bytes = vec![
            0x48, 0x83, 0xEC, 0x28, 0x48, 0x89, 0x4C, 0x24, 0x20, 0x33, 0xC0, 0x48, 0x89, 0xC8,
        ];
        let s = analyze_oep_prologue(&bytes, 0x1000, 0x140000000).unwrap();
        assert_eq!(s.steal_len, 14);
        assert_eq!(s.encoded.len(), 14); // verbatim
        assert_eq!(&s.encoded[..], &bytes[..]);
        assert_eq!(s.rva, 0x1000);
    }

    #[test]
    fn handles_nativeaot_shim() {
        // sub rsp,0x28; call rel32 +0x993; add rsp,0x28; jmp rel32 -0x18E
        // Total 18 original bytes; encoded:
        //   sub rsp,0x28                              4 bytes verbatim
        //   call -> FF 15 02 .. EB 08 + abs(+0x99C)   16 bytes
        //   add rsp,0x28                              4 bytes verbatim
        //   jmp  -> FF 25 00 .. + abs(-0x172)         14 bytes
        // = 38 encoded.
        let bytes = vec![
            0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28          (4, PI)
            0xE8, 0x93, 0x09, 0x00, 0x00, // call rel32 +0x993      (5, rewriteable)
            0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28          (4, PI)
            0xE9, 0x72, 0xFE, 0xFF, 0xFF, // jmp  rel32 -0x18E      (5, rewriteable)
        ];
        let s = analyze_oep_prologue(&bytes, 0x1783E10, 0x140000000).unwrap();
        assert_eq!(s.steal_len, 18);
        // Encoded length: 4 + 16 + 4 + 14 = 38
        assert_eq!(s.encoded.len(), 38);
        // First 4 bytes are verbatim sub rsp,0x28.
        assert_eq!(&s.encoded[..4], &bytes[..4]);
        // Next 16 bytes are the call rewrite. Spot-check opcodes.
        assert_eq!(&s.encoded[4..10], &[0xFF, 0x15, 0x02, 0x00, 0x00, 0x00]);
        assert_eq!(&s.encoded[10..12], &[0xEB, 0x08]);
        // Then verbatim add rsp,0x28
        assert_eq!(&s.encoded[20..24], &[0x48, 0x83, 0xC4, 0x28]);
        // Then jmp rewrite
        assert_eq!(&s.encoded[24..30], &[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn stops_before_rip_relative() {
        let mut bytes = vec![0x48, 0x83, 0xEC, 0x28]; // sub rsp,0x28
        bytes.extend_from_slice(&[0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00]); // mov rax,[rip+0x10]
        let res = analyze_oep_prologue(&bytes, 0x1000, 0x140000000);
        assert!(res.is_err(), "should fail: only 4 PI bytes < gadget len");
    }

    #[test]
    fn stops_before_conditional_jump() {
        // sub rsp,0x28; je rel32 — conditional, not rewriteable.
        let bytes = vec![
            0x48, 0x83, 0xEC, 0x28, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,
        ];
        let res = analyze_oep_prologue(&bytes, 0x1000, 0x140000000);
        assert!(res.is_err());
    }

    #[test]
    fn handles_short_jmp_rel8() {
        // sub rsp,0x28; jmp rel8 +0x10  — only 6 original bytes, < 14, must fail.
        let bytes = vec![0x48, 0x83, 0xEC, 0x28, 0xEB, 0x10];
        let res = analyze_oep_prologue(&bytes, 0x1000, 0x140000000);
        assert!(res.is_err(), "6 bytes < gadget len, must fail");
    }
}
