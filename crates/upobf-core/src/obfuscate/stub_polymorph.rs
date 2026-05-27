//! Per-build byte-level polymorphism for the linked stub.
//!
//! Goal: invalidate any signature DB that fingerprints the upobf stub
//! by raw bytes. Without this pass every packed binary contains the
//! exact same ~13 KiB of clang-emitted machine code, indexed by
//! `tls_callback_offset`. A scanner only needs the first 32 bytes of
//! the TLS-callback prologue to flag the file as packed by us.
//!
//! Strategy: append a small *trampoline* and a deterministic random
//! tail to the linked stub, then have the OS Loader call the
//! trampoline instead of the real C callback. The trampoline:
//!
//!   1. Executes a sequence of instructions sampled from an ABI-safe
//!      pool (push/pop pairs, multi-byte NOPs, `xchg rax,rax`,
//!      `test rN,rN`, etc.). Every instruction is balanced so the
//!      register/stack state at the trampoline's tail is identical to
//!      its head. Flags are clobbered freely; the real callback's
//!      prologue is robust to that.
//!   2. Tail-jumps into the original `tls_callback_offset` via a
//!      `JMP rel32`. The displacement is computed relative to the
//!      trampoline's tail, so the rest of the stub remains
//!      position-independent.
//!   3. Is followed by 64..256 bytes of high-entropy "dead data"
//!      derived from the master seed. The bytes are unreachable but
//!      contribute to the section's hash, ensuring SHA256 diversity
//!      across builds even when the chosen instruction sequence
//!      happens to repeat.
//!
//! The pass mutates [`LinkedStub::text`] (length grows), updates
//! [`LinkedStub::entry_offset`] to point at the trampoline head, and
//! leaves [`LinkedStub::tls_callback_offset`] (the real C function)
//! untouched. The packer wires those two fields like this:
//!
//! - `__upobf_stub_self_rva` slot   <- stub_section_rva + tls_callback_offset
//! - TLS callback array entry        <- ImageBase + stub_section_rva + entry_offset
//!
//! That is, the real callback recovers `ImageBase` correctly because
//! its own VA still equals `image_base + tls_callback_offset` after
//! the trampoline is appended (we only `append`, never `prepend`).
//!
//! The pass is reproducible from the master seed; same seed yields the
//! same trampoline bytes. Different seeds produce different trampoline
//! lengths, instruction sequences, register choices, and tail bytes.

use anyhow::{bail, Result};
use byteorder::{ByteOrder, LittleEndian};
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};
use rand_chacha::ChaCha20Rng;

use crate::crypto::prng::Polymorphic;
use crate::stub_link::LinkedStub;

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Total trampoline body length, *excluding* the final `JMP rel32`.
/// Sampled uniformly from this list. Keeping it bounded means the
/// trampoline never bloats the section by more than ~80 + 5 + 256 =
/// 341 bytes, well below any sensible threshold.
const BODY_LENGTH_CHOICES: &[usize] = &[24, 40, 56, 72, 96];

/// Tail dead-data length range (inclusive both ends).
const TAIL_MIN: usize = 64;
const TAIL_MAX: usize = 192;

/// Caller-saved general-purpose registers we may freely push/pop.
/// `RSP` and `RBP` are excluded so we never touch the stack frame in
/// surprising ways. `RBX`/`RSI`/`RDI`/`R12..R15` are callee-saved on
/// the Microsoft x64 ABI; we skip them because the surrounding C
/// function may rely on them being live across the trampoline.
///
/// The actual encoders below pick from sub-pools (low / high) directly
/// via `pick_low_reg` / `pick_high_reg`; this constant is kept for
/// documentation. `#[allow(dead_code)]` is intentional.
#[allow(dead_code)]
const SAFE_REGS: &[u8] = &[
    0, // RAX
    1, // RCX
    2, // RDX
    8, // R8
    9, // R9
    10, // R10
    11, // R11
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Apply byte-level polymorphism to `stub`. Returns a new `LinkedStub`
/// with `text` extended, `entry_offset` rewritten to point at the
/// trampoline, and all other fields unchanged.
///
/// `poly` is the per-build polymorphic context; the pass uses
/// distinct labels so it doesn't disturb the entropy other passes
/// (payload key derivation, section name picking) consume.
pub fn apply(mut stub: LinkedStub, poly: &Polymorphic) -> Result<LinkedStub> {
    let mut len_rng = poly.rng("stub.poly.length");
    let mut body_rng = poly.rng("stub.poly.body");
    let mut tail_rng = poly.rng("stub.poly.tail");

    // ---- 1. Choose dimensions ------------------------------------------
    let body_target = *BODY_LENGTH_CHOICES
        .choose(&mut len_rng)
        .expect("BODY_LENGTH_CHOICES is non-empty");
    let tail_len = TAIL_MIN + (len_rng.next_u32() as usize) % (TAIL_MAX - TAIL_MIN + 1);

    // ---- 2. Generate body ----------------------------------------------
    let body = generate_body(body_target, &mut body_rng);
    debug_assert_eq!(
        body.len(),
        body_target,
        "body generator returned {} bytes for target {}",
        body.len(),
        body_target
    );

    // ---- 3. Lay it out into stub.text ----------------------------------
    // Pad text to 16-byte alignment first so the trampoline starts on a
    // cache line boundary (also gives us deterministic offsets).
    align_to(&mut stub.text, 16);
    let trampoline_off: u32 = stub
        .text
        .len()
        .try_into()
        .map_err(|_| anyhow::anyhow!("stub text exceeds u32 range"))?;
    stub.text.extend_from_slice(&body);

    // ---- 4. Append `JMP rel32` to original entry -----------------------
    // E9 disp32, where `disp32 = target - (rip_after_jmp)`.
    // `rip_after_jmp = trampoline_off + body.len() + 5`.
    let jmp_site = trampoline_off as usize + body.len();
    let rip_after = (jmp_site + 5) as i64;
    let target = stub.tls_callback_offset as i64;
    let disp = target - rip_after;
    if !(-(1i64 << 31)..(1i64 << 31)).contains(&disp) {
        bail!(
            "trampoline JMP displacement {} would overflow i32 (target={:#x}, site={:#x})",
            disp,
            target,
            jmp_site,
        );
    }
    stub.text.push(0xE9);
    let mut disp_bytes = [0u8; 4];
    LittleEndian::write_i32(&mut disp_bytes, disp as i32);
    stub.text.extend_from_slice(&disp_bytes);

    // ---- 5. Tail dead data ---------------------------------------------
    let mut tail = vec![0u8; tail_len];
    tail_rng.fill_bytes(&mut tail);
    // Stamp a `INT3` (0xCC) at the very front of the dead data so that
    // any accidental fall-through (must not happen, but defence in
    // depth) traps immediately rather than starts decoding random bytes
    // as instructions.
    if !tail.is_empty() {
        tail[0] = 0xCC;
    }
    stub.text.extend_from_slice(&tail);

    // ---- 6. Hand back ---------------------------------------------------
    stub.entry_offset = trampoline_off;
    Ok(stub)
}

// ---------------------------------------------------------------------------
// Body generator
// ---------------------------------------------------------------------------

/// Generate exactly `target` bytes of ABI-neutral instructions sampled
/// from the safe pool. The implementation greedily picks instructions
/// until the remaining budget is small enough that only a NOP of
/// matching length can still fit, then plugs the gap with multi-byte
/// NOPs.
fn generate_body(target: usize, rng: &mut ChaCha20Rng) -> Vec<u8> {
    let mut out = Vec::with_capacity(target);
    while out.len() < target {
        let remaining = target - out.len();
        let instr = pick_safe_instr(remaining, rng);
        out.extend_from_slice(&instr);
    }
    out
}

/// Pick one safe instruction whose encoding length is `<= max_len`.
/// Always returns at least 1 byte. We bias toward push/pop and reg-reg
/// moves so the body looks like compiler output rather than alignment
/// padding.
fn pick_safe_instr(max_len: usize, rng: &mut ChaCha20Rng) -> Vec<u8> {
    debug_assert!(max_len > 0);

    // Generators by produced length (1..=9). Each entry is a closure
    // that materialises an encoding given the rng. We dispatch by the
    // length we *want* this slot to be, picked by `decide_len` below.
    let len = decide_len(max_len, rng);
    match len {
        1 => one_byte(rng),
        2 => two_byte(rng),
        3 => three_byte(rng),
        4 => four_byte(rng),
        5 => five_byte(rng),
        6 => six_byte(rng),
        7 => seven_byte(rng),
        8 => eight_byte(rng),
        9 => nine_byte(rng),
        _ => unreachable!(),
    }
}

fn decide_len(max_len: usize, rng: &mut ChaCha20Rng) -> usize {
    // Distribution: prefer 2..=5 byte instructions to look natural;
    // clamp to the available budget. We cannot exceed budget because
    // the tail of the body must always be representable.
    let cap = max_len.min(9);
    let table: &[usize] = &[2, 3, 3, 4, 4, 5, 5, 2, 3, 1, 6, 7, 8, 9];
    loop {
        let pick = table[rng.gen_range(0..table.len())];
        if pick <= cap {
            return pick;
        }
    }
}

// --------- Length-keyed encoders -------------------------------------

fn one_byte(rng: &mut ChaCha20Rng) -> Vec<u8> {
    // Choices:
    //  - 0x90  NOP
    //  - 0x50+rd PUSH r64 (low regs only)  -- but pop in same slot is
    //    impossible (we'd unbalance), so push/pop pairs need >=2 bytes.
    //    Stick to NOP at length 1.
    let _ = rng;
    vec![0x90]
}

fn two_byte(rng: &mut ChaCha20Rng) -> Vec<u8> {
    let choice = rng.gen_range(0..6);
    match choice {
        // PUSH r64 ; POP r64 (same reg). Encodes as 50+rd, 58+rd. Both
        // 1 byte for low regs => total 2 bytes. Stack-balanced.
        0 => {
            let r = pick_low_reg(rng);
            vec![0x50 | r, 0x58 | r]
        }
        // 66 90: 2-byte NOP (operand size override + NOP).
        1 => vec![0x66, 0x90],
        // 87 C0..C0+r/m: XCHG rN, rN -- only legal for non-XCHG-pair
        // forms; XCHG eax,eax is 0x87 C0 with 32-bit operand. To keep
        // the body 64-bit-clean we use NOP-equivalent 2-byte encodings
        // instead.
        2 => vec![0x66, 0x90],
        // F3 90: PAUSE -- legal anywhere, no architectural effect
        // beyond a hint to the CPU. Useful for variety.
        3 => vec![0xF3, 0x90],
        // F2 90: REPNE NOP -- redundant prefix, decoded as NOP.
        // Some CPUs may flag a stall but functionally a NOP.
        // We avoid it to stay vanilla.
        // Fall-through to two NOPs.
        _ => vec![0x90, 0x90],
    }
}

fn three_byte(rng: &mut ChaCha20Rng) -> Vec<u8> {
    let choice = rng.gen_range(0..4);
    match choice {
        // 0F 1F 00: 3-byte NOP, official Intel recommended.
        0 => vec![0x0F, 0x1F, 0x00],
        // PUSH r64 (high reg, REX.B = 1) + POP r64 (high reg).
        // PUSH: 41 50+r. POP: 41 58+r. Total 2+2 = 4 bytes -- doesn't
        // fit at 3. Skip and fall back.
        1 => vec![0x0F, 0x1F, 0x00],
        // TEST rN, rN where N is a low reg.
        // Encoding: 48 85 C0+r*9 (mod=11, reg=src, r/m=dst).
        // ModR/M for `test r/m64, r64` with same reg N (0..7):
        //   ModR/M = 11_NNN_NNN = 0xC0 | (N<<3) | N
        // 3 bytes total (REX.W + opcode + ModR/M).
        2 => {
            let r = pick_low_reg(rng);
            let modrm: u8 = 0xC0 | (r << 3) | r;
            vec![0x48, 0x85, modrm]
        }
        // OR rN, rN: 48 09 C0+r*9. Behaves like TEST for flag setting.
        // 3 bytes.
        _ => {
            let r = pick_low_reg(rng);
            let modrm: u8 = 0xC0 | (r << 3) | r;
            vec![0x48, 0x09, modrm]
        }
    }
}

fn four_byte(rng: &mut ChaCha20Rng) -> Vec<u8> {
    let choice = rng.gen_range(0..4);
    match choice {
        // 0F 1F 40 00: 4-byte NOP.
        0 => vec![0x0F, 0x1F, 0x40, 0x00],
        // PUSH high_reg ; POP high_reg : 2 bytes + 2 bytes = 4 bytes.
        1 => {
            let h = pick_high_reg(rng);
            // PUSH r64: 41 50+rd  (rd = N - 8)
            // POP r64:  41 58+rd
            let rd = h - 8;
            vec![0x41, 0x50 | rd, 0x41, 0x58 | rd]
        }
        // PUSH low + POP same low + 0x66 90 (operand-size NOP)
        // = 1+1+2 = 4 bytes.
        2 => {
            let r = pick_low_reg(rng);
            vec![0x50 | r, 0x58 | r, 0x66, 0x90]
        }
        // 4-byte NOP variant: 0F 1F 40 xx where xx is sib/disp (=0).
        _ => vec![0x0F, 0x1F, 0x40, 0x00],
    }
}

fn five_byte(_rng: &mut ChaCha20Rng) -> Vec<u8> {
    // 0F 1F 44 00 00: 5-byte NOP, Intel recommended.
    vec![0x0F, 0x1F, 0x44, 0x00, 0x00]
}

fn six_byte(_rng: &mut ChaCha20Rng) -> Vec<u8> {
    // 66 0F 1F 44 00 00: 6-byte NOP.
    vec![0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00]
}

fn seven_byte(_rng: &mut ChaCha20Rng) -> Vec<u8> {
    // 0F 1F 80 00 00 00 00: 7-byte NOP.
    vec![0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]
}

fn eight_byte(_rng: &mut ChaCha20Rng) -> Vec<u8> {
    // 0F 1F 84 00 00 00 00 00: 8-byte NOP.
    vec![0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]
}

fn nine_byte(_rng: &mut ChaCha20Rng) -> Vec<u8> {
    // 66 0F 1F 84 00 00 00 00 00: 9-byte NOP.
    vec![0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pick_low_reg(rng: &mut ChaCha20Rng) -> u8 {
    // RAX(0), RCX(1), RDX(2). Skip RBX(3) (callee-saved), RSP/RBP/RSI/RDI.
    *[0u8, 1, 2].choose(rng).unwrap()
}

fn pick_high_reg(rng: &mut ChaCha20Rng) -> u8 {
    // R8..R11 (caller-saved on Win64).
    *[8u8, 9, 10, 11].choose(rng).unwrap()
}

fn align_to(buf: &mut Vec<u8>, align: usize) {
    debug_assert!(align.is_power_of_two());
    let pad = (align - (buf.len() % align)) % align;
    if pad == 0 {
        return;
    }
    buf.extend(std::iter::repeat(0xCC).take(pad)); // INT3 padding
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stub_link::{ExternalSymbol, LinkedStub};
    use std::collections::BTreeMap;

    fn fake_stub(callback_off: u32, total_len: usize) -> LinkedStub {
        let text = vec![0xCC; total_len];
        LinkedStub {
            text,
            tls_callback_offset: callback_off,
            entry_offset: callback_off,
            abs_fixups: vec![],
            imp_rel32_sites: vec![],
            external_symbols: vec![ExternalSymbol {
                name: "__upobf_payload_blob".into(),
            }],
            local_symbols: BTreeMap::new(),
        }
    }

    fn poly(seed: u8) -> Polymorphic {
        Polymorphic::new([seed; 32])
    }

    #[test]
    fn entry_moves_to_trampoline_head() {
        let stub = fake_stub(0x100, 0x400);
        let original_callback = stub.tls_callback_offset;
        let original_text_len = stub.text.len();
        let polymorphed = apply(stub, &poly(7)).unwrap();
        // Real callback offset is preserved.
        assert_eq!(polymorphed.tls_callback_offset, original_callback);
        // Entry now points at or past the original text (we only ever
        // append; the trampoline head sits at the post-alignment fill
        // boundary).
        assert!(polymorphed.entry_offset as usize >= original_text_len);
        // Entry must be 16-byte aligned.
        assert_eq!(polymorphed.entry_offset % 16, 0);
        // Total text grew by at least body_min + 5 (JMP) + tail_min.
        let min_growth = BODY_LENGTH_CHOICES.iter().min().unwrap() + 5 + TAIL_MIN;
        assert!(polymorphed.text.len() >= original_text_len + min_growth);
    }

    #[test]
    fn jmp_lands_on_real_callback() {
        let stub = fake_stub(0x100, 0x400);
        let polymorphed = apply(stub, &poly(11)).unwrap();
        let entry = polymorphed.entry_offset as usize;
        // Walk until we find the JMP. Body length is one of
        // BODY_LENGTH_CHOICES; the JMP starts at entry + body_len.
        let mut found = None;
        for &body_len in BODY_LENGTH_CHOICES {
            let jmp_off = entry + body_len;
            if jmp_off + 5 > polymorphed.text.len() {
                continue;
            }
            if polymorphed.text[jmp_off] == 0xE9 {
                found = Some((body_len, jmp_off));
                break;
            }
        }
        let (body_len, jmp_off) = found.expect("did not find JMP rel32 marker");
        let disp = LittleEndian::read_i32(&polymorphed.text[jmp_off + 1..jmp_off + 5]);
        let landing = (jmp_off + 5) as i64 + disp as i64;
        assert_eq!(
            landing as u32, polymorphed.tls_callback_offset,
            "JMP at body_len={} did not land on real callback",
            body_len
        );
    }

    #[test]
    fn polymorphic_across_seeds() {
        // 16 seeds should produce a wide variety of trampoline bytes.
        let mut seen_lens: std::collections::HashSet<usize> = Default::default();
        let mut seen_hashes: std::collections::HashSet<Vec<u8>> = Default::default();
        for s in 0u8..16 {
            let stub = fake_stub(0x100, 0x400);
            let polymorphed = apply(stub, &poly(s)).unwrap();
            seen_lens.insert(polymorphed.text.len());
            // Hash just the appended bytes (entry_offset onwards) so
            // the comparison is meaningful.
            seen_hashes.insert(polymorphed.text[polymorphed.entry_offset as usize..].to_vec());
        }
        assert!(
            seen_lens.len() >= 3,
            "expected multiple total lengths across seeds, got {}",
            seen_lens.len()
        );
        assert!(
            seen_hashes.len() >= 12,
            "expected mostly-unique trampolines, got {} of 16",
            seen_hashes.len()
        );
    }

    #[test]
    fn deterministic_for_same_seed() {
        let a = apply(fake_stub(0x100, 0x400), &poly(42)).unwrap();
        let b = apply(fake_stub(0x100, 0x400), &poly(42)).unwrap();
        assert_eq!(a.text, b.text);
        assert_eq!(a.entry_offset, b.entry_offset);
    }

    #[test]
    fn no_dangerous_byte_patterns() {
        // Sweep many seeds and confirm we never emit:
        //  - 0F 05  (SYSCALL)
        //  - 0F 34  (SYSENTER)
        //  - 0F 30  (WRMSR)
        //  - CD     (INT n, except CC INT3 which we use as padding sentinel)
        // We only check the *body*, not the tail (random data is allowed).
        for s in 0u8..32 {
            let stub = fake_stub(0x100, 0x400);
            let polymorphed = apply(stub.clone(), &poly(s)).unwrap();
            let entry = polymorphed.entry_offset as usize;
            // Body ends just before the JMP rel32. Locate it by
            // scanning for E9 within the first BODY_LENGTH_CHOICES.max
            // bytes after entry; the first E9 we hit is the JMP.
            let mut jmp_off: Option<usize> = None;
            let max_body = *BODY_LENGTH_CHOICES.iter().max().unwrap();
            for i in 0..=max_body {
                if entry + i + 5 > polymorphed.text.len() {
                    break;
                }
                if polymorphed.text[entry + i] == 0xE9 && BODY_LENGTH_CHOICES.contains(&i) {
                    jmp_off = Some(entry + i);
                    break;
                }
            }
            let jmp = jmp_off.unwrap_or_else(|| panic!("no JMP found for seed {}", s));
            let body = &polymorphed.text[entry..jmp];
            for (i, w) in body.windows(2).enumerate() {
                let dangerous = matches!(w, [0x0F, 0x05] | [0x0F, 0x34] | [0x0F, 0x30]);
                assert!(!dangerous, "seed {}: dangerous opcode at body[{}]", s, i);
            }
            for (i, &b) in body.iter().enumerate() {
                // INT n other than INT3: CD xx (so any 0xCD that is not
                // followed by 03). We also explicitly forbid 0xCC inside
                // the body (it's only allowed as padding/tail sentinel).
                if b == 0xCD {
                    panic!("seed {}: INT n at body[{}]", s, i);
                }
                if b == 0xCC {
                    panic!("seed {}: stray INT3 inside body at [{}]", s, i);
                }
            }
        }
    }
}
