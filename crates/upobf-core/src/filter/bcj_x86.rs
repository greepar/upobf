//! BCJ filter for x86 / x86-64 code.
//!
//! BCJ ("Branch / Call / Jump") is the same trick LZMA SDK and `xz` use to
//! pre-process executable code before the LZ stage: rewrite the *relative*
//! 32-bit displacement that follows a `0xE8` (`CALL rel32`) or `0xE9`
//! (`JMP rel32`) opcode into the *absolute* target address. After the
//! transform, identical call sites that target the same function produce
//! identical 4-byte patterns regardless of where they appear in the section,
//! which compresses dramatically better than relative offsets do.
//!
//! ## Conservative, not perfect
//!
//! The filter is byte-oriented: it does **not** disassemble. Any time it
//! sees a `0xE8` or `0xE9` byte with at least four trailing bytes, it
//! tentatively treats the next four bytes as a `rel32` and rewrites them.
//! That will occasionally rewrite bytes that were not really `call`/`jmp`
//! displacements (immediate operands, the second byte of a multi-byte
//! instruction, plain data). Two design choices keep this safe:
//!
//! 1. **Unconditional, position-driven rewrite.** Both forward and backward
//!    rewrite at *every* `E8`/`E9` opcode that has 4 trailing bytes. The
//!    decision to rewrite is taken purely on the buffer position, never on
//!    the value being read. This makes the transform bit-exactly reversible
//!    for any `base_addr`: if `forward` decided to touch position `i`, then
//!    `backward` will examine the same position `i` (because the opcode
//!    byte is untouched) and undo the change.
//! 2. **Skip past the displacement.** After rewriting at position `i` we
//!    advance to `i + 5`, so the four displacement bytes are not themselves
//!    re-scanned for nested `E8`/`E9`. Forward and backward use the same
//!    skip rule, which is what preserves reversibility in the presence of
//!    `E8`/`E9` bytes inside displacement data.
//!
//! The filter therefore costs us a small amount of compression efficiency
//! on data that happens to contain `E8`/`E9` bytes outside real call sites,
//! but never corrupts the round-trip.
//!
//! ## `base_addr`
//!
//! `base_addr` is the virtual address at which the *first* byte of `data`
//! will live in the loaded image. For example, when filtering the contents
//! of `.text` whose `RVA = 0x1000`, you would pass `base_addr =
//! image_base + 0x1000`. The transform is reversible for any `base_addr`
//! value as long as the same value is used for `forward` and `backward`, so
//! when in doubt pass the section's RVA alone (`0x1000`).
//!
//! See `LZMA SDK / C/Bra86.c` and `xz/src/liblzma/simple/x86.c` for the
//! historical reference implementation.

/// Apply the forward BCJ transform: `rel32` → `abs32` after every
/// `0xE8` / `0xE9` byte that has 4 trailing bytes.
pub fn forward(data: &mut [u8], base_addr: u32) {
    convert(data, base_addr, true);
}

/// Apply the inverse BCJ transform: `abs32` → `rel32`.
pub fn backward(data: &mut [u8], base_addr: u32) {
    convert(data, base_addr, false);
}

/// Core sweep. `encoding == true` does forward (rel→abs); `false` does
/// backward (abs→rel).
fn convert(data: &mut [u8], base_addr: u32, encoding: bool) {
    if data.len() < 5 {
        return;
    }

    // Highest opcode index where a full rel32 still fits.
    let limit = data.len() - 4;
    let mut i = 0usize;

    while i < limit {
        let op = data[i];
        if op != 0xE8 && op != 0xE9 {
            i += 1;
            continue;
        }

        let disp_off = i + 1;
        let cur = u32::from_le_bytes([
            data[disp_off],
            data[disp_off + 1],
            data[disp_off + 2],
            data[disp_off + 3],
        ]);

        // `pc` matches x86 CALL/JMP semantics: the address of the byte
        // *after* the rel32. Opcode at `base_addr + i`, displacement at
        // `+ 1..+ 5`, so pc == base_addr + i + 5.
        let pc = base_addr.wrapping_add(i as u32).wrapping_add(5);

        let new = if encoding {
            cur.wrapping_add(pc) // rel -> abs
        } else {
            cur.wrapping_sub(pc) // abs -> rel
        };

        let bytes = new.to_le_bytes();
        data[disp_off] = bytes[0];
        data[disp_off + 1] = bytes[1];
        data[disp_off + 2] = bytes[2];
        data[disp_off + 3] = bytes[3];

        // Skip past the 5-byte instruction so the 4 displacement bytes are
        // not re-scanned. Forward and backward must use the same skip rule
        // for reversibility.
        i += 5;
    }
}
