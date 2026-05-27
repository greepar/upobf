//! Per-build polymorphic selection of PE section names.
//!
//! The MVP picked the literal names `.upobf0`, `.upobf1`, `.reloc2` for
//! the three sections it appends to the host image. Static-analysis
//! tools like Detect-It-Easy / DIE / pestudio match those strings as a
//! hard signature and immediately label the file as packed by `upobf`.
//!
//! This module replaces them with names sampled from pools of plausible
//! compiler / linker section names that real production binaries
//! actually use. The choice is reproducible per master seed so a build's
//! random state can be recovered for debugging.
//!
//! Constraints:
//! - PE `IMAGE_SECTION_HEADER.Name` is exactly 8 bytes, NUL-padded.
//! - Names must NOT collide with any name already used by the host
//!   image (the OS Loader does not require uniqueness but having two
//!   sections named `.text` confuses every dumper and is itself a
//!   suspicious tell).
//! - Pool members are fixed (we cannot ship truly random names because
//!   "novel" 8-byte strings are themselves a signature). They are taken
//!   from a survey of MSVC, clang-cl, MinGW and Rust output.
//!
//! Pools are split by intended characteristics:
//! - [`EXEC_POOL`] for sections marked `IMAGE_SCN_MEM_EXECUTE` (stub).
//! - [`RDATA_POOL`] for `READ`-only initialised-data sections (payload).
//! - [`RELOC_POOL`] for the auxiliary base-reloc table.

use rand::RngCore;
use rand_chacha::ChaCha20Rng;

/// Names that show up as executable code sections in real binaries.
///
/// `.text` itself is intentionally absent — the host already has one,
/// and our pickers reject collisions. Listed alternatives are emitted
/// by either `/SECTION:.text=...` linker overrides, MASM/JWasm output,
/// or runtime hot-patch toolchains.
pub const EXEC_POOL: &[&[u8]] = &[
    b".text2",
    b".CRTHUNK",
    b".prsl",
    b".tcfg",
    b".thunks",
    b".jmp",
    b".trampln",
    b".vcj",
    b".clr",
    b".mtl",
];

/// Names that show up as read-only initialised-data sections.
pub const RDATA_POOL: &[&[u8]] = &[
    b".rdata2",
    b".xdata",
    b".gfids",
    b".00cfg",
    b".gehcont",
    b".didat",
    b".rdcfg",
    b".rstr",
    b".cstr",
    b".vec",
];

/// Names suitable for an auxiliary base-reloc / debug-style section.
/// Members of this pool MUST be acceptable when marked discardable.
pub const RELOC_POOL: &[&[u8]] = &[
    b".reloc2",
    b".reloc3",
    b".relocX",
    b".rsrc2",
    b".pdata2",
    b".rldata",
    b".rmeta",
    b".retplx",
];

/// Pad-or-truncate a byte slice to the 8-byte `IMAGE_SECTION_HEADER.Name`
/// shape.
pub fn pad_section_name(s: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    let n = s.len().min(8);
    out[..n].copy_from_slice(&s[..n]);
    out
}

/// Pick a name from `pool` that is not already in `used`.
///
/// Falls back to appending an incrementing suffix to the first pool
/// entry if every candidate is exhausted (impossible with pool size >>
/// host section count in practice, but kept for robustness).
pub fn pick_unique(
    pool: &[&[u8]],
    rng: &mut ChaCha20Rng,
    used: &[[u8; 8]],
) -> [u8; 8] {
    debug_assert!(!pool.is_empty(), "section name pool must be non-empty");
    for _ in 0..(pool.len() * 4) {
        let idx = (rng.next_u32() as usize) % pool.len();
        let candidate = pad_section_name(pool[idx]);
        if !used.contains(&candidate) {
            return candidate;
        }
    }
    // Fallback path. Replaces last byte with an incrementing digit so
    // we still produce a name (worst case: collision with an already
    // numbered fallback in the same call -- caller guards against that
    // by also adding pool entries to `used`).
    let mut out = pad_section_name(pool[0]);
    for d in 0..=9u8 {
        out[7] = b'0' + d;
        if !used.contains(&out) {
            return out;
        }
    }
    out
}

/// Pick three distinct, non-colliding section names for the appended
/// upobf sections (stub-text, payload-data, aux-reloc). The third value
/// is `None` if the caller doesn't actually need a reloc section.
pub fn pick_three(
    rng: &mut ChaCha20Rng,
    host_section_names: &[[u8; 8]],
) -> ([u8; 8], [u8; 8], [u8; 8]) {
    let mut used: Vec<[u8; 8]> = host_section_names.to_vec();
    let exec = pick_unique(EXEC_POOL, rng, &used);
    used.push(exec);
    let data = pick_unique(RDATA_POOL, rng, &used);
    used.push(data);
    let reloc = pick_unique(RELOC_POOL, rng, &used);
    (exec, data, reloc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::prng::Polymorphic;

    fn rng_for(seed: u8) -> ChaCha20Rng {
        let p = Polymorphic::new([seed; 32]);
        p.rng("section.names")
    }

    #[test]
    fn pick_three_no_collision_with_host() {
        let host = vec![pad_section_name(b".text"), pad_section_name(b".rdata")];
        for s in 0u8..16 {
            let mut rng = rng_for(s);
            let (a, b, c) = pick_three(&mut rng, &host);
            assert_ne!(a, b);
            assert_ne!(a, c);
            assert_ne!(b, c);
            assert!(!host.contains(&a));
            assert!(!host.contains(&b));
            assert!(!host.contains(&c));
        }
    }

    #[test]
    fn pick_three_is_polymorphic_across_seeds() {
        // Different master seeds should usually yield at least one
        // differing name. A handful of seeds are enough — we only need
        // to confirm the generator does respond to entropy.
        let host = vec![pad_section_name(b".text")];
        let mut seen = std::collections::HashSet::new();
        for s in 0u8..32 {
            let mut rng = rng_for(s);
            seen.insert(pick_three(&mut rng, &host));
        }
        // Trivial bound: more than one unique tuple across 32 seeds.
        assert!(seen.len() > 1, "name picker is degenerate");
    }

    #[test]
    fn pick_three_stable_for_same_seed() {
        let host: Vec<[u8; 8]> = vec![];
        let mut a = rng_for(7);
        let mut b = rng_for(7);
        assert_eq!(pick_three(&mut a, &host), pick_three(&mut b, &host));
    }
}
