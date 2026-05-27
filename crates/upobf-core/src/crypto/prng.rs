//! Polymorphic seed source.
//!
//! A [`Polymorphic`] holds a single 32-byte master seed (chosen per build,
//! either deterministically for tests or from `OsRng` for shipping artifacts).
//! All other secrets the packer needs (per-chunk keys, per-chunk nonces, RNGs
//! that drive code mutation, name salts, etc.) are derived from that single
//! seed via labeled key derivation. This way a packed binary's full random
//! state can be reproduced from one 32-byte value when debugging, while a
//! shipping build still gets fresh entropy on every invocation.
//!
//! ## Key derivation: simplified, **not** RFC-5869 HKDF
//!
//! The plan calls for an HKDF-SHA256 style `Expand` step. RustCrypto's
//! `hkdf` crate would give us a NIST-compliant implementation, but it pulls
//! in `hmac` and another wrapper layer for what is, in our threat model, a
//! purely *internal* derivation: the master seed is already a high-entropy,
//! uniformly-distributed 32-byte secret, never exposed off-process, and the
//! derived material only feeds ChaCha20 and `rand_chacha`. In that setting
//! `SHA256(master || label)` is indistinguishable from random under the
//! random-oracle model and avoids the extra crates.
//!
//! We document this clearly so nobody mistakes it for an interoperable HKDF
//! and tries to derive cross-tool keys with it.

use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use super::chacha20::{Key, Nonce};

/// A 32-byte master polymorphic context.
#[derive(Debug, Clone)]
pub struct Polymorphic {
    master_seed: [u8; 32],
}

impl Polymorphic {
    /// Wrap an already-chosen master seed (typically used in tests for
    /// reproducible builds, or by callers that want to persist a build's
    /// entropy to a file).
    pub fn new(master_seed: [u8; 32]) -> Self {
        Self { master_seed }
    }

    /// Pull 32 fresh bytes from the OS CSPRNG and use them as the master seed.
    pub fn from_os_rng() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self { master_seed: seed }
    }

    /// Borrow the master seed (e.g. to persist for reproducibility).
    pub fn master_seed(&self) -> &[u8; 32] {
        &self.master_seed
    }

    /// Derive 32 bytes labeled by `label`.
    ///
    /// Uses `SHA256(master_seed || label)`. See module docs for why this is
    /// not full HKDF.
    pub fn derive(&self, label: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.master_seed);
        hasher.update(label.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Derive a 32-byte ChaCha20 key labeled by `label`.
    pub fn derive_key(&self, label: &str) -> Key {
        self.derive(label)
    }

    /// Derive a 12-byte ChaCha20 nonce labeled by `label`.
    ///
    /// We hash with a `"nonce:"` prefix so [`derive_key("foo")`] and
    /// [`derive_nonce("foo")`] produce *different* output for the same label,
    /// which is what every caller intuitively expects.
    pub fn derive_nonce(&self, label: &str) -> Nonce {
        let mut hasher = Sha256::new();
        hasher.update(self.master_seed);
        hasher.update(b"nonce:");
        hasher.update(label.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 12];
        out.copy_from_slice(&digest[..12]);
        out
    }

    /// Spawn a labeled `rand_chacha` PRNG seeded from `derive(label)`.
    ///
    /// Useful for code-mutation passes that need many random choices but
    /// must be reproducible from the master seed.
    pub fn rng(&self, label: &str) -> ChaCha20Rng {
        ChaCha20Rng::from_seed(self.derive(label))
    }

    /// Sample a single u32 from a labeled PRNG. Convenience wrapper so
    /// callers can avoid pulling in `rand`/`rand_core` themselves.
    pub fn next_u32(&self, label: &str) -> u32 {
        self.rng(label).next_u32()
    }

    /// Sample a single u64 from a labeled PRNG.
    pub fn next_u64(&self, label: &str) -> u64 {
        self.rng(label).next_u64()
    }
}
