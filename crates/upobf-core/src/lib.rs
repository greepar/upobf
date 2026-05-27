//! upobf-core: cross-platform packer/obfuscator core.
//!
//! Modules:
//! - [`compress`]   LZMA compression (and BCJ-friendly framing).
//! - [`crypto`]     ChaCha20 stream cipher and PRNG for polymorphism.
//! - [`filter`]     Pre-compression transforms (BCJ for x86/x64).
//! - [`obfuscate`]  String encryption, bin2bin mutation passes.
//! - [`policy`]     Build presets (av-friendly / aggressive).
//! - [`stub_link`]  Relocates compiled stub blobs into a target image.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod compress;
pub mod crypto;
pub mod filter;
pub mod obfuscate;
pub mod policy;
pub mod stub_link;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
