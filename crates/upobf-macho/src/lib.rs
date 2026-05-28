//! upobf-macho: macOS Mach-O (arm64) parser and packer.
//!
//! This crate provides:
//! - `parse::MachoImage` — structured representation of a Mach-O 64-bit binary
//! - `layout::safe_ranges` — forbidden/safe range computation for compression
//! - `build::writer` — writer / packer for producing obfuscated output
//! - `pack` — end-to-end packing pipeline
//!
//! ## Current status (vs Linux/Windows)
//!
//! Working:
//! - Runtime decompression of __DATA safe regions (1.8MB on PatchInstaller)
//! - Per-page chained fixup chain walk (safe_ranges avoids fixup pages)
//! - Entry redirect via LC_MAIN → stub trampoline
//! - Polymorphic encryption (ChaCha20 + per-pack random seed)
//! - GOT-based mmap/mprotect/munmap resolution from host binary
//! - Ad-hoc codesign compatible output
//!
//! TODO (not yet at parity with Linux/Windows):
//! - Watchdog CRC32 thread: requires resolving dyld APIs (_dyld_image_count
//!   etc.) which the host binary doesn't import. Need to implement direct
//!   dyld shared cache resolution or add imports to host's chained fixups.
//! - __TEXT compression: AMFI page hash verification prevents runtime writes
//!   to __TEXT. Possible via MAP_JIT + pthread_jit_write_protect_np but high
//!   risk and requires com.apple.security.cs.allow-jit entitlement.
//! - File shrink for mid-segment compression: current implementation only
//!   shrinks when compressed ranges form a contiguous tail. Need segment
//!   splitting (like ELF PT_LOAD split) for mid-segment holes.
//! - BCJ arm64 filter: code exists in stub but not yet enabled in packer
//!   (evaluate compression gain on __DATA code-like sections).

pub mod build;
pub mod layout;
pub mod pack;
pub mod parse;
