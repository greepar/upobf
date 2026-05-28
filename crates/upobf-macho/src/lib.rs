//! upobf-macho: macOS Mach-O (arm64) parser and packer.
//!
//! This crate provides:
//! - `parse::MachoImage` — structured representation of a Mach-O 64-bit binary
//! - `build::writer` — writer / packer for producing obfuscated output
//! - `pack` — end-to-end packing pipeline

pub mod build;
pub mod layout;
pub mod pack;
pub mod parse;
