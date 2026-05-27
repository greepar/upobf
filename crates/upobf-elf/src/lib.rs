//! upobf-elf: Linux ELF (x64) parsing, layout planning and packing.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod parse;

pub use parse::ElfImage;

#[cfg(test)]
mod unit_tests;
