//! upobf-pe: Windows PE (x64) parsing, layout planning and packing.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod parse;
pub mod layout;
pub mod build;

pub use parse::PeImage;

#[cfg(test)]
mod unit_tests;
