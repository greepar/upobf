//! Layout planning for ELF packing.
//!
//! Currently surfaces [`safe_ranges`] (forbidden-range computation
//! used by Phase E in-place section compression). M1L baseline does
//! not yet drive compression; it stops at writer round-tripping.

pub mod safe_ranges;
