//! Layout analysis for Mach-O compression.
//!
//! Determines which byte ranges in the binary can be safely compressed
//! without breaking dyld's chained fixup chain walk or other load-time
//! data structures.

pub mod safe_ranges;
