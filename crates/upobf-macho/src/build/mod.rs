//! Mach-O writer / packer.
//!
//! Takes a parsed `MachoImage`, compressed ranges, stub blob, and payload,
//! then produces a new Mach-O binary with:
//! - Compressed sections replaced by zero-fill (file-shrink)
//! - New `__UPOBF0` segment (stub code, R+X)
//! - New `__UPOBF1` segment (encrypted payload, R)
//! - `LC_MAIN.entryoff` rewritten to stub trampoline
//! - `LC_CODE_SIGNATURE` dropped (user re-signs)

pub mod stub_loader;
pub mod writer;
