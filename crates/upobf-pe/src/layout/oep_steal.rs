//! Phase I: OEP-stealing prologue analyzer — PE re-export shim.
//!
//! The implementation is now in [`upobf_core::oep_steal`]. PE call
//! sites continue to use this module's namespace; ELF call sites
//! consume `upobf_core::oep_steal` directly.

pub use upobf_core::oep_steal::{
    analyze_oep_prologue, StolenPrologue, OEP_PATCH_GADGET_LEN, OEP_STEAL_MAX,
};
