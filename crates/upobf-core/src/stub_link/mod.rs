//! Stub linker.
//!
//! Parses compiled stub COFF objects and links them into a single blob
//! ready to be embedded into the packed PE. See [`coff`] for the parser
//! and [`relocator`] for the linker.

pub mod coff;
pub mod relocator;

pub use coff::{
    parse as parse_coff, CoffFileHeader, CoffObject, CoffRelocKind, CoffRelocation, CoffSection,
    CoffSymbol, IMAGE_FILE_MACHINE_AMD64,
};
pub use relocator::{
    link, AbsFixup, ExternalSymbol, FixupTarget, LinkedStub, SYM_IMP_PREFIX, SYM_ORIGINAL_OEP,
    SYM_ORIGINAL_TLS_CALLBACK, SYM_PAYLOAD_BLOB, SYM_STUB_SELF_RVA, SYM_TLS_CALLBACK,
};
