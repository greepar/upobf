//! ELF writer.
//!
//! See [`writer::PackedElfBuilder`] for the entry point.

pub mod stub_loader;
pub mod writer;

pub use stub_loader::StubBlob;
pub use writer::PackedElfBuilder;
