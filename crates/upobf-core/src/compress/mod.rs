//! Compression (LZMA primary; framing helpers).

pub mod lzma;

pub use lzma::{compress as lzma_compress, decompress as lzma_decompress};
