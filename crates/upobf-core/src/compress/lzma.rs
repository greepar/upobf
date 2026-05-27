//! LZMA compression wrapper.
//!
//! Two on-disk formats exist for LZMA in `liblzma`:
//!
//! - **`.xz` container**: produced by [`xz2::stream::Stream::new_easy_encoder`].
//!   Carries a stream header, integrity check (CRC32/CRC64/SHA-256), one or
//!   more block headers, an index and a stream footer. Recommended for files
//!   on disk because it is self-describing and tamper-evident.
//! - **`.lzma` / "alone" / *raw* LZMA1**: produced by
//!   [`xz2::stream::Stream::new_lzma_encoder`] and decoded by
//!   [`xz2::stream::Stream::new_lzma_decoder`]. The header is a tiny 13-byte
//!   structure (1 byte properties, 4 bytes dict size, 8 bytes uncompressed
//!   size or `u64::MAX`), with no integrity check. Smallest framing overhead
//!   for in-memory payloads.
//!
//! upobf embeds compressed payload chunks inside the packed PE image and the
//! decompressor lives inside the runtime stub. We do **not** want to ship a
//! `.xz` container parser inside the stub, nor pay for a CRC check that the
//! outer ChaCha20 layer already implies (and the CRC watchdog re-verifies).
//! We therefore use the *alone / raw LZMA1* framing here, with preset 6 as
//! the default to match the `liblzma` defaults.
//!
//! The 13-byte alone header is intentionally kept by the encoder: the
//! decompressor needs the dict size and properties bytes. Stripping it would
//! save a handful of bytes per chunk but force us to reimplement parts of the
//! `lzma_alone_decoder` initialization in the stub. The trade-off is not
//! worth it for the M2 payload sizes in scope.

use anyhow::{Context, Result};
use xz2::stream::{Action, LzmaOptions, Status, Stream};

/// Default compression level (matches `xz -6`).
pub const DEFAULT_LEVEL: u32 = 6;

/// Decoder memory limit, in bytes. 256 MiB is well above what preset 9 needs
/// (~675 MiB worst case dict, but our preset 6 needs ~16 MiB) and avoids
/// false `MemLimit` errors on adversarial inputs.
const DECODER_MEMLIMIT: u64 = 256 * 1024 * 1024;

/// Compress `input` with LZMA1 alone-format using the default preset.
pub fn compress(input: &[u8]) -> Result<Vec<u8>> {
    compress_with_level(input, DEFAULT_LEVEL)
}

/// Compress `input` with LZMA1 alone-format at the given preset (`0..=9`).
///
/// Levels above 9 are clamped by `liblzma` and will return an error; we
/// surface that as an [`anyhow::Error`].
pub fn compress_with_level(input: &[u8], level: u32) -> Result<Vec<u8>> {
    let opts = LzmaOptions::new_preset(level)
        .with_context(|| format!("LzmaOptions::new_preset({level}) failed"))?;
    let mut stream =
        Stream::new_lzma_encoder(&opts).context("Stream::new_lzma_encoder failed")?;

    // Output starts with the 13-byte alone header plus compressed payload.
    // Reserve a sensible upper bound: header + input + 1% margin + 64 B.
    let mut output: Vec<u8> = Vec::with_capacity(input.len() + input.len() / 100 + 128);

    run_stream(&mut stream, input, &mut output).context("LZMA encode loop failed")?;

    Ok(output)
}

/// Decompress an LZMA1 alone-format stream produced by [`compress`].
pub fn decompress(input: &[u8]) -> Result<Vec<u8>> {
    let mut stream =
        Stream::new_lzma_decoder(DECODER_MEMLIMIT).context("Stream::new_lzma_decoder failed")?;

    // We do not know the original size; start with 4x input and let the
    // grow loop in `run_stream` handle the rest.
    let mut output: Vec<u8> = Vec::with_capacity(input.len().saturating_mul(4).max(64));

    run_stream(&mut stream, input, &mut output).context("LZMA decode loop failed")?;

    Ok(output)
}

/// Drive a `Stream` to completion against `input`, appending into `output`.
///
/// `process_vec` writes into the *spare capacity* of `output`, so we have to
/// keep `output.capacity() > output.len()` whenever we feed the stream more
/// data, otherwise it returns immediately with no progress and we spin.
fn run_stream(stream: &mut Stream, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
    let mut consumed = 0usize;

    loop {
        // Make sure there is at least 4 KiB of spare capacity.
        let spare = output.capacity() - output.len();
        if spare < 4096 {
            output.reserve(64 * 1024);
        }

        let action = if consumed == input.len() {
            Action::Finish
        } else {
            Action::Run
        };

        let in_before = stream.total_in();
        let status = stream
            .process_vec(&input[consumed..], output, action)
            .context("xz2 process_vec returned an error")?;
        let in_after = stream.total_in();
        consumed += (in_after - in_before) as usize;

        match status {
            Status::Ok => {
                // Need to feed more input or have more output room.
                continue;
            }
            Status::StreamEnd => {
                return Ok(());
            }
            Status::GetCheck => {
                // Only meaningful for `.xz`; ignore.
                continue;
            }
            Status::MemNeeded => {
                anyhow::bail!("LZMA decoder reported MemNeeded above {DECODER_MEMLIMIT} bytes");
            }
        }
    }
}
