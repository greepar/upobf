//! ChaCha20 stream cipher (IETF variant, RFC 8439).
//!
//! - 256-bit key, 96-bit nonce, 32-bit block counter that always starts at 0.
//! - Encryption and decryption are the *same* operation (XOR with keystream).
//!   We expose both names because the surrounding pipeline reads more clearly
//!   when the intent is encoded at the call site.
//! - **Nonce reuse is catastrophic** for stream ciphers: identical
//!   `(key, nonce)` pairs produce identical keystreams, so XORing two
//!   ciphertexts cancels the keystream. Pick a fresh nonce per encryption
//!   (e.g. derive it via [`super::prng::Polymorphic::derive_nonce`]).
//!
//! Built on the RustCrypto `chacha20` crate's `cipher::StreamCipher` trait.

use anyhow::Result;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

/// 256-bit ChaCha20 key.
pub type Key = [u8; 32];
/// 96-bit IETF ChaCha20 nonce.
pub type Nonce = [u8; 12];

/// XOR `data` in place with the ChaCha20 keystream derived from `(key, nonce)`.
///
/// The block counter starts at 0 and the operation runs over the entire
/// `data` slice in one shot.
pub fn encrypt_in_place(data: &mut [u8], key: &Key, nonce: &Nonce) -> Result<()> {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(data);
    Ok(())
}

/// Stream-cipher decryption is XOR with the same keystream. Provided as a
/// distinct symbol so callers can be explicit about direction.
pub fn decrypt_in_place(data: &mut [u8], key: &Key, nonce: &Nonce) -> Result<()> {
    encrypt_in_place(data, key, nonce)
}

/// Allocating wrapper around [`encrypt_in_place`].
pub fn encrypt(data: &[u8], key: &Key, nonce: &Nonce) -> Result<Vec<u8>> {
    let mut out = data.to_vec();
    encrypt_in_place(&mut out, key, nonce)?;
    Ok(out)
}

/// Allocating wrapper around [`decrypt_in_place`].
pub fn decrypt(data: &[u8], key: &Key, nonce: &Nonce) -> Result<Vec<u8>> {
    let mut out = data.to_vec();
    decrypt_in_place(&mut out, key, nonce)?;
    Ok(out)
}
