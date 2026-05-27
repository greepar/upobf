//! M2 smoke tests: LZMA round-trip, ChaCha20 KAT (RFC 8439 §2.3.2), polymorphic
//! key-derivation stability, and BCJ x86/x64 round-trip.

use upobf_core::compress::lzma;
use upobf_core::crypto::chacha20 as chacha;
use upobf_core::crypto::prng::Polymorphic;
use upobf_core::filter::bcj_x86;

// ---------------------------------------------------------------------------
// LZMA
// ---------------------------------------------------------------------------

const ONE_MB: usize = 1024 * 1024;

#[test]
fn lzma_roundtrip_zeros_compresses_well() {
    let input = vec![0u8; ONE_MB];
    let compressed = lzma::compress(&input).expect("compress zeros");
    let decompressed = lzma::decompress(&compressed).expect("decompress zeros");

    assert_eq!(decompressed.len(), input.len());
    assert_eq!(decompressed, input);

    // Zeros should compress to well below 1% of the input.
    assert!(
        compressed.len() < input.len() / 100,
        "1MB of zeros compressed to {} bytes (expected < 10 KB)",
        compressed.len()
    );
}

#[test]
fn lzma_roundtrip_random_does_not_blow_up() {
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    // Deterministic RNG so the size-overhead bound below is reproducible.
    let mut rng = StdRng::seed_from_u64(0xC0FFEE_F00D_BAAD);
    let mut input = vec![0u8; ONE_MB];
    rng.fill_bytes(&mut input);

    let compressed = lzma::compress(&input).expect("compress random");
    let decompressed = lzma::decompress(&compressed).expect("decompress random");

    assert_eq!(decompressed, input);

    // Random data is incompressible. We allow up to 1% overhead vs raw input.
    let max_allowed = input.len() + input.len() / 100 + 4096;
    assert!(
        compressed.len() <= max_allowed,
        "incompressible 1MB blew up to {} bytes (cap {} bytes)",
        compressed.len(),
        max_allowed
    );
}

#[test]
fn lzma_roundtrip_pseudocode_pattern_compresses_well() {
    // Simulated "code-like" repeating instruction byte patterns.
    let pattern = vec![
        0x48, 0x89, 0xC8, // mov rax, rcx
        0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
        0xE8, 0x00, 0x00, 0x00, 0x00, // call rel32
        0xC9, 0xC3, // leave; ret
    ];
    let input: Vec<u8> = pattern
        .iter()
        .copied()
        .cycle()
        .take(256 * 1024)
        .collect();

    let compressed = lzma::compress(&input).expect("compress pattern");
    let decompressed = lzma::decompress(&compressed).expect("decompress pattern");

    assert_eq!(decompressed, input);

    // Highly repetitive: must compress to under 1% of input.
    assert!(
        compressed.len() < input.len() / 100,
        "{} bytes of repeated pattern compressed to {} bytes",
        input.len(),
        compressed.len()
    );
}

#[test]
fn lzma_levels_all_roundtrip() {
    let input: Vec<u8> = (0..=255u8).cycle().take(64 * 1024).collect();
    for level in 0u32..=9 {
        let compressed = lzma::compress_with_level(&input, level)
            .unwrap_or_else(|e| panic!("compress level {level}: {e}"));
        let decompressed = lzma::decompress(&compressed)
            .unwrap_or_else(|e| panic!("decompress level {level}: {e}"));
        assert_eq!(decompressed, input, "level {level} roundtrip mismatch");
    }
}

// ---------------------------------------------------------------------------
// ChaCha20 KAT — RFC 8439 §2.3.2 Test Vector #1 (block function, counter = 0).
// ---------------------------------------------------------------------------
//
// key   = 00..00 (32 bytes)
// nonce = 00..00 (12 bytes)
// ctr   = 0
// Encrypting 64 zero bytes yields the first 64 bytes of the keystream.

#[test]
fn chacha20_rfc8439_zero_key_zero_nonce_keystream() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut buf = [0u8; 64];

    chacha::encrypt_in_place(&mut buf, &key, &nonce).unwrap();

    let expected: [u8; 64] = [
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd,
        0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77,
        0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8,
        0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69,
        0xb2, 0xee, 0x65, 0x86,
    ];

    assert_eq!(buf, expected, "ChaCha20 RFC 8439 §2.3.2 vector mismatch");
}

#[test]
fn chacha20_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let nonce = [0x77u8; 12];
    let original = b"upobf payload chunk: BCJ + LZMA + ChaCha20".repeat(37);

    let ciphertext = chacha::encrypt(&original, &key, &nonce).unwrap();
    assert_ne!(ciphertext, original, "ciphertext must differ from plaintext");

    let recovered = chacha::decrypt(&ciphertext, &key, &nonce).unwrap();
    assert_eq!(recovered, original);
}

#[test]
fn chacha20_in_place_matches_allocating() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let original: Vec<u8> = (0u8..=200).collect();

    let allocated = chacha::encrypt(&original, &key, &nonce).unwrap();
    let mut in_place = original.clone();
    chacha::encrypt_in_place(&mut in_place, &key, &nonce).unwrap();
    assert_eq!(in_place, allocated);
}

// ---------------------------------------------------------------------------
// Polymorphic key derivation stability
// ---------------------------------------------------------------------------

#[test]
fn polymorphic_same_seed_same_label_same_key() {
    let seed = *b"upobf-test-seed-32-bytes-XXXXXXX";
    let p1 = Polymorphic::new(seed);
    let p2 = Polymorphic::new(seed);

    assert_eq!(p1.derive("text-key"), p2.derive("text-key"));
    assert_eq!(p1.derive_key("rdata-key"), p2.derive_key("rdata-key"));
    assert_eq!(p1.derive_nonce("rdata-nonce"), p2.derive_nonce("rdata-nonce"));
}

#[test]
fn polymorphic_different_label_different_key() {
    let seed = *b"upobf-test-seed-32-bytes-XXXXXXX";
    let p = Polymorphic::new(seed);

    let k_text = p.derive_key("text-key");
    let k_rdata = p.derive_key("rdata-key");
    assert_ne!(k_text, k_rdata);

    let n_a = p.derive_nonce("chunk-A");
    let n_b = p.derive_nonce("chunk-B");
    assert_ne!(n_a, n_b);
}

#[test]
fn polymorphic_different_seed_different_key() {
    let p1 = Polymorphic::new([0u8; 32]);
    let p2 = Polymorphic::new([1u8; 32]);

    assert_ne!(p1.derive("label"), p2.derive("label"));
}

#[test]
fn polymorphic_key_and_nonce_label_namespaces_differ() {
    // derive_key and derive_nonce with the same label must differ —
    // otherwise a caller using the same label for both would re-use bytes.
    let p = Polymorphic::new([7u8; 32]);
    let k = p.derive_key("foo");
    let n = p.derive_nonce("foo");
    assert_ne!(&k[..12], &n[..]);
}

#[test]
fn polymorphic_rng_is_deterministic() {
    use rand::RngCore;
    let seed = [0xABu8; 32];
    let mut a = Polymorphic::new(seed).rng("mutate");
    let mut b = Polymorphic::new(seed).rng("mutate");

    let mut buf_a = [0u8; 64];
    let mut buf_b = [0u8; 64];
    a.fill_bytes(&mut buf_a);
    b.fill_bytes(&mut buf_b);
    assert_eq!(buf_a, buf_b);

    let mut c = Polymorphic::new(seed).rng("other-label");
    let mut buf_c = [0u8; 64];
    c.fill_bytes(&mut buf_c);
    assert_ne!(buf_a, buf_c);
}

// ---------------------------------------------------------------------------
// BCJ x86/x64 round-trip
// ---------------------------------------------------------------------------

fn sample_x64_code() -> Vec<u8> {
    // A mock function prologue / epilogue with several CALL/JMP rel32 sites
    // and some non-call data interleaved.
    vec![
        0x55, // push rbp
        0x48, 0x89, 0xE5, // mov rbp, rsp
        0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
        0xE8, 0x12, 0x34, 0x56, 0x78, // call rel32 (will be filtered)
        0x48, 0x8B, 0x05, 0x10, 0x20, 0x30, 0x40, // mov rax, [rip+disp32]
        0xE9, 0xAA, 0xBB, 0xCC, 0xDD, // jmp rel32 (will be filtered)
        0x90, 0x90, 0x90, // nop sled
        0xE8, 0x00, 0x00, 0x00, 0x00, // call rel32 to next insn
        0xC9, 0xC3, // leave; ret
        // Trailing data containing E8/E9 bytes that we still expect to
        // round-trip cleanly.
        0xE8, 0xE9, 0xE8, 0xE9, 0xE8, 0xE9, 0xE8, 0xE9, 0x00, 0x11, 0x22, 0x33,
    ]
}

#[test]
fn bcj_roundtrip_basic() {
    let original = sample_x64_code();
    let mut buf = original.clone();

    bcj_x86::forward(&mut buf, 0x1000);
    assert_ne!(buf, original, "forward must change at least one byte");

    bcj_x86::backward(&mut buf, 0x1000);
    assert_eq!(buf, original, "backward(forward(x)) must equal x");
}

#[test]
fn bcj_roundtrip_various_base_addresses() {
    let original = sample_x64_code();
    for base in [0u32, 0x1000, 0x4000_1000, 0xFFFF_FFF0, 0x7FFF_FFFF] {
        let mut buf = original.clone();
        bcj_x86::forward(&mut buf, base);
        bcj_x86::backward(&mut buf, base);
        assert_eq!(buf, original, "roundtrip at base {base:#x}");
    }
}

#[test]
fn bcj_roundtrip_short_buffer_is_noop() {
    // Anything shorter than 5 bytes can't host an opcode + rel32, so the
    // filter must leave it strictly alone.
    for len in 0..5 {
        let original: Vec<u8> = (0..len as u8).map(|x| 0xE8 ^ x).collect();
        let mut buf = original.clone();
        bcj_x86::forward(&mut buf, 0x1000);
        assert_eq!(buf, original, "len {len}: forward should be no-op");
        bcj_x86::backward(&mut buf, 0x1000);
        assert_eq!(buf, original, "len {len}: backward should be no-op");
    }
}

#[test]
fn bcj_roundtrip_large_random_with_e8_e9() {
    // Bias an RNG-generated buffer so plenty of E8/E9 bytes appear, ensuring
    // the round-trip keeps working under heavy filter activity.
    use rand::rngs::StdRng;
    use rand::{Rng, RngCore, SeedableRng};

    let mut rng = StdRng::seed_from_u64(0xBCD_DEADBEEF);
    let mut data = vec![0u8; 64 * 1024];
    rng.fill_bytes(&mut data);
    // Sprinkle ~6% E8 / 6% E9 bytes.
    for byte in data.iter_mut() {
        let r: u8 = rng.gen();
        if r < 16 {
            *byte = 0xE8;
        } else if r < 32 {
            *byte = 0xE9;
        }
    }

    let original = data.clone();
    bcj_x86::forward(&mut data, 0x4000_1000);
    bcj_x86::backward(&mut data, 0x4000_1000);
    assert_eq!(data, original);
}

#[test]
fn bcj_lzma_pipeline_roundtrip() {
    // End-to-end: BCJ → LZMA → LZMA-decompress → BCJ-inverse should be the
    // identity on a code-like blob.
    let pattern = vec![
        0x48, 0x89, 0xC8, 0xE8, 0x10, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90, 0xE9, 0x20, 0x00, 0x00,
        0x00, 0xCC,
    ];
    let original: Vec<u8> = pattern.iter().copied().cycle().take(128 * 1024).collect();
    let mut staged = original.clone();
    bcj_x86::forward(&mut staged, 0x1000);

    let compressed = lzma::compress(&staged).unwrap();
    let mut decompressed = lzma::decompress(&compressed).unwrap();
    bcj_x86::backward(&mut decompressed, 0x1000);

    assert_eq!(decompressed, original);
}
