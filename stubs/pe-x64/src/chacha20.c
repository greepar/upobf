// upobf stub ChaCha20 (RFC 8439, IETF variant).
//
// 256-bit key, 96-bit nonce, 32-bit block counter starting at 0.
// In-place XOR. Freestanding: no libc, no SSE/AVX intrinsics.
//
// Tested against RustCrypto's ChaCha20 KAT vectors via the packer side.

#include <stdint.h>

#ifndef UPOBF_FORCE_INLINE
#define UPOBF_FORCE_INLINE static inline __attribute__((always_inline))
#endif

UPOBF_FORCE_INLINE uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

UPOBF_FORCE_INLINE uint32_t load_le32(const uint8_t* p) {
    return ((uint32_t)p[0])
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

UPOBF_FORCE_INLINE void store_le32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v        & 0xff);
    p[1] = (uint8_t)((v >>  8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

#define QR(a, b, c, d) \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d,  8); \
    c += d; b ^= c; b = rotl32(b,  7);

static void chacha20_block(uint32_t out[16], const uint32_t state[16]) {
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = state[i];

    for (int i = 0; i < 10; i++) {
        // column rounds
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        // diagonal rounds
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }

    for (int i = 0; i < 16; i++) out[i] = x[i] + state[i];
}

#undef QR

// Public API: in-place ChaCha20 XOR. Counter starts at 0.
void upobf_chacha20_xor(uint8_t* data, uint32_t len,
                        const uint8_t key[32], const uint8_t nonce[12])
{
    uint32_t state[16];
    // "expand 32-byte k"
    state[0] = 0x61707865u;
    state[1] = 0x3320646eu;
    state[2] = 0x79622d32u;
    state[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) {
        state[4 + i] = load_le32(key + 4 * i);
    }
    state[12] = 0; // counter
    state[13] = load_le32(nonce + 0);
    state[14] = load_le32(nonce + 4);
    state[15] = load_le32(nonce + 8);

    uint32_t block[16];
    uint32_t pos = 0;
    while (pos < len) {
        chacha20_block(block, state);
        // counter++
        state[12] += 1;

        uint32_t take = len - pos;
        if (take > 64) take = 64;

        // XOR keystream with data
        uint8_t ks[64];
        for (int i = 0; i < 16; i++) {
            store_le32(ks + 4 * i, block[i]);
        }
        for (uint32_t i = 0; i < take; i++) {
            data[pos + i] ^= ks[i];
        }
        pos += take;
    }
}
