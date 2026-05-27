// upobf stub BCJ x86 backward filter.
//
// Inverse of crates/upobf-core/src/filter/bcj_x86.rs. Same byte-driven
// "unconditional rewrite at every E8/E9 with 4 trailing bytes, then skip
// 5 bytes" rule. Freestanding.

#include <stdint.h>

void upobf_bcj_x86_backward(uint8_t* data, uint32_t len, uint32_t base_addr)
{
    if (len < 5) return;

    // Highest opcode index where a full rel32 still fits.
    uint32_t limit = len - 4;
    uint32_t i = 0;

    while (i < limit) {
        uint8_t op = data[i];
        if (op != 0xE8 && op != 0xE9) {
            i += 1;
            continue;
        }

        uint32_t off = i + 1;
        uint32_t cur = ((uint32_t)data[off + 0])
                     | ((uint32_t)data[off + 1] << 8)
                     | ((uint32_t)data[off + 2] << 16)
                     | ((uint32_t)data[off + 3] << 24);

        // pc = base_addr + i + 5  (32-bit wraparound matches Rust impl).
        uint32_t pc = base_addr + i + 5u;
        uint32_t neu = cur - pc;  // abs -> rel

        data[off + 0] = (uint8_t)(neu        & 0xff);
        data[off + 1] = (uint8_t)((neu >>  8) & 0xff);
        data[off + 2] = (uint8_t)((neu >> 16) & 0xff);
        data[off + 3] = (uint8_t)((neu >> 24) & 0xff);

        i += 5;
    }
}
