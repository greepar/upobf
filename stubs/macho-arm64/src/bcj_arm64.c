// upobf ARM64 BCJ (Branch-Call-Jump) reverse filter.
//
// LZMA SDK's ARM64 BCJ filter converts relative branch/call offsets
// to absolute addresses before compression (improving redundancy).
// This routine reverses that transformation after decompression.
//
// ARM64 instructions that encode PC-relative offsets:
//   - B/BL (26-bit signed imm, shifted left 2): opcode[31:26] = 00010x
//   - ADRP (21-bit signed imm, shifted left 12): opcode[31:24] = 1x01_0000
//   - B.cond / CBZ / CBNZ / TBZ / TBNZ: various, but we only handle
//     B and BL for the baseline (matching LZMA SDK Bcj2.c ARM64 filter).
//
// The forward filter (applied before compression) does:
//   offset = extract_imm(insn)
//   absolute = offset + (pc / 4)  [for B/BL, pc-relative in instruction units]
//   insn = replace_imm(insn, absolute)
//
// The backward filter (this function, applied after decompression) does:
//   absolute = extract_imm(insn)
//   offset = absolute - (pc / 4)
//   insn = replace_imm(insn, offset)

#include <stdint.h>

static inline uint32_t load_le32_bcj(const uint8_t *p) {
    return ((uint32_t)p[0])
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static inline void store_le32_bcj(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void upobf_bcj_arm64_backward(uint8_t *buf, uint32_t len, uint32_t base) {
    // Process 4 bytes at a time (ARM64 instructions are fixed 4 bytes).
    uint32_t pos = 0;
    while (pos + 4 <= len) {
        uint32_t insn = load_le32_bcj(buf + pos);
        uint32_t pc = base + pos;

        // Check for B or BL: bits[31:26] == 000101 (B) or 100101 (BL)
        // Mask: top 6 bits. B = 0x14000000, BL = 0x94000000.
        // Common check: (insn & 0x7C000000) == 0x14000000
        if ((insn & 0x7C000000u) == 0x14000000u) {
            // 26-bit signed immediate (in instruction units = 4 bytes each).
            uint32_t imm26 = insn & 0x03FFFFFFu;
            // The forward filter stored: absolute = original_offset + (pc / 4)
            // We reverse: original_offset = absolute - (pc / 4)
            uint32_t absolute = imm26;
            uint32_t offset = (absolute - (pc >> 2)) & 0x03FFFFFFu;
            insn = (insn & 0xFC000000u) | offset;
            store_le32_bcj(buf + pos, insn);
        }

        pos += 4;
    }
}
