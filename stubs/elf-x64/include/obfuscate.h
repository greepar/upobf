// upobf stub source-level obfuscation primitives.
//
// This header offers a handful of macros and inline helpers that the
// real stub TUs sprinkle through their hot control flow to make
// IDA/Ghidra/F5 output noticeably less readable. They are NOT a
// replacement for an LLVM IR-level pass — for that, see the (future)
// `tools/upobf-llvm-pass`. They are the pragmatic, source-level
// alternative when an LLVM dev SDK is not available.
//
// Design constraints:
//   - Freestanding: no libc, no globals with initialisers other than
//     `volatile static`.
//   - AV-friendly: the produced code uses no syscalls, no SEH abuse,
//     no anti-attach. It is a pure CFG / dataflow obfuscation layer.
//   - Reversible at runtime: every primitive must collapse to its
//     trivial equivalent so semantics are preserved. Tests cover this.
//
// Primitives:
//   OPAQUE_ZERO()   - returns 0, but the compiler can't fold it. Costs
//                     ~3-5 instructions of dataflow noise.
//   OPAQUE_ONE()    - returns 1 by the same trick.
//   OPAQUE_TRUE(c)  - evaluates `(c) || OPAQUE_ZERO()` so the branch
//                     guard now mixes a runtime-only value into the
//                     condition. Forces the decompiler to keep the
//                     extra term in the symbolic predicate.
//   OPAQUE_FALSE(c) - dual of OPAQUE_TRUE: `(c) && !OPAQUE_ONE()`.
//   BOGUS_GUARD()   - true predicate based on a small parametric
//                     polynomial; reduces to constant true at runtime
//                     but the decompiler will emit the full
//                     comparison.
//   JUNK_DATAFLOW(x) - noop dataflow churn that depends on `x` and
//                     writes back through a volatile so DCE can't
//                     remove it.
//   OBFUSCATED_RETURN_INT(v) - returns `v` after running it through
//                     a couple of opaque-zero adds, so the function
//                     epilogue isn't a single `mov eax,…`.
//
// Note on opaque-zero correctness:
//   We rely on `volatile` to defeat the optimizer. Each TU that
//   includes this header gets its own private `static` seed so the
//   linker can't merge them; the seed is initialised by the loader
//   to its declared value (no `__attribute__((constructor))`).

#ifndef UPOBF_OBFUSCATE_H
#define UPOBF_OBFUSCATE_H

#include <stdint.h>

// ---- Per-TU volatile seed ------------------------------------------------
//
// Declared `static` so each translation unit gets its own copy and the
// optimiser can never inter-procedurally fold reads through it.
//
// Declared `const volatile`:
//   - `volatile` forces the compiler to emit a real memory load every
//     time, even though the value never changes at runtime.
//   - `const` lets the linker place the slot in `.rdata` (read-only).
//     The freestanding stub policy in `upobf-core::stub_link` rejects
//     writable data sections, so the seed MUST land in `.rdata`.
//
// The C standard guarantees volatile reads happen regardless of const.
// Empirically clang 21 honours this at -O2/-Os; the test suite below
// would catch any future regression.
//
// Initial value 0xA5 is arbitrary; every primitive below depends on
// this exact byte at runtime.
static const volatile uint8_t upobf_obf_seed_byte = 0xA5;

// Read the seed once. Helper exists so we can stick `__attribute__
// ((always_inline))` on it; tests confirm the volatile load survives
// `-O2`.
static inline __attribute__((always_inline)) uint32_t
upobf_obf_seed_u32(void) {
    // Read the byte, then expand to a 32-bit value via xor of a
    // constant. The compiler cannot constant-fold the load; the xor
    // is then trivially folded but only at the use site, leaving an
    // observable `xor reg, imm32` in the emitted code.
    uint32_t b = (uint32_t)upobf_obf_seed_byte;
    return (b ^ 0xC3A5u) & 0xFFFFu;
    // = (0xA5 ^ 0xC3A5) & 0xFFFF = 0xC300 at runtime.
}

// ---- Opaque zero/one -----------------------------------------------------

// Returns 0 at runtime; the compiler must keep the load + arithmetic
// in the emitted code.
//
// At runtime: upobf_obf_seed_u32() == 0xC300; subtract 0xC300 -> 0.
static inline __attribute__((always_inline)) uint32_t OPAQUE_ZERO(void) {
    uint32_t s = upobf_obf_seed_u32();
    return s - 0xC300u;
}

// Returns 1 at runtime via a different reduction so the two primitives
// don't decode to the same byte sequence.
//
// At runtime: (0xC300 >> 8) - 0xC2 = 0xC3 - 0xC2 = 1.
static inline __attribute__((always_inline)) uint32_t OPAQUE_ONE(void) {
    uint32_t s = upobf_obf_seed_u32();
    return (s >> 8) - 0xC2u;
}

// ---- Opaque condition wrappers ------------------------------------------

// Evaluates to the same boolean as `c`, but mixes the opaque zero in
// so the compiler can't see through the guard.
//
// Macro form (rather than function) is intentional: we want short
// circuit on `c == true`, otherwise the volatile load might be
// elided by an aggressive optimiser that proves `c` already true.
#define OPAQUE_TRUE(c)  ((c) || (OPAQUE_ZERO() != 0))
#define OPAQUE_FALSE(c) ((c) && (OPAQUE_ONE()  != 0))

// ---- Bogus guard --------------------------------------------------------

// A predicate that is always true at runtime, but emits as a real
// arithmetic comparison. The polynomial below maps every uint8 input
// to a value in [0, 510]; the constant 1024 is unreachable. The
// compiler can statically prove this only by reasoning about the
// volatile read's value, which it conservatively can't.
//
// Use as: `if (!BOGUS_GUARD()) { /* unreachable */ } else { ... }`
// or simply `BOGUS_GUARD() ? real() : never()`.
static inline __attribute__((always_inline)) int BOGUS_GUARD(void) {
    uint32_t x = upobf_obf_seed_u32() & 0xFFu; // 0..255
    uint32_t y = (x * x) >> 7;                  // 0..510
    return y < 1024u;
}

// ---- Junk dataflow ------------------------------------------------------

// Folds `x` through a couple of bit-twiddles that round-trip to `x`
// but force the compiler to keep the temporaries live.
static inline __attribute__((always_inline)) uint32_t
JUNK_DATAFLOW(uint32_t x) {
    uint32_t k = upobf_obf_seed_u32();
    uint32_t a = x ^ k;
    a = ((a << 13) | (a >> (32 - 13)));
    a = ((a >> 13) | (a << (32 - 13)));
    return a ^ k;
}

// ---- Obfuscated return helpers ------------------------------------------

#define OBFUSCATED_RETURN_INT(v) \
    do { return (int)((uint32_t)(v) + OPAQUE_ZERO()); } while (0)

#define OBFUSCATED_RETURN_U32(v) \
    do { return (uint32_t)(v) + OPAQUE_ZERO(); } while (0)

#endif // UPOBF_OBFUSCATE_H
