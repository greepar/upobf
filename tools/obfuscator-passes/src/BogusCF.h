// upobf bogus control-flow injection pass.
//
// New-pass-manager FunctionPass that wraps each eligible BasicBlock
// in an opaque-true predicate guard. Concretely, for a chosen block
// `B` (with predecessor `P`), we transform:
//
//      P -> B -> ...
//
// into:
//
//      P -> Guard
//      Guard:
//          if (opaquePredicate()) goto B; else goto Junk;
//      Junk:
//          (random-looking instructions that never execute)
//          goto B;
//      B:
//          (original code)
//
// The opaque predicate evaluates to `true` at runtime, but is
// constructed from a polynomial that the compiler cannot constant-
// fold without proving the value of a `volatile` load. We use the
// `upobf_obf_seed_byte` symbol that the source-level obfuscation
// header (stubs/pe-x64/include/obfuscate.h) places in `.rdata`. If
// the symbol is not present in the module, we synthesize a fresh
// global with the same name and initialiser; the linker will merge
// duplicate definitions (or, if multiple TUs contribute, prefer
// the first one). All initialisations agree on byte 0xA5.
//
// The "junk" block contains a small handful of arithmetic on dead
// values, then unconditionally jumps to the real block. Because
// the guard is statically true at runtime, the junk block is dead
// at runtime, but the static analyser cannot easily prove that.
//
// Notes:
//   - We do not transform the entry block (would require splitting
//     the function entry).
//   - We do not transform blocks ending in unreachable / terminator
//     pseudo-ops (e.g. catchswitch on Windows EH); the freestanding
//     stub doesn't use these but the guard is defensive.
//   - We skip blocks whose predecessor is itself the result of a
//     previous transformation in this pass (avoid pathological
//     self-amplification).

#pragma once

#include "llvm/IR/PassManager.h"

namespace upobf {

class BogusCFPass : public llvm::PassInfoMixin<BogusCFPass> {
public:
    explicit BogusCFPass(uint64_t seed) : seed_(seed) {}

    llvm::PreservedAnalyses run(llvm::Function &f,
                                llvm::FunctionAnalysisManager &fam);

private:
    uint64_t seed_;
};

} // namespace upobf
