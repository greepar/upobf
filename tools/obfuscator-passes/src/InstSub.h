// upobf MBA instruction substitution pass.
//
// New-pass-manager FunctionPass that walks every BinaryOperator in
// the function and, with some probability driven by a deterministic
// PRNG, replaces it with a Mixed Boolean-Arithmetic (MBA) equivalent
// expression. The replacement preserves bit-for-bit semantics on
// every input, but materially obscures the operation's identity in
// the emitted machine code.
//
// Substitutions implemented:
//   ADD : a + b -> (a ^ b) + 2*(a & b)
//   ADD : a + b -> a - (~b) - 1
//   SUB : a - b -> (a ^ -b) + 2*(a & -b)
//   XOR : a ^ b -> (a | b) - (a & b)
//   AND : a & b -> (a + b) - (a | b)
//   OR  : a | b -> (a & b) + (a ^ b)
//
// Each rule is a published MBA identity verifiable by a 1-bit truth
// table (or by appeal to the obvious identities `a + b == (a ^ b) +
// 2*(a & b)` and `a + b == (a | b) + (a & b)`). The pass is therefore
// semantics-preserving by construction.
//
// Notes:
//   - We skip vector / pointer / floating-point operands; only
//     IntegerType operands are substituted. This avoids surprising
//     codegen explosions for SIMD code paths.
//   - For each candidate operator we draw two PRNG numbers: one for
//     "should we substitute?" and one for "which rule?". The same
//     seed input therefore produces the same output, which is a
//     property the unit tests rely on.

#pragma once

#include "llvm/IR/PassManager.h"

namespace upobf {

class InstSubPass : public llvm::PassInfoMixin<InstSubPass> {
public:
    explicit InstSubPass(uint64_t seed) : seed_(seed) {}

    llvm::PreservedAnalyses run(llvm::Function &f,
                                llvm::FunctionAnalysisManager &fam);

private:
    uint64_t seed_;
};

} // namespace upobf
