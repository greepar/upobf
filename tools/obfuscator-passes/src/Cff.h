// upobf control-flow flattening pass.
//
// New-pass-manager FunctionPass that flattens a function's CFG into
// a single dispatcher loop driven by an integer state variable.
// Concretely, a function with N original basic blocks gets rewritten
// into:
//
//      entry:
//          %state = alloca i32
//          store i32 <state_for_first_real_block>, %state
//          br dispatcher
//      dispatcher:
//          %s = load i32, %state
//          switch i32 %s, label %unreachable [
//              i32 <S0> label %BB0
//              i32 <S1> label %BB1
//              ...
//          ]
//      BB0:
//          ; original code, with terminator rewritten to:
//          store i32 <next_state>, %state
//          br dispatcher
//      ...
//
// Plus, every value defined in one block and consumed in another is
// demoted to a stack alloca via DemotePHIToStack / DemoteRegToStack
// so the rewritten branches don't leave dangling SSA links across
// the dispatcher.
//
// Effect: the original CFG (an arbitrary DAG with conditional and
// unconditional edges) collapses to a single hub-and-spoke shape.
// IDA / Ghidra still produce a graph but it loses every meaningful
// edge; F5 output collapses to a giant `while (1) switch (s)` loop
// with no readable structure. Combined with Phase A1's bogus-CF
// guards and MBA substitutions, individual stub functions become
// substantially harder to recover.
//
// Notes:
//   - Functions with EH terminators (Invoke / Resume / CatchSwitch /
//     CatchRet / CleanupRet) are skipped. The freestanding stub
//     never raises exceptions, but the guard is defensive: lifting
//     EH terminators across the dispatcher requires landingpad-aware
//     re-routing that we don't bother to implement.
//   - Functions with fewer than two non-entry basic blocks are
//     skipped: there is nothing to flatten.
//   - Functions ending in a single `Ret` see the return inlined into
//     a synthetic terminal state and removed from the dispatcher.
//   - State numbering is permuted by the per-function PRNG so the
//     visual ordering of `switch` labels in the IR / disassembly
//     gives no hint at the original block sequence.

#pragma once

#include "llvm/IR/PassManager.h"

namespace upobf {

class CffPass : public llvm::PassInfoMixin<CffPass> {
public:
    explicit CffPass(uint64_t seed) : seed_(seed) {}

    llvm::PreservedAnalyses run(llvm::Function &f,
                                llvm::FunctionAnalysisManager &fam);

private:
    uint64_t seed_;
};

} // namespace upobf
