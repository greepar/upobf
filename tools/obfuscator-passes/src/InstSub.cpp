// upobf MBA instruction substitution pass — implementation.
//
// See InstSub.h for the design intent and the substitution rules.

#include "InstSub.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>

using namespace llvm;
using namespace upobf;

namespace {

// xorshift64* PRNG. Deterministic, fast, no dependencies. We only
// need uniform 64-bit draws for "skip vs substitute" decisions and
// "rule selection".
struct Xorshift64 {
    uint64_t state;
    explicit Xorshift64(uint64_t seed) : state(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
    uint64_t next() {
        uint64_t x = state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        state = x;
        return x * 0x2545F4914F6CDD1DULL;
    }
};

// Probability of substituting any given candidate. 60% gives a
// good visual obfuscation density without bloating stub size beyond
// our budget. Tunable.
constexpr unsigned kSubstituteProbPct = 60;

bool shouldSubstitute(Xorshift64 &rng) {
    return (rng.next() % 100u) < kSubstituteProbPct;
}

// ADD: a + b -> (a ^ b) + 2*(a & b)
Value *substituteAddV1(IRBuilder<> &b, Value *a, Value *bb) {
    Value *xorAB = b.CreateXor(a, bb);
    Value *andAB = b.CreateAnd(a, bb);
    Value *twoAnd = b.CreateShl(andAB, 1);
    return b.CreateAdd(xorAB, twoAnd);
}

// ADD: a + b -> a - (~b) - 1
Value *substituteAddV2(IRBuilder<> &b, Value *a, Value *bb) {
    Value *notB = b.CreateNot(bb);
    Value *sub1 = b.CreateSub(a, notB);
    Value *one = ConstantInt::get(a->getType(), 1);
    return b.CreateSub(sub1, one);
}

// SUB: a - b -> (a ^ -b) + 2*(a & -b)
Value *substituteSub(IRBuilder<> &b, Value *a, Value *bb) {
    Value *negB = b.CreateNeg(bb);
    Value *xorAnB = b.CreateXor(a, negB);
    Value *andAnB = b.CreateAnd(a, negB);
    Value *twoAnd = b.CreateShl(andAnB, 1);
    return b.CreateAdd(xorAnB, twoAnd);
}

// XOR: a ^ b -> (a | b) - (a & b)
Value *substituteXor(IRBuilder<> &b, Value *a, Value *bb) {
    Value *orAB = b.CreateOr(a, bb);
    Value *andAB = b.CreateAnd(a, bb);
    return b.CreateSub(orAB, andAB);
}

// AND: a & b -> (a + b) - (a | b)
Value *substituteAnd(IRBuilder<> &b, Value *a, Value *bb) {
    Value *addAB = b.CreateAdd(a, bb);
    Value *orAB = b.CreateOr(a, bb);
    return b.CreateSub(addAB, orAB);
}

// OR: a | b -> (a & b) + (a ^ b)
Value *substituteOr(IRBuilder<> &b, Value *a, Value *bb) {
    Value *andAB = b.CreateAnd(a, bb);
    Value *xorAB = b.CreateXor(a, bb);
    return b.CreateAdd(andAB, xorAB);
}

// Build an MBA replacement for the binary operator `bo`. Returns
// nullptr if no rule applies (caller leaves the original op alone).
Value *substituteBinaryOp(IRBuilder<> &b, BinaryOperator *bo, Xorshift64 &rng) {
    Value *lhs = bo->getOperand(0);
    Value *rhs = bo->getOperand(1);

    // Only handle integer scalar types. Vector / pointer / float we
    // leave alone; codegen for those is too brittle to mess with at
    // this milestone.
    if (!bo->getType()->isIntegerTy()) {
        return nullptr;
    }

    switch (bo->getOpcode()) {
        case Instruction::Add:
            return (rng.next() & 1) ? substituteAddV1(b, lhs, rhs)
                                    : substituteAddV2(b, lhs, rhs);
        case Instruction::Sub: return substituteSub(b, lhs, rhs);
        case Instruction::Xor: return substituteXor(b, lhs, rhs);
        case Instruction::And: return substituteAnd(b, lhs, rhs);
        case Instruction::Or:  return substituteOr(b, lhs, rhs);
        default: return nullptr;
    }
}

} // namespace

PreservedAnalyses InstSubPass::run(Function &f,
                                   FunctionAnalysisManager & /*fam*/) {
    if (f.isDeclaration() || f.empty()) {
        return PreservedAnalyses::all();
    }

    // Mix the pass-level seed with the function name hash so each
    // function gets a different PRNG stream. This keeps the pass
    // deterministic per (seed, function) but defeats trivial pattern
    // matching across the stub.
    uint64_t mixed = seed_ ^ static_cast<uint64_t>(
        std::hash<std::string>{}(std::string(f.getName())));
    Xorshift64 rng(mixed);

    // Collect candidates first. Mutating the use-list during the walk
    // would confuse the iterator.
    std::vector<BinaryOperator *> candidates;
    for (BasicBlock &bb : f) {
        for (Instruction &inst : bb) {
            if (auto *bo = dyn_cast<BinaryOperator>(&inst)) {
                candidates.push_back(bo);
            }
        }
    }

    bool changed = false;
    for (BinaryOperator *bo : candidates) {
        if (!shouldSubstitute(rng)) {
            continue;
        }
        IRBuilder<> b(bo);
        Value *replacement = substituteBinaryOp(b, bo, rng);
        if (!replacement) {
            continue;
        }
        bo->replaceAllUsesWith(replacement);
        bo->eraseFromParent();
        changed = true;
    }

    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
