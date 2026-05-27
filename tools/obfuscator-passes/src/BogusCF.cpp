// upobf bogus control-flow injection pass — implementation.
//
// See BogusCF.h for the design intent.

#include "BogusCF.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <vector>

using namespace llvm;
using namespace upobf;

namespace {

// xorshift64*, identical generator to InstSub for predictability.
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

// Probability of wrapping a given block. Lower than InstSub's rate
// because each wrap costs more (a new BB plus guard + junk), and
// the cost per non-wrap candidate is zero.
constexpr unsigned kWrapProbPct = 30;

// Find or create the per-module `upobf_obf_seed_byte` global. The
// source-level header initialises it to 0xA5; if the linker merges
// our generated copy with the source-level one, the values agree.
GlobalVariable *getOrCreateSeedGlobal(Module &m) {
    static const char *kSeedName = "upobf_obf_seed_byte";
    if (auto *gv = m.getNamedGlobal(kSeedName)) {
        return gv;
    }
    Type *i8 = Type::getInt8Ty(m.getContext());
    auto *gv = new GlobalVariable(
        m, i8, /*isConstant=*/true, GlobalValue::InternalLinkage,
        ConstantInt::get(i8, 0xA5), kSeedName);
    return gv;
}

// Build an opaque-true predicate. Evaluates to `true` at runtime
// based on the volatile load of the seed byte, but the compiler
// cannot prove the result without inlining the volatile read.
//
// Identity used:
//   x = load_volatile(seed_byte);
//   y = x * (x + 1);  // even for any integer x
//   return (y & 1) == 0;
//
// At runtime y is always even, so the low bit is always zero, so
// the comparison is always true.
Value *buildOpaqueTrue(IRBuilder<> &b, GlobalVariable *seed) {
    Type *i8 = Type::getInt8Ty(b.getContext());
    Type *i32 = Type::getInt32Ty(b.getContext());
    LoadInst *raw = b.CreateLoad(i8, seed, /*isVolatile=*/true);
    raw->setAlignment(Align(1));
    Value *x = b.CreateZExt(raw, i32);
    Value *xPlusOne = b.CreateAdd(x, ConstantInt::get(i32, 1));
    Value *prod = b.CreateMul(x, xPlusOne);
    Value *low = b.CreateAnd(prod, ConstantInt::get(i32, 1));
    return b.CreateICmpEQ(low, ConstantInt::get(i32, 0));
}

// Populate a fresh "junk" block with a few dead arithmetic ops, then
// jump to `target`. The instructions write to a single SSA chain
// terminating in an unused value; codegen will keep them because
// they live on a path that the static CFG includes.
void fillJunkBlock(BasicBlock *junk, BasicBlock *target, Xorshift64 &rng) {
    LLVMContext &ctx = junk->getContext();
    IRBuilder<> b(junk);
    Type *i32 = Type::getInt32Ty(ctx);

    // Materialise a small dependency chain: 4 arithmetic ops on
    // PRNG-derived constants. Forced live by writing the final
    // value to a volatile store to a local stack slot.
    AllocaInst *slot = nullptr;
    {
        // Place the alloca in the function's entry block so it is
        // codegen'd as a fixed stack offset.
        IRBuilder<> entryB(&junk->getParent()->getEntryBlock(),
                           junk->getParent()->getEntryBlock().getFirstInsertionPt());
        slot = entryB.CreateAlloca(i32, nullptr, "upobf_junk_slot");
    }

    Value *acc = ConstantInt::get(i32,
        static_cast<uint32_t>(rng.next() & 0xFFFFFFFFu));
    for (int i = 0; i < 4; i++) {
        uint32_t k = static_cast<uint32_t>(rng.next() & 0xFFFFFFFFu) | 1u;
        Value *kV = ConstantInt::get(i32, k);
        switch (i & 3) {
            case 0: acc = b.CreateXor(acc, kV); break;
            case 1: acc = b.CreateAdd(acc, kV); break;
            case 2: acc = b.CreateMul(acc, kV); break;
            case 3: acc = b.CreateSub(acc, kV); break;
        }
    }
    StoreInst *st = b.CreateStore(acc, slot);
    st->setVolatile(true);
    b.CreateBr(target);
}

// Try to wrap `bb` with an opaque-true guard. Returns true if
// transformation succeeded.
//
// Implementation note (post-fix):
//
//   The naive approach — walk every predecessor of `bb` and rewrite
//   its terminator's `bb` operand to point at a freshly-allocated
//   `guard` block — produces malformed PHI nodes whenever `bb` has
//   PHI entries from two distinct predecessors with distinct
//   incoming values, because we end up with two entries for the
//   same `guard` block (which is now the unique predecessor along
//   that edge). Worse, when `bb` was the unique successor of a
//   conditional branch whose two arms both went to `bb`, both arms
//   collapse onto `guard` and the PHI's two entries pick up the
//   same block label twice.
//
//   The clean fix is to delegate the predecessor split to LLVM's
//   `SplitBlockPredecessors`, which:
//     - creates the new block,
//     - rewrites all designated predecessor terminators to target it,
//     - merges PHI entries inside `bb` by inserting a fresh PHI
//       inside the new block (so each PHI in `bb` ends up with at
//       most one entry per *distinct* predecessor block),
//     - leaves DT / LoopInfo / MemorySSA updates as no-ops when
//       passed nullptr (we don't preserve those analyses anyway).
//
//   We then convert the new block's unconditional branch into a
//   conditional one with an opaque-true predicate, point the false
//   arm at the junk block, and have junk fall through to `bb`.
bool wrapBlock(BasicBlock *bb, GlobalVariable *seed, Xorshift64 &rng) {
    Function *f = bb->getParent();
    LLVMContext &ctx = f->getContext();

    // Skip the entry block: SplitBlockPredecessors requires at least
    // one predecessor.
    if (bb == &f->getEntryBlock()) return false;

    // Skip blocks with no predecessors (dead) or EH-related blocks.
    if (pred_empty(bb)) return false;
    if (bb->isLandingPad() || bb->isEHPad()) return false;

    // SplitBlockPredecessors operates on a list of predecessors. We
    // want all of them to flow through the guard. Some of those
    // predecessors are themselves catchpad / cleanuppad terminators
    // we shouldn't rewrite; bail if any of those appear.
    SmallVector<BasicBlock *, 4> preds(pred_begin(bb), pred_end(bb));
    for (BasicBlock *p : preds) {
        Instruction *t = p->getTerminator();
        // Detect EH terminators by opcode rather than the dropped
        // `isExceptionalTerminator()` helper. The freestanding stub
        // never raises exceptions, so any of these would itself be
        // a bug, but we keep the guard defensively.
        switch (t->getOpcode()) {
            case Instruction::Invoke:
            case Instruction::Resume:
            case Instruction::CatchSwitch:
            case Instruction::CatchRet:
            case Instruction::CleanupRet:
                return false;
            default:
                break;
        }
    }

    BasicBlock *guard = SplitBlockPredecessors(
        bb, ArrayRef<BasicBlock *>(preds), ".upobf_guard",
        static_cast<DomTreeUpdater *>(nullptr),
        static_cast<LoopInfo *>(nullptr),
        static_cast<MemorySSAUpdater *>(nullptr),
        /*PreserveLCSSA*/ false);
    if (!guard) return false;

    // After SplitBlockPredecessors, `guard` ends in an unconditional
    // branch to `bb`. We need to replace that with a conditional
    // branch to either bb or a junk block. Build a fresh junk block
    // first (so the conditional has somewhere to land).
    BasicBlock *junk = BasicBlock::Create(ctx, "upobf_junk", f, bb);

    // Replace guard's terminator with the conditional branch.
    Instruction *guardTerm = guard->getTerminator();
    {
        IRBuilder<> b(guardTerm);
        Value *cond = buildOpaqueTrue(b, seed);
        b.CreateCondBr(cond, bb, junk);
    }
    guardTerm->eraseFromParent();

    // Junk path: a small dead arithmetic chain, then jump to bb.
    fillJunkBlock(junk, bb, rng);

    // Add a PHI incoming for the junk -> bb edge. Pick the value
    // already coming in from `guard` so the type and dominance
    // properties are preserved. Since junk is never executed at
    // runtime, the chosen value is semantically irrelevant.
    for (PHINode &phi : bb->phis()) {
        // Find guard's existing incoming entry; copy its value.
        int guardIdx = phi.getBasicBlockIndex(guard);
        if (guardIdx < 0) {
            // SplitBlockPredecessors should have left exactly one
            // entry for `guard`; if it didn't, fall back to the
            // first incoming value rather than aborting.
            phi.addIncoming(phi.getIncomingValue(0), junk);
        } else {
            phi.addIncoming(phi.getIncomingValue(guardIdx), junk);
        }
    }

    return true;
}

} // namespace

PreservedAnalyses BogusCFPass::run(Function &f,
                                   FunctionAnalysisManager & /*fam*/) {
    if (f.isDeclaration() || f.empty()) {
        return PreservedAnalyses::all();
    }

    Module *m = f.getParent();
    if (!m) return PreservedAnalyses::all();

    GlobalVariable *seed = getOrCreateSeedGlobal(*m);

    // Mix the pass seed with the function name hash for per-function
    // PRNG decorrelation, mirroring InstSub.
    uint64_t mixed = seed_ ^ static_cast<uint64_t>(
        std::hash<std::string>{}(std::string(f.getName())));
    Xorshift64 rng(mixed);

    // Snapshot the block list because we're going to insert new
    // blocks during the walk.
    std::vector<BasicBlock *> candidates;
    for (BasicBlock &bb : f) candidates.push_back(&bb);

    bool changed = false;
    for (BasicBlock *bb : candidates) {
        if ((rng.next() % 100u) >= kWrapProbPct) continue;
        if (wrapBlock(bb, seed, rng)) {
            changed = true;
        }
    }

    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
