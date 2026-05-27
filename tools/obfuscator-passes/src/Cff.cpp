// upobf control-flow flattening pass — implementation.
//
// See Cff.h for the design intent. The implementation here:
//
//   1. Skips functions that contain EH terminators or trivially small
//      ones (one block of code).
//
//   2. Snapshots the non-entry basic blocks before any mutation.
//
//   3. Demotes every PHI node and every cross-block SSA value to a
//      stack alloca via LLVM's `DemotePHIToStack` / `DemoteRegToStack`
//      helpers. This is what frees us to rewrite branch terminators
//      arbitrarily without producing dangling SSA references.
//
//   4. Inserts a state alloca + dispatcher block + unreachable
//      default block.
//
//   5. Rewrites the entry block's terminator to set the initial
//      state and br to the dispatcher. (Switch- and other
//      non-branch entry-terminators currently bail out — the
//      freestanding stub never produces them.)
//
//   6. Rewrites each non-entry block's branch terminator to:
//        - `BR succ`   -> `store STATE[succ]; br dispatcher`
//        - `BR cond %T,%F` -> `select cond, STATE[T], STATE[F];
//                              store sel; br dispatcher`
//      `ret` / `unreachable` / `switch` blocks are left in place;
//      they remain reachable via the dispatcher's own switch.
//
// State IDs are scrambled by multiplying the block index by an
// odd PRNG salt mod 2^32 (a bijection), so the visual layout of
// the dispatcher's `switch` cases gives no hint about the
// original block sequence.

#include "Cff.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/Local.h"

#include <functional>
#include <map>
#include <string>
#include <vector>

using namespace llvm;
using namespace upobf;

namespace {

// xorshift64*, identical generator to InstSub / BogusCF for
// predictability across the plugin.
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

// Detect EH-related terminator opcodes. Functions containing any of
// these are skipped: lifting them across the dispatcher requires
// landingpad-aware re-routing we don't bother to implement.
bool hasExceptionalTerminator(Function &f) {
    for (BasicBlock &bb : f) {
        Instruction *t = bb.getTerminator();
        if (!t) continue;
        switch (t->getOpcode()) {
            case Instruction::Invoke:
            case Instruction::Resume:
            case Instruction::CatchSwitch:
            case Instruction::CatchRet:
            case Instruction::CleanupRet:
                return true;
            default:
                break;
        }
    }
    return false;
}

// Decide whether `bb` is eligible for flattening. We exclude:
//   - the entry block (handled separately as the initial-state setter)
//   - any block ending in a non-branch terminator (ret / unreachable /
//     switch / indirectbr / ...). Those blocks remain in the
//     dispatcher's switch but their terminator is left intact.
bool blockHasFlattenableTerminator(BasicBlock *bb) {
    Instruction *t = bb->getTerminator();
    if (!t) return false;
    return isa<BranchInst>(t);
}

} // namespace

PreservedAnalyses CffPass::run(Function &f, FunctionAnalysisManager & /*fam*/) {
    if (f.isDeclaration() || f.empty()) {
        return PreservedAnalyses::all();
    }
    if (hasExceptionalTerminator(f)) {
        return PreservedAnalyses::all();
    }

    // Snapshot non-entry blocks. Defensive copy so subsequent
    // mutations to the function's block list don't invalidate us.
    BasicBlock &entry = f.getEntryBlock();
    std::vector<BasicBlock *> blocks;
    for (BasicBlock &bb : f) {
        if (&bb != &entry) {
            blocks.push_back(&bb);
        }
    }
    if (blocks.size() < 2) {
        return PreservedAnalyses::all();
    }

    // Defensive: bail if any block branches back to the entry block.
    // Re-executing entry would re-allocate the state slot and lose
    // the running value. C-language stubs don't produce this shape.
    for (BasicBlock *bb : blocks) {
        for (BasicBlock *succ : successors(bb)) {
            if (succ == &entry) {
                return PreservedAnalyses::all();
            }
        }
    }

    // Entry must end in a single conditional or unconditional branch
    // for the rewrite below to handle it. Anything else (switch,
    // indirectbr, ret in entry-only) is rare in stub C code; just
    // skip the function.
    Instruction *entryTerm = entry.getTerminator();
    auto *entryBr = dyn_cast<BranchInst>(entryTerm);
    if (!entryBr) {
        return PreservedAnalyses::all();
    }

    // Per-function PRNG for state-ID scrambling and any future
    // randomisation (block ordering, etc.).
    uint64_t mixed = seed_ ^ static_cast<uint64_t>(
        std::hash<std::string>{}(std::string(f.getName())));
    Xorshift64 rng(mixed);

    LLVMContext &ctx = f.getContext();
    Type *i32 = Type::getInt32Ty(ctx);

    // ----- Demote PHIs and cross-block SSA to stack ----------------
    //
    // Order matters: phis first (because demoting a phi inserts new
    // stores into predecessor blocks, but those stores should land
    // before the terminator we will rewrite later — and DemotePHIToStack
    // does land them before the existing terminator).
    {
        std::vector<PHINode *> phis;
        for (BasicBlock *bb : blocks) {
            for (Instruction &i : *bb) {
                if (auto *phi = dyn_cast<PHINode>(&i)) phis.push_back(phi);
            }
        }
        for (PHINode *phi : phis) {
            DemotePHIToStack(phi, entry.getFirstInsertionPt());
        }
    }

    {
        std::vector<Instruction *> toDemote;
        for (BasicBlock &bb : f) {
            for (Instruction &i : bb) {
                if (isa<AllocaInst>(&i)) continue;
                if (i.getType()->isVoidTy()) continue;
                for (User *u : i.users()) {
                    auto *uinst = dyn_cast<Instruction>(u);
                    if (uinst && uinst->getParent() != i.getParent()) {
                        toDemote.push_back(&i);
                        break;
                    }
                }
            }
        }
        for (Instruction *i : toDemote) {
            DemoteRegToStack(*i, /*VolatileLoads=*/false,
                             entry.getFirstInsertionPt());
        }
    }

    // ----- Allocate state slot in entry block ----------------------
    AllocaInst *stateAlloca = nullptr;
    {
        IRBuilder<> b(&entry, entry.getFirstInsertionPt());
        stateAlloca = b.CreateAlloca(i32, nullptr, "upobf_cff_state");
    }

    // ----- Build dispatcher + unreachable default ------------------
    BasicBlock *dispatcher =
        BasicBlock::Create(ctx, "upobf_cff_dispatcher", &f);
    BasicBlock *unrBlock =
        BasicBlock::Create(ctx, "upobf_cff_unreachable", &f);
    {
        IRBuilder<> b(unrBlock);
        b.CreateUnreachable();
    }

    // Build a stable assignment of state IDs. Multiplication by an
    // odd salt is a bijection on 32-bit integers, so we get N
    // distinct, scrambled IDs.
    uint32_t salt = static_cast<uint32_t>(rng.next() | 1u);
    std::map<BasicBlock *, uint32_t> stateOf;
    for (size_t i = 0; i < blocks.size(); i++) {
        uint32_t id = (static_cast<uint32_t>(i) + 1u) * salt;
        stateOf[blocks[i]] = id;
    }

    // Construct the dispatcher's switch.
    SwitchInst *swInst = nullptr;
    {
        IRBuilder<> b(dispatcher);
        Value *cur = b.CreateLoad(i32, stateAlloca);
        swInst = b.CreateSwitch(cur, unrBlock,
                                static_cast<unsigned>(blocks.size()));
        for (BasicBlock *bb : blocks) {
            swInst->addCase(
                cast<ConstantInt>(ConstantInt::get(i32, stateOf[bb])), bb);
        }
    }

    // Helper: rewrite a branch terminator into the
    //   store next_state; br dispatcher
    // shape. Conditional branches go through a select.
    auto rewriteBranchToDispatcher =
        [&](BranchInst *br) -> bool {
            if (br->isConditional()) {
                BasicBlock *t = br->getSuccessor(0);
                BasicBlock *fl = br->getSuccessor(1);
                auto tIt = stateOf.find(t);
                auto fIt = stateOf.find(fl);
                if (tIt == stateOf.end() || fIt == stateOf.end()) {
                    return false;
                }
                IRBuilder<> b(br);
                Value *sel =
                    b.CreateSelect(br->getCondition(),
                                   ConstantInt::get(i32, tIt->second),
                                   ConstantInt::get(i32, fIt->second));
                b.CreateStore(sel, stateAlloca);
                b.CreateBr(dispatcher);
                br->eraseFromParent();
                return true;
            }
            BasicBlock *succ = br->getSuccessor(0);
            auto it = stateOf.find(succ);
            if (it == stateOf.end()) return false;
            IRBuilder<> b(br);
            b.CreateStore(ConstantInt::get(i32, it->second), stateAlloca);
            b.CreateBr(dispatcher);
            br->eraseFromParent();
            return true;
        };

    // ----- Rewrite entry's terminator to seed dispatcher -----------
    if (!rewriteBranchToDispatcher(entryBr)) {
        // Should be unreachable: the entry's successors are non-entry
        // blocks, all of which are in stateOf. Bail defensively
        // anyway; the demote-to-stack changes above are still
        // semantically correct on their own.
        return PreservedAnalyses::none();
    }

    // ----- Rewrite each flattenable non-entry block ----------------
    for (BasicBlock *bb : blocks) {
        if (!blockHasFlattenableTerminator(bb)) continue;
        Instruction *term = bb->getTerminator();
        auto *br = dyn_cast<BranchInst>(term);
        if (!br) continue;
        rewriteBranchToDispatcher(br);
    }

    return PreservedAnalyses::none();
}
