// upobf-passes plugin entry point.
//
// Exposes two function passes through the LLVM new-pass-manager
// plugin ABI:
//
//   - "upobf-mba"   : Mixed Boolean-Arithmetic instruction substitution.
//   - "upobf-bcf"   : Bogus control-flow injection.
//
// Both passes accept an optional integer parameter via the pipeline
// syntax `upobf-mba<seed=N>` so each invocation of the stub build can
// drive a different PRNG stream. If no seed is given the pass falls
// back to a fixed value (0xC0FFEE) so unit tests are reproducible.
//
// Plugin host expectation: this DLL is loaded by `opt.exe` from the
// LLVM 21.1.0 prebuilt dev SDK via `--load-pass-plugin=...`. On
// Windows we deliberately avoid the `clang -fpass-plugin` path
// because the upstream prebuilt does not ship the symbol-export
// import library required by clang-side plugins.

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include "InstSub.h"
#include "BogusCF.h"

using namespace llvm;

namespace {

// Parse `<seed=NN>` from a parameter string of the form expected by
// the new pass manager. Returns the parsed seed, or `defaultSeed` if
// the parameter is empty / malformed. We accept hex (0x...) and
// decimal.
uint64_t parseSeed(StringRef params, uint64_t defaultSeed) {
    if (params.empty()) {
        return defaultSeed;
    }
    StringRef rest = params;
    // Accept "seed=N" or just "N".
    if (rest.starts_with("seed=")) {
        rest = rest.drop_front(5);
    }
    uint64_t value = 0;
    if (!rest.consumeInteger(0, value)) {
        return value;
    }
    return defaultSeed;
}

bool registerPipeline(StringRef name, FunctionPassManager &fpm,
                      ArrayRef<PassBuilder::PipelineElement> /*innerPipeline*/) {
    // The new pass manager passes parameters in the form "passname<...>"
    // by stripping the angle brackets before calling the callback. We
    // accept both `upobf-mba` and `upobf-mba<seed=N>` styles.
    StringRef rawName = name;
    StringRef params;
    auto angle = rawName.find('<');
    if (angle != StringRef::npos) {
        params = rawName.substr(angle + 1);
        if (params.ends_with(">")) {
            params = params.drop_back(1);
        }
        rawName = rawName.substr(0, angle);
    }

    if (rawName == "upobf-mba") {
        fpm.addPass(upobf::InstSubPass(parseSeed(params, 0xC0FFEEULL)));
        return true;
    }
    if (rawName == "upobf-bcf") {
        fpm.addPass(upobf::BogusCFPass(parseSeed(params, 0xBADC0DEULL)));
        return true;
    }
    return false;
}

void registerCallbacks(PassBuilder &pb) {
    pb.registerPipelineParsingCallback(registerPipeline);
}

} // namespace

// Plugin entry point exported to the host (`opt.exe` or `clang`).
//
// Windows note: MSVC does not export DLL symbols by default. The
// upstream declaration in <llvm/Passes/PassPlugin.h> uses
// `LLVM_ATTRIBUTE_WEAK`, which expands to nothing on MSVC and so
// produces an undecorated import-only declaration. Adding
// `__declspec(dllexport)` to the definition is rejected as
// "different linkage". We therefore emit a linker `/EXPORT`
// directive: the resulting DLL exposes `llvmGetPassPluginInfo`
// without changing the function's declared linkage in the
// translation unit.
#if defined(_WIN32)
#  pragma comment(linker, "/EXPORT:llvmGetPassPluginInfo")
#endif

extern "C" ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "upobf-passes", "0.1.0",
            registerCallbacks};
}
