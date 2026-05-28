# upobf LLVM IR-level obfuscation passes (Phase A1 + Phase H).
#
# Builds a single shared library `upobf-passes.dll` that exposes
# three function passes through the LLVM new-pass-manager plugin
# ABI:
#
#   - upobf-mba   : Mixed Boolean-Arithmetic instruction substitution.
#   - upobf-bcf   : Bogus control-flow injection.
#   - upobf-cff   : Control-flow flattening (demote-to-stack +
#                   dispatcher loop with PRNG-scrambled state IDs).
#
# Built against the LLVM 21.1.0 prebuilt dev SDK that lives under
# `<repo>/.tools/clang+llvm-21.1.0-x86_64-pc-windows-msvc`. The path
# is supplied by the caller via -DLLVM_DIR=<...>/lib/cmake/llvm so this
# CMakeLists has no hard-coded host-specific path.
#
# We deliberately link against LLVM's static libraries (LLVMCore,
# LLVMSupport, LLVMTransformUtils) and let the prebuilt `opt.exe`
# host be the ABI sink. The Windows prebuilt does NOT define the
# `clang.lib` import library that `clang -fpass-plugin` would need,
# so the integration path is `clang -emit-llvm` -> `opt --load-pass-plugin`
# -> `llc -filetype=obj`. opt.exe natively supports loading
# new-pass-manager plugins on Windows.

cmake_minimum_required(VERSION 3.20)
project(upobf-passes C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# LLVM_DIR must be passed in: -DLLVM_DIR=<dev>/lib/cmake/llvm.
# We accept any 21.x build. CMake's `find_package(... 21 ...)` insists
# on an exact major+minor match for some configs, so we use a range.
find_package(LLVM 21.1.0 REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
message(STATUS "LLVM include dir: ${LLVM_INCLUDE_DIRS}")

# Only the headers and basic lib paths; we link against the static
# component libs by name below.
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})

# Match LLVM's expected RTTI / EH posture. opt.exe is built without
# RTTI; loading a plugin compiled with RTTI works in practice but
# makes some downcasts mis-link, so we mirror upstream policy.
if (MSVC)
    add_compile_options(/EHs-c- /GR-)
    add_definitions(-D_HAS_EXCEPTIONS=0)
else()
    add_compile_options(-fno-exceptions -fno-rtti)
endif()

# Pass plugin DLL.
add_library(upobf-passes SHARED
    src/Plugin.cpp
    src/InstSub.cpp
    src/BogusCF.cpp
    src/Cff.cpp
)

# Map cmake component names to actual lib targets exported by
# LLVMConfig.cmake. `llvm_map_components_to_libnames` resolves a
# logical component name (e.g. "core") to the concrete LLVM*.lib it
# corresponds to in this build.
#
# Linux note: distros that ship `libLLVM-21.so` (Debian/Ubuntu's
# llvm-21-dev package is one) have opt-21 / llc-21 dynamically
# linked against that single SO. If we statically link our plugin
# against the LLVM component .a's, cl::opt globals get registered
# twice and the host abort()s with "inconsistency in registered
# CommandLine options". To match the host, we prefer the single
# shared `LLVM` library when it exists. On Windows the prebuilt
# only ships per-component .lib's, so the static path remains.
if (UNIX AND TARGET LLVM)
    target_link_libraries(upobf-passes PRIVATE LLVM)
else()
    llvm_map_components_to_libnames(LLVM_PASS_LIBS
        core            # IR
        support         # cl::opt, errs(), raw_ostream
        transformutils  # BasicBlockUtils etc
        analysis        # for FunctionAnalysisManager
    )
    target_link_libraries(upobf-passes PRIVATE ${LLVM_PASS_LIBS})
endif()

# Note on diaguids.lib:
#
# The LLVM 21.1.0 prebuilt's LLVMExports.cmake hard-codes a transitive
# dependency on `diaguids.lib` from the build machine's VS 2019 install
# path. We patch the dev SDK to point at our local VS install during
# the bootstrap step (see tools/obfuscator-passes/build.ps1 docs).
# Our plugin doesn't actually call any DIA APIs — diaguids.lib is
# pulled in only because LLVMDebugInfoPDB is in the Support library's
# transitive closure on Windows.

# On Windows we want `upobf-passes.dll` (no `lib` prefix).
set_target_properties(upobf-passes PROPERTIES
    PREFIX ""
    OUTPUT_NAME "upobf-passes"
)

install(TARGETS upobf-passes RUNTIME DESTINATION bin)
