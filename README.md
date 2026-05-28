# upobf

> **u**niversal **p**acker + **ob**fuscator **f**ramework
> 类似 UPX 的压缩壳，配合反调试 / 完整性校验 / 多态化。
> 开源、AV 友好、为大体积 .NET NativeAOT / Avalonia 桌面程序优化。

## 状态

- [x] **M0** workspace 骨架（5 crates，Rust workspace）
- [x] **M1** PE32+ 解析（手写、零 unsafe、12 个单元测试 + 2 个 demo 集成测试）
- [x] **M2** LZMA + ChaCha20 + BCJ-x86 filter（17 个集成测试，含 RFC 8439 KAT）
- [x] **M3** Stub 骨架（C + asm，clang freestanding，COFF parser + multi-obj linker，5 个测试）
- [x] **M4** 完整压缩管线 → packed.exe 启动后 NativeAOT + Avalonia UI 正常工作
- [x] **M5** AV 友好反调试 + 内联 CRC32 完整性 + per-build 多态
- [x] **M6** E2E 测试脚本（`tests/e2e/pack_run_verify.ps1`），全程自动化验证
- [x] **Phase 1-3** 节名多态化 + stub 字符串去明文 + PE 头清洗（Rich/TimeDateStamp/LinkerVersion）
- [x] **Phase C** stub 字节级多态（junk trampoline + dead tail，每构建 stub-section SHA256 全异）
- [x] **Phase A2** 源码级 CFG / dataflow 混淆原语（`OPAQUE_TRUE/FALSE`、`BOGUS_GUARD`、`JUNK_DATAFLOW`）
- [x] **Phase A1** LLVM IR 级 pass plugin（MBA 指令替换 + bogus control-flow，新-pass-manager 接入 `opt`）
- [x] **Phase G** Import 表 API 名延迟解析（IAT 仅留 `GetModuleHandleW + GetProcAddress` 两个锚点；其余 9 个 API 全部从加密 ApiStringTable 在 TLS callback 内 GetProcAddress 解析）
- [x] **Phase E** `.rdata` 分块压缩（forbidden-page mask + section splitting；demo 进一步从 27.86 MiB 砍到 18.39 MiB / 41.0%）
- [x] **Phase F** 后台 CRC32 watchdog 线程（每 30 s 重算 chunk 基线；不退出，mismatch 异或进 heap 内 seed；packed.exe 线程数 +1）
- [x] **Phase H** `upobf-cff` 控制流扁平化（DemoteRegToStack + dispatcher loop with PRNG-scrambled state IDs；entry/anti_debug/api_resolve/watchdog 走 cff，chacha20/bcj_x86/lzma_dec 豁免）
- [x] **Phase I** OEP redirect + stolen bytes（iced-x86 LDE 解码 OEP prologue；PI 字节直拷、`call/jmp rel32` 重写为 abs 间接形式；packer 把原 prologue 替换成 `0xCC` 后再压缩；stub 解压完 VirtualAlloc 一页 trampoline + 14B abs-jmp 回 host，再把原 OEP 处int3 padding 写回成 `jmp [rip+0]; .quad <heap-VA>`；ProcessHacker dump 出来的 PE OEP 处指向堆 VA，重跑必崩）
- [x] **Phase J / M0L–M4L** Linux ELF（x86_64）端到端：
  - **M0L** ELF parser（Ehdr/Phdr/Shdr/Dyn/Sym/Rela 全手写零 unsafe）
  - **M1L** writer：phdr 表搬迁 + DT_INIT_ARRAY 注入 + .upobf{0,1,2} 三段 PT_LOAD
  - **M2L** freestanding stub（pure RIP-relative，零重定位，纯 syscall，stub.so 一节 R+X）
  - **M3L** 端到端压缩：`__managedcode` + `__unbox` 全段压缩
  - **Phase E** 扩展段覆盖：`.text` / `.rodata` / `.dotnet_eh_table`（safe-runs 算法 + tier-1/tier-2 分级）
  - **Phase H** IR pass plugin Linux 构建：apt LLVM 21、动态 libLLVM 链接修 cl::opt 重复注册
  - **Phase G** 动态 libc API 解析：`/proc/self/maps` 走 GNU-hash → 8 个 API 槽（pthread/mmap/mprotect/prctl/clock_gettime…）；ChaCha20 解密 ApiTable，PR_SET_DUMPABLE=0 禁 coredump
  - **Phase F** pthread CRC32 watchdog：30 s 周期，IEEE 802.3 多项式逐字节实现（freestanding 禁可写全局），Avalonia 线程 +1
  - **Phase I** e_entry 重定向 + `.text` 压缩：rewrite ELF e_entry 到 stub 的 `upobf_entry_trampoline`，trampoline 跑完 `upobf_stub_init`（解压所有 chunk）后跳回 host 原 e_entry。**与 PE 不同**：glibc 的 main exe DT_INIT_ARRAY 由 `__libc_start_main` 调用（即 `_start` 之内），所以 init_array hook 来不及在 `_start` 读取压缩后的 `.text` 之前 fire；只能改 e_entry。
- [ ] **V2** macOS Mach-O

## 当前度量（demo: PatchInstaller.exe NativeAOT + Avalonia）

| 指标 | 值 |
|---|---|
| 原大小 | 44.85 MB |
| Packed 大小 | **18.39 MB** |
| 压缩率 | **41.0%（节省 59%）** |
| 较 .text-only 基线再节省 | 9.47 MiB（Phase E `.rdata` 分块） |
| Pack 耗时 (release) | ~12 s |
| Packed 启动到首屏 | ~2-3 s |
| Packed 运行时内存 | ~130 MB（与原版一致） |
| Per-build SHA256 差异 | ✅（master_key/master_nonce 由 OsRng 派生） |

## 工程布局

```
crates/
  upobf-core   跨平台核心：compress / crypto / filter / obfuscate / policy / stub_link
  upobf-pe     Windows PE 实现：parse / layout / build
  upobf-elf    Linux ELF 实现：parse / layout / build（M0L–M4L Phase I 完成）
  upobf-macho  V2 占位 (macOS Mach-O)
  upobf-cli    `upobf pack` / `upobf inspect`

stubs/pe-x64/  C + asm，clang 编译的 freestanding stub
  src/
    entry.c        TLS callback 入口、解密+解压主循环
    chacha20.c     ChaCha20 流密码
    lzma_dec.c     公版 LZMA SDK alone-format 解压器（vendored）
    bcj_x86.c      BCJ x86 inverse filter
    anti_debug.c   IsDebuggerPresent + GetThreadContext + CRC32
  build.ps1      用 clang -ffreestanding -nostdlib 编译

stubs/elf-x64/  C + naked-asm，clang freestanding stub（共享 chacha20/lzma_dec/bcj_x86 与 PE 侧）
  src/
    entry.c        e_entry 蹦床 + upobf_stub_init 主循环
    api_resolve.c  /proc/self/maps + GNU-hash 走 libc，零 dlsym 锚点
    watchdog.c     pthread 30s CRC32 校验
  build.sh       clang-21 / ld.lld-21 / opt-21 / llc-21（IR 流水线可选）

tests/
  e2e/pack_run_verify.ps1         Windows 端到端
  e2e/pack_run_verify_linux.sh    Linux 端到端
```

## 构建

```pwsh
cargo build --workspace            # builder + libs
.\stubs\pe-x64\build.ps1           # stub COFF objects
cargo test  --workspace            # 37 tests
```

## 使用

> `demo/PatchInstaller.exe` 是 42 MB 的 NativeAOT + Avalonia 测试样本，**未入 git**
> （见 `.gitignore`）。运行 inspect / pack / E2E 前请把它放到 `demo/` 目录。

```pwsh
# 解析 PE，输出文本 / JSON 报告
upobf inspect demo\PatchInstaller.exe
upobf inspect demo\PatchInstaller.exe --json

# 加壳
upobf pack demo\PatchInstaller.exe -o packed.exe

# 端到端 verify
.\tests\e2e\pack_run_verify.ps1
```

## 关键设计决策（M4 核心创新）

### 不重写 TLS Directory，改为 in-place 注入

直接重建 `IMAGE_TLS_DIRECTORY` 会破坏 NativeAOT 启动（运行时依赖原 callback 数组的 alignment 与 slot 布局）。
正确做法：保留原 DataDirectory[9] 完全不动，**在原 callback 数组所在 `.rdata` 字节处** patch 为
`[stub_va, original_va, NULL]`。新增的 `stub_va` 通过 `.reloc2` 加入基址重定位列表。

### 复用 host 的 IAT，不新增 Import 描述符

NativeAOT 二进制已经导入 `KERNEL32!{VirtualAlloc, VirtualProtect, VirtualFree, GetProcAddress, LoadLibraryA,
IsDebuggerPresent, GetThreadContext, GetCurrentProcess, GetCurrentThread}`。stub 复用这些 IAT slot 而不是
新增 `.idata2` 描述符 —— 避免重写 DataDirectory[Import] 时 OS Loader 拒绝加载。

### 不可压缩段保留原 RVA

绝对**不**压缩 `.pdata`（x64 SEH unwinder 必读）、`.rsrc`（manifest / icon / DPI）、`.reloc`（OS Loader 必读）、
`.data`（含 LoadConfig.SecurityCookie，OS Loader 在 stub 之前写入）。M4 仅压缩 `.text`。M5/V2 将分块压缩
`.rdata` 和 `.data` 的冷区。

### AV 友好反调试

仅使用公开 Windows API（`IsDebuggerPresent` / `GetThreadContext`）。
**发现调试时不退出**，而是把检测结果累积到 `env_seed`，让 RE 误以为没起效。
不做：自调试、远程线程、direct syscall、API hashing 全清空 IAT、reflective loader。

## 测试矩阵

```
cargo test --workspace        # 37 tests, all green
.\tests\e2e\pack_run_verify.ps1
```

E2E 检验：
1. Stub 编译产出 7 个 .obj（~17 KB 总）
2. 加壳产出 packed.exe，比例 ≤ 70%
3. packed.exe 运行 ≥ 5s，标题非空，线程数 > 1
4. 两次连续打包 SHA256 不同（多态校验）

## 下一步（V2）

- [x] 节名多态化（Phase 1，已完成）
- [x] Rich Header 清零 + TimeDateStamp / LinkerVersion 多态（Phase 3，已完成）
- [x] 控制流混淆 stub（Phase A1：LLVM 21 IR-level MBA + BCF pass，已完成）
- [x] 后台 CRC watchdog 线程（Phase F PE + Phase J/M4L Phase F ELF）
- [x] `.rdata` / `.data` 分块压缩（避开 LoadConfig / IAT / 静态字段）（Phase E PE + Phase J/M4L Phase E ELF）
- [x] Linux x64 (ELF) 支持（Phase J/M0L–M4L Phase I 完成）
- [ ] macOS arm64 (Mach-O) 支持

## Phase A1：LLVM IR-level 混淆 pass

`tools/obfuscator-passes/` 是一个 LLVM 21 new-pass-manager plugin，
产出 `upobf-passes.dll`。提供两个 function pass：

| Pass | 名字 | 作用 |
|---|---|---|
| InstSub | `upobf-mba<seed=N>` | 把 `add/sub/xor/and/or` 替换成等价 MBA 表达式（5 条已发表的 MBA 恒等式）|
| BogusCF | `upobf-bcf<seed=N>` | 在每个 BasicBlock 入口插入 `if (opaquePredicate()) goto B; else goto Junk;` |

opaque predicate 基于 `static const volatile uint8_t upobf_obf_seed_byte`，
落在 `.rdata`，运行时恒为 true，但编译器无法 const-fold（保 LLVM 21 校验）。

### 一次性引导（约 1 分钟，需要 ~4 GB 磁盘）

```pwsh
# 1) 下载并解压 LLVM 21.1.0 prebuilt dev SDK 到 .tools/（944 MB 下载，3.85 GB 解压）
$dlDir = "$PWD\.tools"; New-Item -ItemType Directory -Path $dlDir -Force | Out-Null
$tar = "$dlDir\clang+llvm-21.1.0-x86_64-pc-windows-msvc.tar.xz"
Invoke-WebRequest -Uri "https://github.com/llvm/llvm-project/releases/download/llvmorg-21.1.0/clang%2Bllvm-21.1.0-x86_64-pc-windows-msvc.tar.xz" -OutFile $tar -UseBasicParsing
tar.exe -xf $tar -C $dlDir
# 2) 修补 LLVMExports.cmake：upstream 把 diaguids.lib 硬编码成构建机器的 VS2019 路径，
#    替换成本机已装的 VS 2022/2026 即可
$exp = "$dlDir\clang+llvm-21.1.0-x86_64-pc-windows-msvc\lib\cmake\llvm\LLVMExports.cmake"
(Get-Content $exp -Raw).Replace(
  "C:/Program Files (x86)/Microsoft Visual Studio/2019/Professional/DIA SDK/lib/amd64/diaguids.lib",
  "C:/Program Files/Microsoft Visual Studio/18/Community/DIA SDK/lib/amd64/diaguids.lib"
) | Set-Content $exp -NoNewline
```

### 构建 plugin + 启用 IR 流水线

```pwsh
# 编 plugin（约 30 s）
.\tools\obfuscator-passes\build.ps1            # produces tools/obfuscator-passes/build/Release/upobf-passes.dll

# 用 plugin 编 stub（流水线：clang -emit-llvm -> opt --load-pass-plugin -> llc -filetype=obj）
$dll = ".\tools\obfuscator-passes\build\Release\upobf-passes.dll"
.\stubs\pe-x64\build.ps1 -Clean -PassPlugin $dll -PassSeed 0xDEADBEEF

# 端到端测试
.\tests\e2e\pack_run_verify.ps1 -WithIRPipeline
```

不传 `-PassPlugin` 时 `stubs\pe-x64\build.ps1` 走传统 `clang -c` 单步路径，
因此 dev SDK 缺失的机器上原始 E2E 仍然能跑，A1 是**严格 opt-in**。

## 文档

- [docs/protocol-m4.md](docs/protocol-m4.md) — packer ↔ stub 二进制协议（PayloadHeader / ChunkEntry / ApiTable）
- 设计文档（plan）：`~/.local/share/opencode/plans/upobf-design-plan.md`
