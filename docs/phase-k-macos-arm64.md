# Phase K — macOS arm64 (Mach-O) port plan

> 目标：把已经在 Windows (PE/x64) 和 Linux (ELF/x64) 跑通的压缩混淆壳，移植到 **macOS arm64 (Mach-O)**。
> 对标 Linux 端 (Phase J)。**最终验证**：原生 macOS arm64 上把 Avalonia/NativeAOT 应用打包，运行存活，文件至少减半。

---

## 已确认的前提

来自规划阶段的用户决策：

1. Demo 用户在 MacBook 上提供（macOS arm64 Avalonia 同款）。
2. **代码签名不在本计划范围内** —— 用户在 MacBook 上自己 `codesign` 重签。打包工具产出的二进制可能没有有效签名，这是预期行为。
3. **Stub 必须经 libSystem**（macOS 禁止直接 `syscall`）—— 接受 libSystem.B.dylib 作为 stub 的唯一 NEEDED。
4. **Hardened runtime**：本计划默认支持 (`MAP_JIT` + `pthread_jit_write_protect_np`)，因为 Apple Silicon 不带 entitlement 时仍按 W^X 强制。
5. **原生开发**：MacBook 上有完整的 clang/cargo 工具链；不做 Linux→macOS 交叉编译（dyld/codesign 不可移植）。

---

## 总体架构（与 Linux 对照）

```
crates/upobf-macho/
  src/
    parse/                         # M0M
      mod.rs                       # MachoImage
      headers.rs                   # mach_header_64, load_command, etc.
      segments.rs                  # LC_SEGMENT_64 + section_64
      symbols.rs                   # LC_SYMTAB, LC_DYSYMTAB
      chained_fixups.rs            # LC_DYLD_CHAINED_FIXUPS（最难的一块）
      dylib.rs                     # LC_LOAD_DYLIB / LC_RPATH
      reader.rs                    # 复用 ELF 风格的 cursor 帮手
    layout/                        # M4M Phase E
      safe_ranges.rs               # 改写 ELF safe_ranges 为 Mach-O 概念
    build/                         # M1M / M3M / M4M
      writer.rs                    # 主 writer (LC_SEGMENT_64 切分)
      stub_loader.rs               # 加载 stub.dylib 并 patch slot
    lib.rs

stubs/macho-arm64/
  src/
    entry.c                        # upobf_entry_trampoline + upobf_stub_init
    api_resolve.c                  # dyld 镜像表 + export trie 解析 libSystem
    chacha20.c                     # 复用 PE/ELF 同款
    lzma_dec.c                     # 复用 PE/ELF 同款
    bcj_arm64.c                    # 新增：LZMA SDK 的 ARM64 BCJ filter
    watchdog.c                     # 复用 ELF 的逻辑（pthread CRC32）
  include/
    payload.h                      # 复用，可能新增 macOS 专用 API 名表
    api_resolve.h                  # 新接口
    obfuscate.h                    # 复用
    stub_runtime.h                 # arm64 syscall 帮手 → libSystem trampoline
    watchdog.h                     # 复用
  build.sh                         # clang -target arm64-apple-macos11.0

tests/e2e/
  pack_run_verify_macos.sh         # 新增 e2e
```

---

## 阶段拆解

下面每一项都对应一个独立 commit，参照 Linux/ELF 9-commit 节奏。

### M0M: Mach-O Parser

**输入：** Mach-O 64-bit binary (`MH_MAGIC_64 = 0xFEEDFACF`)，arm64 (`CPU_TYPE_ARM64`)。
**输出：** `MachoImage { raw, header, load_cmds, segments, sections, symtab, dysymtab, chained_fixups, dylibs, ... }`。

需要解析的 load command（按重要度）：

| LC | 必须 | 说明 |
|---|---|---|
| `LC_SEGMENT_64` | ✅ | 全部 segments + 内部 sections |
| `LC_SYMTAB` | ✅ | 符号表入口（n_list, strtab） |
| `LC_DYSYMTAB` | ✅ | 动态符号索引 |
| `LC_DYLD_CHAINED_FIXUPS` | ✅ | 重定位/绑定（替代旧 `LC_DYLD_INFO_ONLY`） |
| `LC_LOAD_DYLIB` | ✅ | 依赖 dylib（libSystem 必有） |
| `LC_MAIN` | ✅ | 入口偏移（Phase I 重定向用） |
| `LC_FUNCTION_STARTS` | 可选 | 用于 Tier-2 safe-runs 计算 |
| `LC_CODE_SIGNATURE` | 知晓 | 文件末尾，写入时丢弃（用户重签） |
| `LC_DYLD_EXPORTS_TRIE` | ✅ | export trie，stub 解析 libSystem 用 |
| `LC_BUILD_VERSION` | 解析 | 记录 min OS，写时透传 |

**测试：** parser round-trip（输入 demo binary 应能 parse + serialize 回字节相等）。

---

### M1M: Writer 骨架（带 file-shrink）

**核心策略**（直接从 ELF 学到的教训）：

1. 每个 `LC_SEGMENT_64` 围绕压缩 hole 切分成 N+1 子 segment。
2. 每个子 segment 的 `vmsize > filesize`，由 dyld 零填充。
3. 16 KB 页对齐（不是 4 KB）。
4. 文件偏移按子 segment 顺序紧密打包，不留 zero-fill。
5. 所有 LC 的 `fileoff` 经过 vaddr→new_offset 映射重写。
6. 末尾 LC_CODE_SIGNATURE 直接 drop（用户重签）。

**新增 segments**（追加到原 segment 列表后）：

| Segment | 权限 | 内容 |
|---|---|---|
| `__UPOBF0` | R+X | rebuilt LC table reserve + stub bytes |
| `__UPOBF1` | R | encrypted payload |
| `__UPOBF2` | R+W (可选) | future work：deferred fixup table 等 |

> M1M 的 `__UPOBF2` 优先保留为未来扩展槽 —— 当前不需要 init_array 注入。
> macOS 没有 ELF DT_INIT_ARRAY 那条路；入口直接走 `LC_MAIN.entryoff` 重定向（见 Phase I）。

**测试：**
* writer round-trip（压无 stub/无 payload，输出能 parse）
* writer with stub blob，验证 `__UPOBF0` 段存在 + `LC_MAIN` 已重写
* writer with payload + compressed_ranges，验证文件确实变小

---

### M2M: Freestanding arm64 stub baseline

**编译：**
```bash
clang -target arm64-apple-macos11.0 \
      -ffreestanding -nostdlib -fno-builtin \
      -fPIC -fvisibility=hidden \
      -Os -fno-asynchronous-unwind-tables -fno-exceptions \
      -c src/*.c -o build/<obj>.o
ld -arch arm64 -dylib -platform_version macos 11.0 11.0 \
   -e _upobf_stub_init -dead_strip \
   -no_uuid \
   build/*.o -o build/stub.dylib
```

**关键差异 vs Linux x86_64 stub：**
- 直接 syscall **禁用**。所有"系统调用"必须经 libSystem 解析后调用。
- `mmap/mprotect` 在 hardened runtime 下必须用 `MAP_JIT` 模式 + `pthread_jit_write_protect_np()` 切换 W↔X。
- arm64 远跳：`ldr x16, [pc, #imm] ; br x16`（B/BL 只能 ±128 MB）。
- **可写全局禁令**继续：所有可变状态走 mmap 出来的 anonymous 页。
- 必须 link 至少一条 libSystem 引用（否则 dyld 不解析 `__DATA_CONST,__got`）。
- entry trampoline：复用 Linux 的两次 push 套路（保护 `x0..x7` 和 `lr`）。

**baseline 验证：** `__UPOBF0` 段被 dyld map 进进程；trampoline 被调用；写一个 `/tmp/upobf_stage_macos_init` marker 文件验证（PoC 期临时加，正式提交前删除）。

---

### M3M: 端到端压缩（最小集）

参照 ELF M3L：先把 `__TEXT,__text` 一段压起来，跑通解压回路就行。

**写入 stub 的 PayloadHeader v2** 复用现有结构。`api_names` 表第一版只放：
- `mmap`
- `mprotect`
- `pthread_jit_write_protect_np`（hardened runtime 下解压必需）

**stub.dylib 必须 export 锚点：** `_dyld_get_image_header` 或 `dyld_stub_binder`，否则 dyld 不会把它链接进来。

---

### M4M Phase E: 段覆盖扩展

**Tier-1 candidates**（macOS 大段、运行时晚 touch）：
| Section | Linux 同名 | 备注 |
|---|---|---|
| `__TEXT,__text` | `.text` | 最大 |
| `__TEXT,__cstring` | `.rodata` C string 部分 | NativeAOT 大字符串池 |
| `__DATA_CONST,__const` | `.rodata` const 部分 | RELRO 等价 |
| `__DATA,__objc_const` | — | NativeAOT 不一定有 |

**Tier-2 candidates**（safe-runs 算法）：
| Section | 备注 |
|---|---|
| `__DATA,__data` | 谨慎，里面有 dyld 改写的 GOT entries |
| `__DATA,__bss` | 全零，不需要压缩，但可以让 vmsize 不缩水 |

**chained fixups 注意**：`__DATA*` 内有指针链表。若压缩 `__DATA` 必须把链表节点重定位到 stub 解压后再走；M4M Phase E 优先压 `__TEXT`/`__DATA_CONST`，`__DATA` 留到后续。

---

### M4M Phase H: IR pipeline（Linux 一次过）

`tools/obfuscator-passes/` 已存在 LLVM 21 plugin。macOS 上需：
- 重新构建：`build_macos.sh`（新增），用 brew 安装的 LLVM 21 (`brew install llvm@21`)
- bypass 列表与 ELF 一致：`lzma_dec` 全跳过；`chacha20`/`bcj_arm64` 跳 CFF
- arm64 codegen 经 `llc-21 -mtriple=arm64-apple-macos11.0`

---

### M4M Phase G: dyld API 解析

**与 Linux 的最大区别：** macOS 不暴露 `/proc/self/maps`；用 dyld 自己的 API：

```c
extern uint32_t _dyld_image_count(void);
extern const struct mach_header *_dyld_get_image_header(uint32_t idx);
extern const char *_dyld_get_image_name(uint32_t idx);
```

锚点：stub 引用 `_dyld_get_image_header` 一个符号 → dyld 必须解析它 → stub 在运行时通过它枚举所有 image，找到 libSystem.B.dylib，然后 walk export trie 拿到所需 API。

**export trie 走法：** 比 ELF GNU-hash 复杂，但 Apple 文档完整。算法：
1. 从 `LC_DYLD_EXPORTS_TRIE` 取 trie 起点
2. 按 byte 匹配走子节点
3. 叶子节点 decode ULEB128 得到 flags + offset
4. offset 加上 mach_header 的 `vmaddr` slide 得到运行时地址

**API 表第一版** （8 槽，照搬 Linux 框架但用 macOS API 名）：
| Slot | API |
|---|---|
| 0 | `_pthread_create` |
| 1 | `_pthread_detach` |
| 2 | `_nanosleep`（→ `_clock_nanosleep` 也行） |
| 3 | `_mach_absolute_time` |
| 4 | `_mmap` |
| 5 | `_mprotect` |
| 6 | `_pthread_jit_write_protect_np` |
| 7 | `_munmap` |

**ChaCha20 解密 ApiTable** 与 ELF 同套；FIXED_API_NONCE 重新随机化。

---

### M4M Phase F: pthread watchdog

直接照搬 ELF Phase F：30 秒周期，IEEE 802.3 多项式，逐字节 CRC32（无可写全局），mmap 一页存 baseline。区别仅是 pthread 入口由 Phase G 的解析提供。

---

### M4M Phase I: 入口重定向

**比 Linux 简单**：macOS 的 main exe 入口由 `LC_MAIN.entryoff` 给定，dyld 直接跳过去。

**做法：**
1. Writer 把 `LC_MAIN.entryoff` 改成 `__UPOBF0` 内 `upobf_entry_trampoline` 的偏移。
2. 把原 entryoff 写入 stub 的 `g_original_entry_off` 槽。
3. trampoline 跑完 `upobf_stub_init` → 重新读取 mach_header slide → 计算 `mach_header + g_original_entry_off` → `br x16` 跳过去。

**注意：** trampoline 必须保护 dyld 调用约定下的所有寄存器：
- `x0` = mach_header（dyld 传入的）
- 其他 `x1..x7` = 由 dyld 实现决定，理论上零

简单做法：trampoline 进来直接 `stp x0, lr, [sp, #-16]!` → call → `ldp x0, lr, [sp], #16` → `br <new>`.

---

### Verify: e2e

`tests/e2e/pack_run_verify_macos.sh`，照 Linux 版本三件套：

```bash
# 1. 构建 stub（含 IR pipeline 可选）
stubs/macho-arm64/build.sh --pass-plugin ... --pass-seed ...

# 2. 构建 packer
cargo build --release

# 3. pack demo
target/release/upobf pack /path/to/demo.app/Contents/MacOS/demo \
  -o packed_demo

# 4. 用户重签
codesign --force --deep --sign - packed_demo  # 由用户运行

# 5. 跑 3s 存活检查
./packed_demo &
PID=$!
sleep 3
kill -0 $PID && echo "ALIVE"

# 6. 多态校验
... 同 Linux
```

> e2e 脚本默认假设 `codesign` 在 PATH（macOS 自带）。如果用户希望让脚本自动 sign，加一句 `codesign --force --sign - "$OUT"`。

---

## 风险登记 + 缓解策略

| # | 风险 | 影响 | 缓解 |
|---|---|---|---|
| 1 | LC_DYLD_CHAINED_FIXUPS 压缩 `__DATA*` 时打断指针链 | dyld 启动失败 | M4M Phase E 只压 `__TEXT`/`__DATA_CONST`；`__DATA` 留作后续 Option C 风格延迟重定位 |
| 2 | Hardened runtime 不让 `mprotect(R→W→X)` | stub 解压失败 | `MAP_JIT` 分配中转页 + `pthread_jit_write_protect_np` 切换 |
| 3 | 代码签名 hash 校验失败 | dyld 拒绝加载 | 用户负责重签；packer drop LC_CODE_SIGNATURE |
| 4 | export trie walk 错误 | 解析不到 API | 单元测试覆盖 trie 解析；fallback：`_dyld_lookup_func`（虽然 deprecated 但稳定） |
| 5 | arm64 trampoline 越过 ±128 MB | BL/B 跳不过去 | 用 `ldr x16, [pc, #literal] ; br x16` 模式 |
| 6 | 16 KB 页 vs 4 KB 假设 | writer 偏移错位 | 全部 PAGE_SIZE 常量集中到一个文件，从 0x1000 改 0x4000 一次性 |
| 7 | `LC_BUILD_VERSION` 缺失导致 dyld 拒绝 | binary 不启动 | parser 强制要求 LC_BUILD_VERSION 存在；writer 透传 |

---

## 与 Phase J / Linux 的代码复用清单

可以直接复用（零改动）：
- `crates/upobf-core/` 整个：crypto / compress / payload / oep_steal
- `stubs/*/src/chacha20.c`
- `stubs/*/src/lzma_dec.c` + `lzma_dec.h`
- `stubs/*/include/payload.h`
- `stubs/*/include/obfuscate.h`
- `tools/obfuscator-passes/` LLVM IR plugin（重新编译即可）

需要重写：
- `crates/upobf-macho/src/` 全部（对应 ELF parse + build + layout）
- `stubs/macho-arm64/src/entry.c`（trampoline ASM、API 解析路径）
- `stubs/macho-arm64/src/api_resolve.c`（dyld 镜像表 vs `/proc/self/maps`）
- `stubs/macho-arm64/src/bcj_arm64.c`（新增；LZMA SDK 自带 BCJ_ARM64 filter）
- `stubs/macho-arm64/src/watchdog.c`（90% 同 ELF 版本，只换 API 解析方式）
- `stubs/macho-arm64/include/stub_runtime.h`（arm64 ABI 帮手）
- `stubs/macho-arm64/build.sh`
- `crates/upobf-cli/src/main.rs` 新 subcommand `pack-macho`（或自动 dispatch by magic）

---

## 估时

| 阶段 | 估时（净开发） |
|---|---|
| M0M parser | 1.5 工作日 |
| M1M writer (含 file-shrink) | 2 工作日 |
| M2M arm64 stub baseline | 2 工作日 |
| M3M e2e 跑通 | 0.5 工作日 |
| M4M Phase E (段扩展) | 0.5 工作日 |
| M4M Phase H (IR pipeline) | 0.5 工作日 |
| M4M Phase G (dyld API 解析 + export trie) | 1.5 工作日 |
| M4M Phase F (watchdog) | 0.5 工作日 |
| M4M Phase I (LC_MAIN 重定向) | 0.5 工作日 |
| 验证 + 度量 + README + 提交 | 0.5 工作日 |
| **合计** | **~10 工作日** |

参考：Linux/ELF 整套 9 commit 共耗时与此相当。

---

## MacBook 上拉到第一行代码该做什么

```bash
git pull origin main
ls docs/phase-k-macos-arm64.md          # 这份文件
ls crates/upobf-macho/                  # 占位 crate
ls stubs/                               # 还没有 macho-arm64/

# 第一步：M0M parser 骨架
mkdir crates/upobf-macho/src/{parse,build,layout}
# 参照 crates/upobf-elf/src/parse/headers.rs 写 mach_header_64
```

---

## 暂缓项（macOS 完工后再做）

- macOS x86_64（Rosetta 之后还有遗存 Intel Mac，但优先级低）
- macOS Universal Binary（fat header）
- LC_CODE_SIGNATURE 自动重签（Rust 实现 CodeDirectory 生成器）
- `__DATA` 段压缩 + chained fixup 延迟应用（高难度）
- iOS / tvOS / visionOS（公司不让上架的环境，远期）

---

*Last updated: 2026-05-28 (Phase J 完工后立刻开 K).*
