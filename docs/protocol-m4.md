# upobf payload protocol (M4)

> packer (Rust) 和 stub (C) 之间的二进制协议。任何变更都必须双端同步。

## 总体布局

```
.upobf 段 (包内一个新 section, R only)
+----------------------+ <- payload_blob_va
| PayloadHeader (固定) |
+----------------------+
| ChunkEntry[N]        |
+----------------------+
| ApiStringTable       |
+----------------------+
| ChunkData (拼接)     |
+----------------------+
```

## 字节序与对齐

- All integers little-endian
- 4-byte aligned

## PayloadHeader (84 字节, packed)

```c
struct PayloadHeader {
    uint32_t magic;           // 'U' 'P' 'O' 'B' = 0x42 4F 50 55  (LE: 0x42_4F_50_55)
    uint32_t version;         // 1
    uint32_t header_size;     // sizeof(PayloadHeader) = 84
    uint32_t chunk_count;     // N
    uint32_t chunks_offset;   // bytes from start of payload to ChunkEntry[0]
    uint32_t api_table_offset;// bytes from start of payload to ApiStringTable
    uint32_t api_table_size;  // bytes
    uint32_t data_offset;     // bytes from start of payload to ChunkData[0]
    uint32_t data_size;       // total bytes of ChunkData
    uint32_t flags;           // reserved (0)
    uint8_t  master_key[32];  // ChaCha20 256-bit master key
    uint8_t  master_nonce[12];// ChaCha20 96-bit master nonce  (= reserved bytes for header future expansion)
};
```

`master_key` 直接以明文嵌入 payload 头里。**这就是设计**：M4 重点是让端到端能跑，单纯加密对抗的是"裸字节扫描"——不在文件里留 `LoadLibraryA`、`VirtualAlloc` 之类的明文字符串就够了；M5 再叠加多态密钥派生（密钥不直接写入，而是从 stub 内嵌的常量+运行时熵派生）。

## ChunkEntry (40 字节, packed)

```c
struct ChunkEntry {
    uint32_t target_rva;       // where to write the decoded bytes (from ImageBase)
    uint32_t virtual_size;     // bytes to write
    uint32_t data_offset;      // bytes from PayloadHeader.data_offset
    uint32_t data_size;        // compressed+encrypted bytes
    uint32_t original_protect; // PAGE_EXECUTE_READ / PAGE_READONLY / PAGE_READWRITE
    uint32_t bcj_base;         // base address used for BCJ filter (= ImageBase + target_rva)
    uint32_t flags;            // bit0 = BCJ_X86 applied, bit1 = LZMA, bit2 = ChaCha20
    uint8_t  sub_nonce[12];    // per-chunk nonce; ChaCha20 nonce = master_nonce XOR sub_nonce (12 bytes)
};
```

**Layered transforms** (顺序，packer 应用 → stub 反向)：
1. raw bytes
2. BCJ_X86 forward (bit0)
3. LZMA compress (bit1)
4. ChaCha20 encrypt (bit2)

stub 反向：
1. ChaCha20 decrypt
2. LZMA decompress (decompressed size = `virtual_size`)
3. BCJ_X86 backward
4. write to `ImageBase + target_rva`, then `VirtualProtect → original_protect`

`virtual_size` 决定 LZMA 解压输出长度。LZMA stream 用 `alone` 格式（13 字节固定 header + raw stream）；其中已编码 uncompressed size，但 stub 信任 ChunkEntry.virtual_size 作为 ground truth。

## ApiStringTable

固定列表，索引顺序与 stub 中 enum 一致。每条记录：

```c
struct ApiEntry {
    uint16_t module_str_offset;  // bytes from start of ApiStringTable
    uint16_t function_str_offset;// bytes from start of ApiStringTable
    uint16_t module_str_len;
    uint16_t function_str_len;
};
struct ApiTable {
    uint32_t count;
    struct ApiEntry entries[count];
    // 然后是字节池，存所有字符串（不必 NUL-terminated；用长度）
};
```

整个 ApiStringTable 在写入 PE 之前**用 ChaCha20(master_key, derive(label="api"))** 单独加密；解密 nonce 由 PayloadHeader.master_nonce 派生（具体派生见下）。

### Nonce 派生

为避免相同 master_nonce 在所有 chunk 复用：
- Chunk i 的 ChaCha20 nonce = `master_nonce[0..12] XOR ChunkEntry.sub_nonce[0..12]`
- ApiStringTable 的 nonce = `master_nonce XOR fixed_api_nonce` 其中 fixed_api_nonce = `b"upobf:apinonce"[..12]` (16 字节取前 12)

固定常量写在 stub 头文件里。

## M4 阶段的 ApiStringTable 内容

> Phase G 起，stub 只通过 IAT 引用两个**锚点** API；其余在 stub 启动时
> 用 `GetProcAddress` 动态解析。所以 ApiStringTable 是真正被 stub 消费
> 的（M4 期间它仅 round-trip 解密，从不消费）。

stub 需要的最小 API 集合（顺序固定，9 项；slot 0..1 为锚点）：

```
[0] kernel32.dll  GetModuleHandleW   (anchor — wide-char form, present in NativeAOT IAT)
[1] kernel32.dll  GetProcAddress     (anchor)
[2] kernel32.dll  VirtualProtect
[3] kernel32.dll  VirtualAlloc
[4] kernel32.dll  VirtualFree
[5] kernel32.dll  IsDebuggerPresent
[6] kernel32.dll  GetCurrentProcess
[7] kernel32.dll  GetCurrentThread
[8] kernel32.dll  GetThreadContext
```

`GetModuleHandleW` 与 `GetProcAddress` 必须在 packed PE 的 IAT 中静态保留
（让 OS Loader 解析）。**packer 行为**：先看 host 原 IAT 是否已经导入这两个名字，
是则直接复用 host IAT 槽，不动 DataDirectory[Import]；缺其一则在
`.idata2` 中追加一个 `IMAGE_IMPORT_DESCRIPTOR` 仅含缺失的锚点。

API 字符串表用 ChaCha20 加密，stub 启动时:

1. 用 IAT 锚点 `GetModuleHandleW(L"KERNEL32.dll")` 获取 kernel32 句柄
   （wide string 通过运行时 XOR 重建，不留连续字符串）
2. 把加密表拷到 stack 缓冲（≤ 1 KiB），就地 ChaCha20 解密
3. 逐 entry 调 `GetProcAddress(k32, name)` 填 `ResolvedApis` 表
4. 后续 chunk 解压 / 反调试 / TLS 流程全部走该函数指针表

这样 **`VirtualAlloc` / `VirtualProtect` / `IsDebuggerPresent` 等名字
永远不在 stub 字节中以明文出现**。验证脚本：从 packed PE 中按 RVA 切出
stub 段（`.upobf0` 多态名）扫 ASCII，应该 0 命中。

## Packer 行为（M4）

输入 PE 的 sections 按以下规则分类：

| Section | 决策 | 备注 |
|---|---|---|
| `.text` | **打包** | 写入 chunks[i] |
| `.rdata` | **打包** | 写入 chunks[i] |
| `.data` | **打包** | 仅打包 `min(VirtualSize, RawSize)` 部分（VSize > RawSize 的 BSS 区由 OS 分配清零） |
| `.pdata` | **保留原样** | 原 RVA 不变 |
| 任何其他可读段 (`.rsrc`, `_RDATA`) | **保留原样** | 原 RVA 不变 |
| `.reloc` | **保留原样** | 原 RVA 不变 |

新增的 sections：
- `.upobf0` (R, 含 stub `.text`)
- `.upobf1` (R, 含 PayloadHeader + chunks + apitable + data)

`AddressOfEntryPoint` **完全不变**。

DataDirectory[9] (TLS) → 改写为新的 TLS Directory（在 `.upobf0` 里），含 stub callback + 原 callback。

DataDirectory[1] (Import) → 重建：保留所有原 DLL 的 import？还是只保留 stub 需要的？**M4 决定**：完整保留原 IAT 不动（NativeAOT 已经依赖 25 个 DLL），只在原 IAT 之外**追加** stub 需要的 6 个 API 到一个新的 IMAGE_IMPORT_DESCRIPTOR。这样：
- OS Loader 解析所有原 import + stub import
- stub 可以直接 `[rip+disp]` 读 IAT 拿到 API 地址
- 完全不破坏原程序的导入

## Stub 行为（M4）

```c
void stub_tls_callback(void* h, DWORD reason, void* res) {
    if (reason != DLL_PROCESS_ATTACH) {
        if (g_unpacked && g_orig_tls_callback)
            g_orig_tls_callback(h, reason, res);
        return;
    }

    // [1] payload 头通过 RIP-relative 地址常量找到（packer 在 fixup 时填好）
    PayloadHeader* ph = upobf_payload_blob;

    // [2] 解密 + 解析 ApiStringTable（M4 不实际用，因为 IAT 已经有所有 API；
    //     但密文表必须解密以模拟 M5 行为，并且 stub 要校验 magic）
    decrypt_api_table(ph);

    // [3] 对每个 chunk
    for (uint32_t i = 0; i < ph->chunk_count; i++) {
        ChunkEntry* ce = &chunks[i];
        uint8_t* dst = (uint8_t*)image_base + ce->target_rva;

        // 准备目标内存：先改成 RW
        DWORD old;
        VirtualProtect(dst, ce->virtual_size, PAGE_READWRITE, &old);

        // ChaCha20 解密 (in-place 到一个临时缓冲)
        uint8_t* enc = (uint8_t*)ph + ph->data_offset + ce->data_offset;
        uint8_t* tmp = VirtualAlloc(0, ce->data_size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        memcpy(tmp, enc, ce->data_size);
        chacha20_xor_inplace(tmp, ce->data_size, ph->master_key, derive_chunk_nonce(ph, ce));

        // LZMA 解压到 dst
        lzma_decompress(tmp, ce->data_size, dst, ce->virtual_size);
        VirtualFree(tmp, 0, MEM_RELEASE);

        // BCJ 反向
        if (ce->flags & FLAG_BCJ_X86)
            bcj_x86_backward(dst, ce->virtual_size, ce->bcj_base);

        // 恢复原 protect
        VirtualProtect(dst, ce->virtual_size, ce->original_protect, &old);
    }

    g_unpacked = 1;

    // [4] 调用原 TLS callback (如果存在)
    if (g_orig_tls_callback) g_orig_tls_callback(h, reason, res);
}
```

## ImageBase 获取

stub 不通过 PEB.ImageBaseAddress 读（虽然合法但是 PEB walk 模式被某些 EDR 启发式标记）。改用：取 stub 函数本身的地址 → 减去 stub 在 image 中的 RVA → 得到 ImageBase。
具体：packer 在 fixup 时把 "stub_tls_callback 函数自身在 image 中的 RVA" 写入一个 stub 内的常量，运行时用 `&stub_tls_callback - that_rva = ImageBase`。

## Fixup 接口

stub_link 已暴露的 `AbsFixup` + `FixupTarget` 在 M4 阶段需要扩展：

```rust
pub enum FixupTarget {
    LocalSymbol(String),
    OriginalOep,
    OriginalTlsCallback,
    PayloadBlobVa,        // VA of PayloadHeader
    StubSelfRva,          // RVA of the stub callback function itself
}
```

packer 在写最终 PE 时：
1. 决定 stub `.text'` 段的最终 RVA（通常紧跟原始 last section）
2. 决定 payload `.upobf1` 段的最终 RVA
3. 计算每个 fixup 的目标值，写入 stub bytes
4. 把所有 ADDR64 fixup 加入 PE 的 `.reloc` 表（让 ASLR 能正确重定位）

## 长度上限

- `chunk_count <= 64` (足够覆盖 .text/.rdata/.data 等大段)
- `api_table_size <= 4096`
- 单 chunk 解压后 size <= 1 GB
- payload 总大小 <= 2 GB（PE32+ 的 32-bit RVA 限制）

## 兼容性约定

- magic + version 不匹配 → stub 应当 silently exit（不 crash）
- chunk_count == 0 → stub 跳过解压，只调原 TLS callback（"穿透模式"）
- 所有 flags 未识别位 → stub 应忽略并按其余 bit 处理
