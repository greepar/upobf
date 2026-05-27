//! Payload blob builder (M4).
//!
//! Translates a list of `(target_rva, raw_bytes, original_protect)` tuples
//! into the on-wire payload format defined in `docs/protocol-m4.md`:
//!
//!   PayloadHeader (84 bytes, packed)
//!   ChunkEntry[N] (40 bytes each, packed)
//!   ApiStringTable (encrypted)
//!   ChunkData (encrypted+compressed+filtered, concatenated)
//!
//! The struct sizes are asserted at compile time so a packer/stub
//! divergence becomes a build error instead of a runtime crash.

use anyhow::{Context, Result};
use byteorder::{ByteOrder, LittleEndian};

use upobf_core::{
    compress::lzma_compress,
    crypto::{
        chacha20::{self, Key, Nonce},
        prng::Polymorphic,
    },
    filter::bcj_x86,
};

// ---------------------------------------------------------------------------
// Wire-format constants (must match `stubs/pe-x64/include/payload.h`).
// ---------------------------------------------------------------------------

pub const UPOBF_PAYLOAD_MAGIC: u32 = 0x42504F55; // 'U','P','O','B' little-endian
pub const UPOBF_PAYLOAD_VERSION: u32 = 1;
pub const UPOBF_FLAG_BCJ_X86: u32 = 1 << 0;
pub const UPOBF_FLAG_LZMA: u32 = 1 << 1;
pub const UPOBF_FLAG_CHACHA20: u32 = 1 << 2;

pub const PAYLOAD_HEADER_SIZE: usize = 84;
pub const CHUNK_ENTRY_SIZE: usize = 40;

/// Hard cap, mirrors `UPOBF_MAX_CHUNK_COUNT` in the stub.
pub const MAX_CHUNK_COUNT: usize = 64;
/// Hard cap, mirrors `UPOBF_MAX_API_TABLE_SIZE` in the stub.
pub const MAX_API_TABLE_SIZE: usize = 4096;

/// First 12 bytes of the ASCII string `"upobf:apinonce"` (matches the stub).
pub const FIXED_API_NONCE: [u8; 12] = *b"upobf:apinon";

/// Number of API entries in the protocol table (must match
/// `UPOBF_API_COUNT`). Phase G expanded this from 6 to 9: every API
/// the stub uses goes through the (encrypted) string table and is
/// resolved via GetProcAddress at runtime. Only two anchors remain
/// in the import table, slot 0 and slot 1.
pub const API_COUNT: usize = 9;

/// Indices into the API table. The order is part of the protocol —
/// stub-side `enum` in `api_resolve.h` mirrors it 1:1.
pub const IDX_GET_MODULE_HANDLE_W: usize = 0;
pub const IDX_GET_PROC_ADDRESS: usize = 1;
pub const IDX_VIRTUAL_PROTECT: usize = 2;
pub const IDX_VIRTUAL_ALLOC: usize = 3;
pub const IDX_VIRTUAL_FREE: usize = 4;
pub const IDX_IS_DEBUGGER_PRESENT: usize = 5;
pub const IDX_GET_CURRENT_PROCESS: usize = 6;
pub const IDX_GET_CURRENT_THREAD: usize = 7;
pub const IDX_GET_THREAD_CONTEXT: usize = 8;

/// Fixed name list driving the API string table. The stub indexes by
/// position so this order is part of the protocol. Slots 0 and 1 are
/// "anchors" — they stay in the packed PE's IAT so the OS Loader
/// resolves them for us; everything else is GetProcAddress'd from
/// inside the stub at runtime.
///
/// We pick the wide-character `GetModuleHandleW` over the ASCII form
/// because the demo NativeAOT corpus (and most modern Windows
/// binaries) imports it but not `GetModuleHandleA`. Sticking with
/// what the host already pulls in lets us avoid rewriting
/// DataDirectory[Import], which destabilises NativeAOT bootstrap.
pub const API_NAMES: [(&str, &str); API_COUNT] = [
    ("KERNEL32.dll", "GetModuleHandleW"), // 0 anchor
    ("KERNEL32.dll", "GetProcAddress"),   // 1 anchor
    ("KERNEL32.dll", "VirtualProtect"),   // 2 dynamic
    ("KERNEL32.dll", "VirtualAlloc"),     // 3 dynamic
    ("KERNEL32.dll", "VirtualFree"),      // 4 dynamic
    ("KERNEL32.dll", "IsDebuggerPresent"),// 5 dynamic
    ("KERNEL32.dll", "GetCurrentProcess"),// 6 dynamic
    ("KERNEL32.dll", "GetCurrentThread"), // 7 dynamic
    ("KERNEL32.dll", "GetThreadContext"), // 8 dynamic
];

/// Number of leading entries in [`API_NAMES`] that are anchors. Anchor
/// APIs are referenced from the stub via `__imp_*` thunks so the OS
/// Loader fills them in; the rest are resolved at runtime via
/// `GetProcAddress`. Bumping this count is the protocol-level lever
/// for trading IAT visibility for stub complexity.
pub const API_ANCHOR_COUNT: usize = 2;

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// One section of the host image we want to compress and decode at runtime.
#[derive(Debug, Clone)]
pub struct PayloadInput {
    /// RVA where the stub must write the decoded bytes.
    pub target_rva: u32,
    /// Final size of the decoded region (the stub writes at most this many
    /// bytes; the OS Loader has already mapped the section).
    pub virtual_size: u32,
    /// `IMAGE_SECTION_HEADER.Characteristics` so the stub can restore the
    /// original protect after writing.
    pub original_protect: u32,
    /// Raw bytes from the original section.
    pub data: Vec<u8>,
    /// Apply the BCJ x86 filter before LZMA. Improves compression for
    /// instruction streams (`.text`) but **mangles** non-code data
    /// because the filter rewrites bytes that look like x86
    /// `call`/`jmp rel32` opcodes. `.rdata` and similar
    /// non-instruction sections must set this to `false`.
    pub apply_bcj: bool,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Result of building a payload: bytes ready to be embedded plus key
/// material so the test layer can sanity-check round-trips.
#[derive(Debug)]
pub struct BuiltPayload {
    pub bytes: Vec<u8>,
    pub master_key: Key,
    pub master_nonce: Nonce,
}

/// Build a payload blob.
pub fn build_payload(inputs: &[PayloadInput], poly: &Polymorphic) -> Result<BuiltPayload> {
    if inputs.len() > MAX_CHUNK_COUNT {
        anyhow::bail!(
            "too many input chunks ({}); MAX_CHUNK_COUNT={}",
            inputs.len(),
            MAX_CHUNK_COUNT
        );
    }

    let master_key = poly.derive_key("payload.master.key");
    let master_nonce = poly.derive_nonce("payload.master.nonce");

    // ---- 1. Encode each chunk ------------------------------------------
    struct EncodedChunk {
        target_rva: u32,
        virtual_size: u32,
        original_protect: u32,
        bcj_base: u32,
        flags: u32,
        sub_nonce: [u8; 12],
        bytes: Vec<u8>,
    }
    let mut encoded: Vec<EncodedChunk> = Vec::with_capacity(inputs.len());
    for (i, inp) in inputs.iter().enumerate() {
        // BCJ forward — opt-in per chunk. The filter rewrites bytes
        // that look like x86 call/jmp rel32 opcodes and is a clear
        // win on `.text` (typically 5-15% extra compression) but
        // **mangles** non-code data, so callers feeding in `.rdata`
        // chunks etc. must set `apply_bcj=false`.
        let mut buf = inp.data.clone();
        let mut chunk_flags = UPOBF_FLAG_LZMA | UPOBF_FLAG_CHACHA20;
        if inp.apply_bcj {
            bcj_x86::forward(&mut buf, inp.target_rva);
            chunk_flags |= UPOBF_FLAG_BCJ_X86;
        }

        // LZMA compress.
        let compressed = lzma_compress(&buf)
            .with_context(|| format!("LZMA compress chunk #{}", i))?;
        // Drop the working buffer asap.
        drop(buf);

        // Per-chunk sub-nonce derivation.
        let label = format!("payload.chunk.{}.nonce", i);
        let sub_nonce_full: [u8; 32] = poly.derive(&label);
        let mut sub_nonce = [0u8; 12];
        sub_nonce.copy_from_slice(&sub_nonce_full[..12]);

        // ChaCha20 encrypt with effective nonce = master_nonce XOR sub_nonce.
        let chunk_nonce = xor12(&master_nonce, &sub_nonce);
        let mut ct = compressed;
        chacha20::encrypt_in_place(&mut ct, &master_key, &chunk_nonce)
            .with_context(|| format!("ChaCha20 encrypt chunk #{}", i))?;

        encoded.push(EncodedChunk {
            target_rva: inp.target_rva,
            virtual_size: inp.virtual_size,
            original_protect: inp.original_protect,
            bcj_base: inp.target_rva,
            flags: chunk_flags,
            sub_nonce,
            bytes: ct,
        });
    }

    // ---- 2. Build encrypted ApiStringTable -----------------------------
    let api_table_plain = build_api_table_plain()?;
    if api_table_plain.len() > MAX_API_TABLE_SIZE {
        anyhow::bail!(
            "API string table {} bytes exceeds MAX_API_TABLE_SIZE={}",
            api_table_plain.len(),
            MAX_API_TABLE_SIZE
        );
    }
    let api_nonce = xor12(&master_nonce, &FIXED_API_NONCE);
    let mut api_table = api_table_plain.clone();
    chacha20::encrypt_in_place(&mut api_table, &master_key, &api_nonce)
        .context("ChaCha20 encrypt API table")?;

    // ---- 3. Compute layout offsets -------------------------------------
    let chunks_offset: u32 = PAYLOAD_HEADER_SIZE as u32;
    let chunks_size: u32 = (encoded.len() * CHUNK_ENTRY_SIZE) as u32;
    let api_table_offset: u32 = chunks_offset + chunks_size;
    let api_table_size: u32 = api_table.len() as u32;
    let data_offset: u32 = api_table_offset + api_table_size;

    let mut chunk_offsets = Vec::with_capacity(encoded.len());
    let mut running: u32 = 0;
    for ec in &encoded {
        chunk_offsets.push(running);
        running = running
            .checked_add(ec.bytes.len() as u32)
            .context("chunk data offset overflow")?;
    }
    let data_size: u32 = running;

    // ---- 4. Serialise --------------------------------------------------
    let total_size: usize = data_offset as usize + data_size as usize;
    let mut out = vec![0u8; total_size];

    // PayloadHeader
    write_payload_header(
        &mut out[0..PAYLOAD_HEADER_SIZE],
        Header {
            magic: UPOBF_PAYLOAD_MAGIC,
            version: UPOBF_PAYLOAD_VERSION,
            header_size: PAYLOAD_HEADER_SIZE as u32,
            chunk_count: encoded.len() as u32,
            chunks_offset,
            api_table_offset,
            api_table_size,
            data_offset,
            data_size,
            flags: 0,
            master_key,
            master_nonce,
        },
    );

    // ChunkEntry[]
    for (i, ec) in encoded.iter().enumerate() {
        let off = chunks_offset as usize + i * CHUNK_ENTRY_SIZE;
        write_chunk_entry(
            &mut out[off..off + CHUNK_ENTRY_SIZE],
            ChunkRow {
                target_rva: ec.target_rva,
                virtual_size: ec.virtual_size,
                data_offset: chunk_offsets[i],
                data_size: ec.bytes.len() as u32,
                original_protect: ec.original_protect,
                bcj_base: ec.bcj_base,
                flags: ec.flags,
                sub_nonce: ec.sub_nonce,
            },
        );
    }

    // ApiStringTable
    out[api_table_offset as usize..(api_table_offset + api_table_size) as usize]
        .copy_from_slice(&api_table);

    // ChunkData
    let mut cursor = data_offset as usize;
    for ec in &encoded {
        out[cursor..cursor + ec.bytes.len()].copy_from_slice(&ec.bytes);
        cursor += ec.bytes.len();
    }
    debug_assert_eq!(cursor, total_size);

    Ok(BuiltPayload {
        bytes: out,
        master_key,
        master_nonce,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn xor12(a: &[u8; 12], b: &[u8; 12]) -> [u8; 12] {
    let mut out = [0u8; 12];
    for i in 0..12 {
        out[i] = a[i] ^ b[i];
    }
    out
}

struct Header {
    magic: u32,
    version: u32,
    header_size: u32,
    chunk_count: u32,
    chunks_offset: u32,
    api_table_offset: u32,
    api_table_size: u32,
    data_offset: u32,
    data_size: u32,
    flags: u32,
    master_key: [u8; 32],
    master_nonce: [u8; 12],
}

fn write_payload_header(buf: &mut [u8], h: Header) {
    debug_assert_eq!(buf.len(), PAYLOAD_HEADER_SIZE);
    LittleEndian::write_u32(&mut buf[0..4], h.magic);
    LittleEndian::write_u32(&mut buf[4..8], h.version);
    LittleEndian::write_u32(&mut buf[8..12], h.header_size);
    LittleEndian::write_u32(&mut buf[12..16], h.chunk_count);
    LittleEndian::write_u32(&mut buf[16..20], h.chunks_offset);
    LittleEndian::write_u32(&mut buf[20..24], h.api_table_offset);
    LittleEndian::write_u32(&mut buf[24..28], h.api_table_size);
    LittleEndian::write_u32(&mut buf[28..32], h.data_offset);
    LittleEndian::write_u32(&mut buf[32..36], h.data_size);
    LittleEndian::write_u32(&mut buf[36..40], h.flags);
    buf[40..72].copy_from_slice(&h.master_key);
    buf[72..84].copy_from_slice(&h.master_nonce);
}

struct ChunkRow {
    target_rva: u32,
    virtual_size: u32,
    data_offset: u32,
    data_size: u32,
    original_protect: u32,
    bcj_base: u32,
    flags: u32,
    sub_nonce: [u8; 12],
}

fn write_chunk_entry(buf: &mut [u8], c: ChunkRow) {
    debug_assert_eq!(buf.len(), CHUNK_ENTRY_SIZE);
    LittleEndian::write_u32(&mut buf[0..4], c.target_rva);
    LittleEndian::write_u32(&mut buf[4..8], c.virtual_size);
    LittleEndian::write_u32(&mut buf[8..12], c.data_offset);
    LittleEndian::write_u32(&mut buf[12..16], c.data_size);
    LittleEndian::write_u32(&mut buf[16..20], c.original_protect);
    LittleEndian::write_u32(&mut buf[20..24], c.bcj_base);
    LittleEndian::write_u32(&mut buf[24..28], c.flags);
    buf[28..40].copy_from_slice(&c.sub_nonce);
}

/// Build the plaintext API string table. The layout matches the C
/// definitions in `payload.h`:
///
/// ```text
///   ApiTableHeader { count: u32 }
///   ApiEntry[count] { module_off:u16, function_off:u16, module_len:u16, function_len:u16 }
///   <byte pool: all module/function strings, deduplicated>
/// ```
fn build_api_table_plain() -> Result<Vec<u8>> {
    let entries_off: usize = 4; // ApiTableHeader.count
    let entries_size: usize = API_COUNT * 8;
    let mut pool: Vec<u8> = Vec::new();

    // Deduplicate strings so the table is compact.
    let mut interned: Vec<(String, u16)> = Vec::new();
    let mut intern = |s: &str, pool: &mut Vec<u8>| -> Result<(u16, u16)> {
        if let Some((_, off)) = interned.iter().find(|(t, _)| t == s) {
            return Ok((*off, s.len() as u16));
        }
        let off_in_pool = pool.len();
        pool.extend_from_slice(s.as_bytes());
        let absolute_off = entries_off + entries_size + off_in_pool;
        if absolute_off > u16::MAX as usize {
            anyhow::bail!("API string offset overflows u16");
        }
        interned.push((s.to_string(), absolute_off as u16));
        Ok((absolute_off as u16, s.len() as u16))
    };

    let mut entries_bytes = vec![0u8; entries_size];
    for (i, (module, function)) in API_NAMES.iter().enumerate() {
        let (m_off, m_len) = intern(module, &mut pool)?;
        let (f_off, f_len) = intern(function, &mut pool)?;
        let off = i * 8;
        LittleEndian::write_u16(&mut entries_bytes[off..off + 2], m_off);
        LittleEndian::write_u16(&mut entries_bytes[off + 2..off + 4], f_off);
        LittleEndian::write_u16(&mut entries_bytes[off + 4..off + 6], m_len);
        LittleEndian::write_u16(&mut entries_bytes[off + 6..off + 8], f_len);
    }

    let mut out = Vec::with_capacity(4 + entries_size + pool.len());
    out.extend_from_slice(&u32::to_le_bytes(API_COUNT as u32));
    out.extend_from_slice(&entries_bytes);
    out.extend_from_slice(&pool);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn poly() -> Polymorphic {
        Polymorphic::new([7u8; 32])
    }

    #[test]
    fn header_layout_size_matches_protocol() {
        // Field-list arithmetic per docs/protocol-m4.md.
        assert_eq!(PAYLOAD_HEADER_SIZE, 10 * 4 + 32 + 12);
        assert_eq!(CHUNK_ENTRY_SIZE, 7 * 4 + 12);
    }

    #[test]
    fn build_empty_payload() {
        let p = build_payload(&[], &poly()).unwrap();
        assert!(p.bytes.len() >= PAYLOAD_HEADER_SIZE);
        let magic = LittleEndian::read_u32(&p.bytes[0..4]);
        assert_eq!(magic, UPOBF_PAYLOAD_MAGIC);
        let chunk_count = LittleEndian::read_u32(&p.bytes[12..16]);
        assert_eq!(chunk_count, 0);
    }

    #[test]
    fn roundtrip_one_chunk() {
        // Build a tiny chunk; verify we can decrypt+decompress+BCJ-back.
        let original: Vec<u8> = (0..256u32).map(|x| x as u8).collect();
        let target_rva = 0x1000;
        let inp = PayloadInput {
            target_rva,
            virtual_size: original.len() as u32,
            original_protect: 0x4000_0040, // R | initialized data
            data: original.clone(),
            apply_bcj: true,
        };
        let p = build_payload(&[inp], &poly()).unwrap();

        // Walk the chunk entry.
        let chunks_off = LittleEndian::read_u32(&p.bytes[16..20]) as usize;
        let api_off = LittleEndian::read_u32(&p.bytes[20..24]) as usize;
        let _api_size = LittleEndian::read_u32(&p.bytes[24..28]);
        let data_off = LittleEndian::read_u32(&p.bytes[28..32]) as usize;
        assert_eq!(chunks_off, PAYLOAD_HEADER_SIZE);
        assert!(api_off > chunks_off);
        assert!(data_off > api_off);

        let ce = &p.bytes[chunks_off..chunks_off + CHUNK_ENTRY_SIZE];
        assert_eq!(LittleEndian::read_u32(&ce[0..4]), target_rva);
        assert_eq!(
            LittleEndian::read_u32(&ce[4..8]),
            original.len() as u32
        );
        let chunk_data_size = LittleEndian::read_u32(&ce[12..16]) as usize;
        let mut sub_nonce = [0u8; 12];
        sub_nonce.copy_from_slice(&ce[28..40]);

        // Decrypt chunk
        let mut payload_data = p.bytes[data_off..data_off + chunk_data_size].to_vec();
        let chunk_nonce = xor12(&p.master_nonce, &sub_nonce);
        chacha20::decrypt_in_place(&mut payload_data, &p.master_key, &chunk_nonce).unwrap();

        // LZMA decompress
        let mut decompressed =
            upobf_core::compress::lzma_decompress(&payload_data).unwrap();
        // BCJ backward
        bcj_x86::backward(&mut decompressed, target_rva);

        assert_eq!(decompressed, original);
    }
}
