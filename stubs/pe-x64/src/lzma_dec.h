/* upobf stub: LZMA decoder header.
 *
 * Vendored from LZMA SDK's LzmaDec.h + 7zTypes.h (Igor Pavlov, public
 * domain) with the following changes:
 *   - Inlined the small subset of 7zTypes.h we actually use (Byte / UInt
 *     types, SRes, Bool, ISzAlloc) so the stub does not need 7zTypes.h.
 *   - Removed _WIN32 windows.h pulls and __fastcall calling convention
 *     macros (we always use the platform default).
 *   - Removed all stream / lookahead interfaces we do not need.
 *   - Wrapped public API names with `upobf_` namespace via the bottom
 *     of this file to avoid clashes if the SDK is ever linked alongside.
 *
 * Original LzmaDec.h header: 2018-04-21 : Igor Pavlov : Public domain
 */

#ifndef UPOBF_LZMA_DEC_H
#define UPOBF_LZMA_DEC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 7zTypes.h subset ---------------------------------------- */

typedef int      SRes;
typedef int      Bool;
typedef uint8_t  Byte;
typedef int16_t  Int16;
typedef uint16_t UInt16;
typedef int32_t  Int32;
typedef uint32_t UInt32;
typedef int64_t  Int64;
typedef uint64_t UInt64;
typedef size_t   SizeT;

#define True  1
#define False 0

#define SZ_OK                 0
#define SZ_ERROR_DATA         1
#define SZ_ERROR_MEM          2
#define SZ_ERROR_UNSUPPORTED  4
#define SZ_ERROR_PARAM        5
#define SZ_ERROR_INPUT_EOF    6
#define SZ_ERROR_FAIL         11

#ifndef RINOK
#define RINOK(x) { int __res__ = (x); if (__res__ != 0) return __res__; }
#endif

/* Calling convention macros from the SDK: stripped down to defaults. */
#define MY_FAST_CALL
#define MY_NO_INLINE
#define MY_FORCE_INLINE static inline __attribute__((always_inline))
#define MY_CDECL

typedef struct ISzAlloc ISzAlloc;
typedef const ISzAlloc *ISzAllocPtr;

struct ISzAlloc
{
    void *(*Alloc)(ISzAllocPtr p, size_t size);
    void  (*Free)(ISzAllocPtr p, void *address);
};

#define ISzAlloc_Alloc(p, size) (p)->Alloc(p, size)
#define ISzAlloc_Free(p, a)     (p)->Free(p, a)

/* ---------- LzmaDec.h --------------------------------------------- */

typedef
#ifdef _LZMA_PROB32
    UInt32
#else
    UInt16
#endif
    CLzmaProb;

#define LZMA_PROPS_SIZE 5

typedef struct _CLzmaProps
{
    Byte  lc;
    Byte  lp;
    Byte  pb;
    Byte  _pad_;
    UInt32 dicSize;
} CLzmaProps;

SRes LzmaProps_Decode(CLzmaProps *p, const Byte *data, unsigned size);

#define LZMA_REQUIRED_INPUT_MAX 20

typedef struct
{
    /* Don't change this structure. ASM code can use it. */
    CLzmaProps prop;
    CLzmaProb *probs;
    CLzmaProb *probs_1664;
    Byte      *dic;
    SizeT      dicBufSize;
    SizeT      dicPos;
    const Byte*buf;
    UInt32     range;
    UInt32     code;
    UInt32     processedPos;
    UInt32     checkDicSize;
    UInt32     reps[4];
    UInt32     state;
    UInt32     remainLen;

    UInt32     numProbs;
    unsigned   tempBufSize;
    Byte       tempBuf[LZMA_REQUIRED_INPUT_MAX];
} CLzmaDec;

#define LzmaDec_Construct(p) { (p)->dic = NULL; (p)->probs = NULL; }

void LzmaDec_Init(CLzmaDec *p);

typedef enum
{
    LZMA_FINISH_ANY,
    LZMA_FINISH_END
} ELzmaFinishMode;

typedef enum
{
    LZMA_STATUS_NOT_SPECIFIED,
    LZMA_STATUS_FINISHED_WITH_MARK,
    LZMA_STATUS_NOT_FINISHED,
    LZMA_STATUS_NEEDS_MORE_INPUT,
    LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK
} ELzmaStatus;

SRes LzmaDec_AllocateProbs(CLzmaDec *p, const Byte *props, unsigned propsSize, ISzAllocPtr alloc);
void LzmaDec_FreeProbs(CLzmaDec *p, ISzAllocPtr alloc);

SRes LzmaDec_Allocate(CLzmaDec *p, const Byte *props, unsigned propsSize, ISzAllocPtr alloc);
void LzmaDec_Free(CLzmaDec *p, ISzAllocPtr alloc);

SRes LzmaDec_DecodeToDic(CLzmaDec *p, SizeT dicLimit,
        const Byte *src, SizeT *srcLen, ELzmaFinishMode finishMode, ELzmaStatus *status);

SRes LzmaDec_DecodeToBuf(CLzmaDec *p, Byte *dest, SizeT *destLen,
        const Byte *src, SizeT *srcLen, ELzmaFinishMode finishMode, ELzmaStatus *status);

SRes LzmaDecode(Byte *dest, SizeT *destLen, const Byte *src, SizeT *srcLen,
        const Byte *propData, unsigned propSize, ELzmaFinishMode finishMode,
        ELzmaStatus *status, ISzAllocPtr alloc);

/* ---------- upobf wrapper ---------------------------------------- */

/* Decompress an LZMA "alone" format stream:
 *   13-byte header (5 bytes properties + 8 bytes uncompressed size or
 *   0xFF...FF) followed by the raw range-coded payload.
 *
 * Inputs:
 *   src         pointer to alone stream (header + body)
 *   src_len     total bytes available at src
 *   dst         pre-allocated output buffer
 *   dst_capacity bytes available at dst (must be >= expected size)
 *   alloc_fn / free_fn:
 *     callbacks used to allocate the LZMA probability table (+ optional
 *     dictionary). The stub provides VirtualAlloc / VirtualFree wrappers.
 *
 * Output:
 *   *out_dst_size  = bytes actually written to dst
 *
 * Returns 0 on success, non-zero on error (mirrors SZ_* codes).
 */
int upobf_lzma_decompress_alone(
    const uint8_t *src, uint32_t src_len,
    uint8_t       *dst, uint32_t dst_capacity, uint32_t *out_dst_size,
    void *(*alloc_fn)(void *user, uint32_t),
    void  (*free_fn)(void *user, void *),
    void  *user);

#ifdef __cplusplus
}
#endif

#endif /* UPOBF_LZMA_DEC_H */
