// Shared config for per-thread context addressing in trampolines
// Included by both C and preprocessed assembly (.S)
#pragma once

// Number of index bits derived from TPIDRRO_EL0 for per-thread slot selection.
// Larger values reduce cross-thread aliasing in processes with many threads.
// 12 bits => 4096 slots per trampoline slot (approx 1 MiB context region per hook).
#ifndef XNIFF_CTX_IDX_BITS
#define XNIFF_CTX_IDX_BITS 12
#endif

// Frame sizing: each invocation frame is 128 bytes (matches xniff_ctx_frame_t).
#ifndef XNIFF_CTX_FRAME_SHIFT
#define XNIFF_CTX_FRAME_SHIFT 7
#endif
#define XNIFF_CTX_FRAME_SIZE (1u << (XNIFF_CTX_FRAME_SHIFT))

// Number of frames kept per thread to tolerate re-entrancy.
// Must be a power of two so assembly can mask with (COUNT - 1).
#ifndef XNIFF_CTX_FRAME_COUNT
#define XNIFF_CTX_FRAME_COUNT 8u
#endif

// Per-thread slot header bytes (depth + reserved/padding).
#ifndef XNIFF_CTX_SLOT_HEADER_BYTES
#define XNIFF_CTX_SLOT_HEADER_BYTES 16u
#endif

// Per-thread slot size in bytes.
// Layout:
//   [0x00..0x0F] header
//   [0x10..]     XNIFF_CTX_FRAME_COUNT frames of XNIFF_CTX_FRAME_SIZE bytes
#define XNIFF_CTX_SLOT_SIZE (XNIFF_CTX_SLOT_HEADER_BYTES + (XNIFF_CTX_FRAME_COUNT * XNIFF_CTX_FRAME_SIZE))

// Derived constants
#define XNIFF_CTX_INDEX_COUNT   (1u << (XNIFF_CTX_IDX_BITS))
#define XNIFF_CTX_TOTAL_BYTES   (XNIFF_CTX_INDEX_COUNT * XNIFF_CTX_SLOT_SIZE)
#define XNIFF_CTX_INDEX_MASK    (XNIFF_CTX_INDEX_COUNT - 1u)
