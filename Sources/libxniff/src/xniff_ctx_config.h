// Shared config for per-thread context addressing in trampolines
// Included by both C and preprocessed assembly (.S)
#pragma once

// Number of index bits derived from TPIDRRO_EL0 for per-thread slot selection.
// Larger values reduce cross-thread aliasing in processes with many threads.
// 12 bits => 4096 slots per trampoline slot (approx 1 MiB context region per hook).
#ifndef XNIFF_CTX_IDX_BITS
#define XNIFF_CTX_IDX_BITS 12
#endif

// Per-thread slot size shift (bytes = 1 << shift).
// Our frame is 128B and we keep a 2-frame ring buffer => 256 bytes per thread.
#ifndef XNIFF_CTX_SLOT_SHIFT
#define XNIFF_CTX_SLOT_SHIFT 8
#endif

// Derived constants
#define XNIFF_CTX_INDEX_COUNT   (1u << (XNIFF_CTX_IDX_BITS))
#define XNIFF_CTX_SLOT_SIZE     (1u << (XNIFF_CTX_SLOT_SHIFT))
#define XNIFF_CTX_TOTAL_BYTES   (XNIFF_CTX_INDEX_COUNT * XNIFF_CTX_SLOT_SIZE)
#define XNIFF_CTX_INDEX_MASK    (XNIFF_CTX_INDEX_COUNT - 1u)

