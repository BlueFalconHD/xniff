#pragma once

/*
 * Per-invocation context frame used by the ARM64 entry+exit trampoline.
 *
 * This is intentionally small and stable so it can be shared between:
 * - the trampoline assembly (Sources/libxniff/src/tramp_ex_template.S)
 * - injected hook dylibs (Sources/xniff-hooks)
 * - simple test programs (Sources/xniff-tests)
 */

/* Offsets used by the trampoline (must match xniff_ctx_frame_t). */
#define XNIFF_CTX_FRAME_BYTES      0x80

#define XNIFF_CTX_OFF_LR_ORIG      0x00
#define XNIFF_CTX_OFF_RESUME_PC    0x08
#define XNIFF_CTX_OFF_SP           0x10
#define XNIFF_CTX_OFF_NZCV         0x18

#define XNIFF_CTX_OFF_X0           0x20
#define XNIFF_CTX_OFF_X1           0x28
#define XNIFF_CTX_OFF_X2           0x30
#define XNIFF_CTX_OFF_X3           0x38
#define XNIFF_CTX_OFF_X4           0x40
#define XNIFF_CTX_OFF_X5           0x48
#define XNIFF_CTX_OFF_X6           0x50
#define XNIFF_CTX_OFF_X7           0x58

#define XNIFF_CTX_OFF_X8           0x60
#define XNIFF_CTX_OFF_RET_X0       0x68
#define XNIFF_CTX_OFF_RET_Q0       0x70 /* 16 bytes */

#ifndef __ASSEMBLER__
#include <stdint.h>

typedef struct xniff_ctx_frame {
    uint64_t lr_orig;      /* +0x00: original LR (return target) */
    uint64_t resume_pc;    /* +0x08: resume PC (after entry patch window) */
    uint64_t sp;           /* +0x10: SP at function entry (for stack args) */
    uint64_t nzcv;         /* +0x18: NZCV at function entry */

    /* Register arguments snapshot at entry */
    uint64_t x[8];         /* +0x20..+0x58: x0..x7 */

    /* Extra register state */
    uint64_t x8;           /* +0x60: x8 (indirect-result / scratch on some ABIs) */

    /* Saved at exit (modifiable by exit-hook) */
    uint64_t ret_x0;       /* +0x68: return value in x0 */
    uint8_t  ret_q0[16];   /* +0x70: return value in v0/q0 (for FP/SIMD returns) */
} xniff_ctx_frame_t;

_Static_assert(sizeof(xniff_ctx_frame_t) == XNIFF_CTX_FRAME_BYTES,
               "xniff_ctx_frame_t must be 0x80 bytes");
#endif
