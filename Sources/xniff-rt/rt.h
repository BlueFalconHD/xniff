// xniff-rt: runtime helpers injected into target processes
#ifndef XNIFF_RT_H
#define XNIFF_RT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Per-call context frame. Snapshot fields are optional; fill what you need.
typedef struct xniff_ctx_frame {
    uint64_t depth;          // call depth (per-thread)
    uint64_t lr_orig;        // original LR to return to
    uint64_t resume_pc;      // address to resume after entry patch
    uint64_t sp;             // SP at snapshot
    uint64_t x[31];          // X0..X30 at snapshot (X30 is LR at entry)
    uint32_t fpsr;           // FP status (optional)
    uint32_t fpcr;           // FP control (optional)
    // Optional snapshot of Q0..Q31 (16 bytes each). Disabled by default for perf.
    // uint8_t  q[32][16];
} xniff_ctx_frame_t;

// Returns the current runtime version string.
__attribute__((visibility("default")))
const char* xniff_rt_version(void);

// Enable/disable full FP state snapshot (no-op by default). Provided for API symmetry.
__attribute__((visibility("default")))
void xniff_rt_set_capture_fp(int enable);

// TLS-backed frame management. These functions are async-signal-unsafe; use for normal calls only.
// Push a new frame and return a pointer to it (owned by runtime; valid until xniff_ctx_exit).
__attribute__((visibility("default")))
xniff_ctx_frame_t* xniff_ctx_enter(void);

// Pop the most recent frame for this thread. Returns pointer to the popped frame for inspection
// during exit; becomes invalid after the next xniff_ctx_enter on this thread.
__attribute__((visibility("default")))
xniff_ctx_frame_t* xniff_ctx_exit(void);

// Default exit hook (does nothing). You can point your trampoline’s exit call at this, or
// export another symbol from a different dylib and look it up after injection.
__attribute__((visibility("default")))
void xniff_exit_hook(uint64_t ret_value, const xniff_ctx_frame_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // XNIFF_RT_H

