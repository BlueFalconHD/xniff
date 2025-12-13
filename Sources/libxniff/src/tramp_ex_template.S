.text
#include "xniff_ctx_config.h"
#include "../../shared/xniff_ctx.h"
.align 2
// Ensure valid landing pads for indirect branches/returns on BTI-enabled systems
// (harmless NOPs where BTI is not enforced).
.globl _XTRAMP_START_AFTER_PROLOGUE
.globl _XTRAMP_HOOK_ADRP
.globl _XTRAMP_HOOK_ADD
.globl _XTRAMP_CTX_ADRP
.globl _XTRAMP_CTX_ADD
.globl _XTRAMP_RESUME_ADRP
.globl _XTRAMP_RESUME_ADD
.globl _XTRAMP_EXITLR_ADRP
.globl _XTRAMP_EXITLR_ADD
.globl _XTRAMP_RETURN_ADRP
.globl _XTRAMP_RETURN_ADD
.globl _XTRAMP_EXIT_STUB
.globl _XTRAMP_EXIT_CTX_ADRP
.globl _XTRAMP_EXIT_CTX_ADD
.globl _XTRAMP_EXIT_HOOK_ADRP
.globl _XTRAMP_EXIT_HOOK_ADD
.globl _XTRAMP_NOOP
.globl _XTRAMP_END

// Extended trampoline that snapshots args, redirects LR to exit stub, and calls entry hook.
_XTRAMP_START_AFTER_PROLOGUE:
    // Valid BTI landing for BR from patched entry; allow both jump/call
    BTI     jc
    // Save all general-purpose registers x0-x30
    SUB     SP, SP, #0x120
    STP     X0,  X1,  [SP, #0x00]
    STP     X2,  X3,  [SP, #0x10]
    STP     X4,  X5,  [SP, #0x20]
    STP     X6,  X7,  [SP, #0x30]
    STP     X8,  X9,  [SP, #0x40]
    STP     X10, X11, [SP, #0x50]
    STP     X12, X13, [SP, #0x60]
    STP     X14, X15, [SP, #0x70]
    STP     X16, X17, [SP, #0x80]
    STP     X18, X19, [SP, #0x90]
    STP     X20, X21, [SP, #0xA0]
    STP     X22, X23, [SP, #0xB0]
    STP     X24, X25, [SP, #0xC0]
    STP     X26, X27, [SP, #0xD0]
    STP     X28, X29, [SP, #0xE0]
    STR     X30,      [SP, #0xF0]

    // Save FP/SIMD state and NZCV to ensure complete transparency across calls.
    // Layout (at current SP after GPR save):
    //   [0x000..0x1FF]  Q0..Q31 (512 bytes)
    //   [0x200]         FPCR (8 bytes)
    //   [0x208]         FPSR (8 bytes)
    //   [0x210]         NZCV (8 bytes)
    SUB     SP, SP, #0x220
    STP     Q0,  Q1,  [SP, #0x000]
    STP     Q2,  Q3,  [SP, #0x020]
    STP     Q4,  Q5,  [SP, #0x040]
    STP     Q6,  Q7,  [SP, #0x060]
    STP     Q8,  Q9,  [SP, #0x080]
    STP     Q10, Q11, [SP, #0x0A0]
    STP     Q12, Q13, [SP, #0x0C0]
    STP     Q14, Q15, [SP, #0x0E0]
    STP     Q16, Q17, [SP, #0x100]
    STP     Q18, Q19, [SP, #0x120]
    STP     Q20, Q21, [SP, #0x140]
    STP     Q22, Q23, [SP, #0x160]
    STP     Q24, Q25, [SP, #0x180]
    STP     Q26, Q27, [SP, #0x1A0]
    STP     Q28, Q29, [SP, #0x1C0]
    STP     Q30, Q31, [SP, #0x1E0]
    MRS     X14, FPCR
    STR     X14,      [SP, #0x200]
    MRS     X14, FPSR
    STR     X14,      [SP, #0x208]
    MRS     X14, NZCV
    STR     X14,      [SP, #0x210]

    // Compute per-thread context frame address in X9
_XTRAMP_CTX_ADRP:
    ADRP    X9, _dummy_patch_hook@PAGE         // patched to context base for this trampoline slot
_XTRAMP_CTX_ADD:
    ADD     X9, X9, _dummy_patch_hook@PAGEOFF
    MRS     X10, TPIDRRO_EL0                   // thread id base
    // Mix bits to reduce aliasing across threads (TPIDRRO is page-aligned).
    EOR     X10, X10, X10, LSR #15
    EOR     X10, X10, X10, LSR #30
    // Derive per-thread index from mixed value and scale by slot size.
    // Configurable via XNIFF_CTX_IDX_BITS and XNIFF_CTX_SLOT_SIZE.
    // Use AArch64 form (UBFM) rather than UBFX alias for broad assembler compatibility.
    UBFM    X10, X10, #0, #(XNIFF_CTX_IDX_BITS - 1) // idx in [0, 2^bits)
    MOV     X12, #XNIFF_CTX_SLOT_SIZE
    MUL     X10, X10, X12                      // bytes per thread-slot
    ADD     X9, X9, X10                        // X9 = thread-slot base
    MOV     X14, X9                            // X14 = slot base (for depth updates)
    // depth at [X9, #0] (32-bit)
    LDR     W11, [X14, #0]
    MOV     W13, W11                           // old depth
    // Re-entrancy guard (Frida-like): if we are already inside this trampoline on
    // the current thread, bypass completely (do not touch LR, do not update depth,
    // do not use the per-thread frames). This prevents ring-buffer overflow and
    // keeps nested calls maximally transparent.
    CBNZ    W11, _XTRAMP_RESTORE_AND_CONTINUE
    // frame = base + header + ((depth & (COUNT-1)) * frame_size)
    AND     W12, W11, #(XNIFF_CTX_FRAME_COUNT - 1)
    UXTW    X12, W12
    LSL     X12, X12, #XNIFF_CTX_FRAME_SHIFT
    ADD     X9,  X9,  #XNIFF_CTX_SLOT_HEADER_BYTES
    ADD     X9,  X9,  X12                      // X9 = frame ptr

    // Capture entry SP and NZCV into frame so hooks can inspect stack arguments and flags.
    // At this point SP has been lowered by: 0x120 (GPR save) + 0x220 (SIMD save) = 0x340.
    ADD     X17, SP, #(0x120 + 0x220)          // original SP at function entry
    STR     X17, [X9, #XNIFF_CTX_OFF_SP]
    LDR     X17, [SP, #0x210]                  // NZCV saved in SIMD-save block
    STR     X17, [X9, #XNIFF_CTX_OFF_NZCV]
    STR     X8,  [X9, #XNIFF_CTX_OFF_X8]

    // Save resume PC into frame
_XTRAMP_RESUME_ADRP:
    ADRP    X15, _dummy_patch_hook@PAGE        // patched to resume address
_XTRAMP_RESUME_ADD:
    ADD     X15, X15, _dummy_patch_hook@PAGEOFF
    STR     X15, [X9, #XNIFF_CTX_OFF_RESUME_PC]

    // Save original LR register (incoming return address) into our frame.
    // We will later replace X30 (LR) with our exit stub *before* executing the
    // relocated prologue, so the callee's own prologue will save/sign it as usual.
    MOV     X16, X30
    STR     X16, [X9,  #XNIFF_CTX_OFF_LR_ORIG] // frame->lr_orig

    // Snapshot argument registers into frame (x0..x7)
    STR     X0,  [X9, #XNIFF_CTX_OFF_X0]
    STR     X1,  [X9, #XNIFF_CTX_OFF_X1]
    STR     X2,  [X9, #XNIFF_CTX_OFF_X2]
    STR     X3,  [X9, #XNIFF_CTX_OFF_X3]
    STR     X4,  [X9, #XNIFF_CTX_OFF_X4]
    STR     X5,  [X9, #XNIFF_CTX_OFF_X5]
    STR     X6,  [X9, #XNIFF_CTX_OFF_X6]
    STR     X7,  [X9, #XNIFF_CTX_OFF_X7]
    // Increment depth and write back
    // Keep old depth in W13 intact for gating below; X14 holds slot base
    ADD     W11, W11, #1
    STR     W11, [X14, #0]

_XTRAMP_HOOK_ADRP:
    ADRP    X16, _dummy_patch_hook@PAGE        // patched to entry hook
_XTRAMP_HOOK_ADD:
    ADD     X16, X16, _dummy_patch_hook@PAGEOFF
    // Call entry hook, passing x0 = ctx_frame.
    // The hook may modify ctx->x[0..7] / ctx->x8 to rewrite arguments.
    STR     X9,  [SP, #0x218]                  // preserve frame ptr across call
    MOV     X0,  X9
    BLR     X16
    LDR     X9,  [SP, #0x218]
    // Apply any rewritten arguments by updating our saved GPR block.
    // GPR-save block begins at SP + 0x220 (SIMD-save size).
    LDR     X10, [X9, #XNIFF_CTX_OFF_X0]
    STR     X10, [SP, #(0x220 + 0x00)]
    LDR     X10, [X9, #XNIFF_CTX_OFF_X1]
    STR     X10, [SP, #(0x220 + 0x08)]
    LDR     X10, [X9, #XNIFF_CTX_OFF_X2]
    STR     X10, [SP, #(0x220 + 0x10)]
    LDR     X10, [X9, #XNIFF_CTX_OFF_X3]
    STR     X10, [SP, #(0x220 + 0x18)]
    LDR     X10, [X9, #XNIFF_CTX_OFF_X4]
    STR     X10, [SP, #(0x220 + 0x20)]
    LDR     X10, [X9, #XNIFF_CTX_OFF_X5]
    STR     X10, [SP, #(0x220 + 0x28)]
    LDR     X10, [X9, #XNIFF_CTX_OFF_X6]
    STR     X10, [SP, #(0x220 + 0x30)]
    LDR     X10, [X9, #XNIFF_CTX_OFF_X7]
    STR     X10, [SP, #(0x220 + 0x38)]
    LDR     X10, [X9, #XNIFF_CTX_OFF_X8]
    STR     X10, [SP, #(0x220 + 0x40)]         // x8 is at (x8,x9) pair slot
1:

    // Redirect return to our exit stub by updating X30 (LR).
    // This avoids relying on any particular stack-frame layout (e.g. X29-based),
    // and matches Frida Gum's approach of modifying the saved return address in
    // the captured CPU context rather than poking at the function's frame.
_XTRAMP_EXITLR_ADRP:
    ADRP    X16, _XTRAMP_EXIT_STUB@PAGE
_XTRAMP_EXITLR_ADD:
    ADD     X16, X16, _XTRAMP_EXIT_STUB@PAGEOFF
    MOV     X30, X16

_XTRAMP_RESTORE_AND_CONTINUE:
    // Restore FP/SIMD state and NZCV first to minimize side-effects
    LDP     Q0,  Q1,  [SP, #0x000]
    LDP     Q2,  Q3,  [SP, #0x020]
    LDP     Q4,  Q5,  [SP, #0x040]
    LDP     Q6,  Q7,  [SP, #0x060]
    LDP     Q8,  Q9,  [SP, #0x080]
    LDP     Q10, Q11, [SP, #0x0A0]
    LDP     Q12, Q13, [SP, #0x0C0]
    LDP     Q14, Q15, [SP, #0x0E0]
    LDP     Q16, Q17, [SP, #0x100]
    LDP     Q18, Q19, [SP, #0x120]
    LDP     Q20, Q21, [SP, #0x140]
    LDP     Q22, Q23, [SP, #0x160]
    LDP     Q24, Q25, [SP, #0x180]
    LDP     Q26, Q27, [SP, #0x1A0]
    LDP     Q28, Q29, [SP, #0x1C0]
    LDP     Q30, Q31, [SP, #0x1E0]
    LDR     X14,      [SP, #0x200]
    MSR     FPCR, X14
    LDR     X14,      [SP, #0x208]
    MSR     FPSR, X14
    LDR     X14,      [SP, #0x210]
    MSR     NZCV, X14
    ADD     SP, SP, #0x220

    // Restore all GPRs and unwind stack
    // Note: do not restore X30 here; we want the prologue-saved X30 to remain
    // our patched, PAC-signed exit stub so the RETAB in the callee epilogue
    // will branch to our exit path. If we restore X30 from our own save
    // (pre-prologue), it would skip the exit stub.
    // LDR   X30,      [SP, #0xF0]
    LDP     X28, X29, [SP, #0xE0]
    LDP     X26, X27, [SP, #0xD0]
    LDP     X24, X25, [SP, #0xC0]
    LDP     X22, X23, [SP, #0xB0]
    LDP     X20, X21, [SP, #0xA0]
    LDP     X18, X19, [SP, #0x90]
    LDP     X16, X17, [SP, #0x80]
    LDP     X14, X15, [SP, #0x70]
    LDP     X12, X13, [SP, #0x60]
    LDP     X10, X11, [SP, #0x50]
    LDP     X8,  X9,  [SP, #0x40]
    LDP     X6,  X7,  [SP, #0x30]
    LDP     X4,  X5,  [SP, #0x20]
    LDP     X2,  X3,  [SP, #0x10]
    LDP     X0,  X1,  [SP, #0x00]
    ADD     SP, SP, #0x120

_XTRAMP_RETURN_ADRP:
    ADRP    X16, _dummy_trampoline_return@PAGE // patched to resume address
_XTRAMP_RETURN_ADD:
    ADD     X16, X16, _dummy_trampoline_return@PAGEOFF
    BR      X16

// Exit stub: called when target RETs (LR replaced by our address). x0 holds return value.
_XTRAMP_EXIT_STUB:
    // Valid BTI landing for RET
    BTI     c
_XTRAMP_EXIT_CTX_ADRP:
    ADRP    X9, _dummy_patch_hook@PAGE         // patched to same context base as above
_XTRAMP_EXIT_CTX_ADD:
    ADD     X9, X9, _dummy_patch_hook@PAGEOFF
    MRS     X10, TPIDRRO_EL0
    EOR     X10, X10, X10, LSR #15
    EOR     X10, X10, X10, LSR #30
    UBFM    X10, X10, #0, #(XNIFF_CTX_IDX_BITS - 1)
    MOV     X12, #XNIFF_CTX_SLOT_SIZE
    MUL     X10, X10, X12
    ADD     X9,  X9,  X10                      // thread-slot base
    MOV     X14, X9                            // X14 = slot base (for depth updates)
    LDR     W11, [X14, #0]                     // current depth (>= 1)
    // Select the same frame used at entry:
    // entry frame index = depth_before_increment
    // exit sees depth_after_increment, so frame index = (depth - 1)
    SUB     W13, W11, #1                       // W13 = frame index for this invocation
    // frame = base + header + ((frame_index & (COUNT-1)) * frame_size)
    AND     W12, W13, #(XNIFF_CTX_FRAME_COUNT - 1)
    UXTW    X12, W12
    LSL     X12, X12, #XNIFF_CTX_FRAME_SHIFT
    ADD     X9,  X9,  #XNIFF_CTX_SLOT_HEADER_BYTES
    ADD     X9,  X9,  X12                      // X9 = frame ptr
    // Save return value into frame (x0 + v0/q0)
    STR     X0,  [X9, #XNIFF_CTX_OFF_RET_X0]
    STR     Q0,  [X9, #XNIFF_CTX_OFF_RET_Q0]
    // Now decrement depth (after selecting frame based on old depth)
    SUB     W11, W11, #1
    // Write back new depth to slot header
    STR     W11, [X14, #0]
    // Call exit hook: x0 is ret, x1 = ctx
_XTRAMP_EXIT_HOOK_ADRP:
    ADRP    X16, _dummy_patch_hook@PAGE
_XTRAMP_EXIT_HOOK_ADD:
    ADD     X16, X16, _dummy_patch_hook@PAGEOFF
    // Preserve return-value registers and flags across exit-hook call to ensure
    // caller observes exactly what the callee returned.
    // Layout (0xB0 bytes):
    //   [0x000..0x07F] q0..q7
    //   [0x080]        x0,x1
    //   [0x090]        x9,x10
    //   [0x0A0]        NZCV
    //   [0x0A8]        depth-after-decrement snapshot (W11)
    SUB     SP, SP, #0xB0
    STP     Q0,  Q1,  [SP, #0x000]
    STP     Q2,  Q3,  [SP, #0x020]
    STP     Q4,  Q5,  [SP, #0x040]
    STP     Q6,  Q7,  [SP, #0x060]
    STP     X0,  X1,  [SP, #0x080]
    STP     X9,  X10, [SP, #0x090]
    MRS     X10, NZCV
    STR     X10,      [SP, #0x0A0]
    // Snapshot depth after decrement for post-call decisions (W11 is caller-saved)
    STR     W11,      [SP, #0x0A8]
    MOV     X1,  X9
    // Call exit hook only when depth reached zero (outermost)
    CBNZ    W11, 1f
    BLR     X16
1:
    // Restore flags and return-value registers (always restore to callee's values)
    LDR     X10,      [SP, #0x0A0]
    MSR     NZCV, X10
    LDP     X9,  X10, [SP, #0x090]
    LDP     X0,  X1,  [SP, #0x080]
    LDP     Q0,  Q1,  [SP, #0x000]
    LDP     Q2,  Q3,  [SP, #0x020]
    LDP     Q4,  Q5,  [SP, #0x040]
    LDP     Q6,  Q7,  [SP, #0x060]
    ADD     SP, SP, #0xB0
    // Apply any rewritten return value from ctx frame.
    LDR     X0,  [X9, #XNIFF_CTX_OFF_RET_X0]
    LDR     Q0,  [X9, #XNIFF_CTX_OFF_RET_Q0]
    LDR     X16, [X9, #XNIFF_CTX_OFF_LR_ORIG]
    MOV     X30, X16
    RET

_XTRAMP_END:

// Simple no-op hook that immediately returns
_XTRAMP_NOOP:
    BTI     jc
    RET
