.text
#include "xniff_ctx_config.h"
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
    // Configurable via XNIFF_CTX_IDX_BITS and XNIFF_CTX_SLOT_SHIFT.
    // Use AArch64 form (UBFM) rather than UBFX alias for broad assembler compatibility.
    UBFM    X10, X10, #0, #(XNIFF_CTX_IDX_BITS - 1) // idx in [0, 2^bits)
    LSL     X10, X10, #XNIFF_CTX_SLOT_SHIFT    // bytes per thread-slot
    ADD     X9, X9, X10                        // X9 = thread-slot base
    // depth at [X9, #0] (32-bit)
    LDR     W11, [X9, #0]
    MOV     W13, W11                           // save old depth for gating and frame index
    // frame = base + 16 + ((depth & 1) << 7) ; frame size = 128 bytes, 2-frame ring
    AND     W12, W11, #1
    UXTW    X12, W12
    LSL     X12, X12, #7
    ADD     X9,  X9,  #16
    ADD     X9,  X9,  X12                      // X9 = frame ptr

    // Save resume PC into frame
_XTRAMP_RESUME_ADRP:
    ADRP    X15, _dummy_patch_hook@PAGE        // patched to resume address
_XTRAMP_RESUME_ADD:
    ADD     X15, X15, _dummy_patch_hook@PAGEOFF
    STR     X15, [X9, #8]

    // Save original LR register (incoming return address) into our frame
    MOV     X16, X30
    STR     X16, [X9,  #0]                     // frame->lr_orig
_XTRAMP_EXITLR_ADRP:
    ADRP    X16, _XTRAMP_EXIT_STUB@PAGE
_XTRAMP_EXITLR_ADD:
    ADD     X16, X16, _XTRAMP_EXIT_STUB@PAGEOFF
    // Redirect return to our exit stub by overwriting the caller-saved LR slot.
    // The target prologue has already established X29 as frame pointer via
    //   STP X29, X30, [SP, #imm]; ADD X29, SP, #imm
    // Epilogue typically does: MOV SP, X29; LDP X29, X30, [SP], #16; RETAB
    // So we sign the exit stub pointer with key B using X29 as the context,
    // matching the MOV SP, X29 before RETAB.
    PACIB   X16, X29
    STR     X16, [X29, #0x8]

    // Snapshot argument registers into frame (x0..x7)
    STR     X0,  [X9, #16]
    STR     X1,  [X9, #24]
    STR     X2,  [X9, #32]
    STR     X3,  [X9, #40]
    STR     X4,  [X9, #48]
    STR     X5,  [X9, #56]
    STR     X6,  [X9, #64]
    STR     X7,  [X9, #72]
    // Increment depth and write back
    // Keep old depth in W13 intact for gating below; use X14 as header ptr
    ADD     W11, W11, #1
    SUB     X14, X9,  #16                      // slot header address
    STR     W11, [X14]

_XTRAMP_HOOK_ADRP:
    ADRP    X16, _dummy_patch_hook@PAGE        // patched to entry hook
_XTRAMP_HOOK_ADD:
    ADD     X16, X16, _dummy_patch_hook@PAGEOFF
    // Call entry hook only for outermost depth
    // old depth in W13: if zero, call; else skip
    CBNZ    W13, 1f
    BLR     X16
1:

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
    LSL     X10, X10, #XNIFF_CTX_SLOT_SHIFT
    ADD     X9,  X9,  X10                      // thread-slot base
    LDR     W11, [X9, #0]                      // current depth
    MOV     W13, W11                           // save old depth (matches entry)
    // frame = base + 16 + ((old_depth & 1) << 7) ; use same ring as entry
    AND     W12, W13, #1
    UXTW    X12, W12
    LSL     X12, X12, #7
    ADD     X12, X12, #16
    ADD     X9,  X9,  X12                      // X9 = frame ptr
    // Save return value into frame at offset 80
    STR     X0,  [X9, #80]
    // Now decrement depth (after selecting frame based on old depth)
    SUB     W11, W11, #1
    // Write back new depth to slot header
    SUB     X12, X9, #16
    STR     W11, [X12]
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
    LDR     X16, [X9, #0]
    MOV     X30, X16
    RET

_XTRAMP_END:

// Simple no-op hook that immediately returns
_XTRAMP_NOOP:
    BTI     jc
    RET
