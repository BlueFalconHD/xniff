.text
.align 2
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

    // Compute per-thread context frame address in X9
_XTRAMP_CTX_ADRP:
    ADRP    X9, _dummy_patch_hook@PAGE         // patched to context base for this trampoline slot
_XTRAMP_CTX_ADD:
    ADD     X9, X9, _dummy_patch_hook@PAGEOFF
    MRS     X10, TPIDRRO_EL0                   // thread id
    UBFX    X10, X10, #0, #6                   // idx = low 6 bits (0..63)
    LSL     X10, X10, #8                       // thread-slot size = 256 bytes
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

    // Save original LR from function frame and redirect LR to our exit stub
    LDR     X16, [X29, #0x8]
    STR     X16, [X9,  #0]                     // frame->lr_orig
_XTRAMP_EXITLR_ADRP:
    ADRP    X16, _XTRAMP_EXIT_STUB@PAGE
_XTRAMP_EXITLR_ADD:
    ADD     X16, X16, _XTRAMP_EXIT_STUB@PAGEOFF
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

    // Restore all GPRs and unwind stack
    LDR     X30,      [SP, #0xF0]
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
_XTRAMP_EXIT_CTX_ADRP:
    ADRP    X9, _dummy_patch_hook@PAGE         // patched to same context base as above
_XTRAMP_EXIT_CTX_ADD:
    ADD     X9, X9, _dummy_patch_hook@PAGEOFF
    MRS     X10, TPIDRRO_EL0
    UBFX    X10, X10, #0, #6
    LSL     X10, X10, #8
    ADD     X9,  X9,  X10                      // thread-slot base
    LDR     W11, [X9, #0]
    SUB     W11, W11, #1
    STR     W11, [X9, #0]
    // frame = base + 16 + ((depth & 1) << 7) ; match entry ring selection
    AND     W12, W11, #1
    UXTW    X12, W12
    LSL     X12, X12, #7
    ADD     X12, X12, #16
    ADD     X9,  X9,  X12                      // X9 = frame ptr
    // Save return value into frame at offset 80
    STR     X0,  [X9, #80]
    // Call exit hook: x0 is ret, x1 = ctx
_XTRAMP_EXIT_HOOK_ADRP:
    ADRP    X16, _dummy_patch_hook@PAGE
_XTRAMP_EXIT_HOOK_ADD:
    ADD     X16, X16, _dummy_patch_hook@PAGEOFF
    // Preserve ctx pointer across the call without clobbering callee-saved regs
    // Save X9 (ctx) on stack to keep ABI promises for X19..X28
    STP     X9, X10, [SP, #-16]!
    MOV     X1,  X9
    // Call exit hook only when depth reached zero (outermost)
    CBNZ    W11, 2f
    BLR     X16
    // Ensure original return value is restored to x0 before returning to caller
    // (exit hook may have clobbered x0)
    // Restore saved ctx pointer and reload original return value
    LDP     X9, X10, [SP], #16
    LDR     X0, [X9, #80]
2:
    // Return to original caller using lr_orig saved in frame
    // If we skipped the call (depth!=0), restore stack slot we reserved
    // (paired with the STP above). When we did call, X9/X10 already popped.
    CBNZ    W11, 3f
    B       4f
3:
    // Depth != 0 path: we didn't branch to the hook, so pop the saved regs now
    LDP     X9, X10, [SP], #16
4:
    LDR     X16, [X9, #0]
    MOV     X30, X16
    RET

_XTRAMP_END:

// Simple no-op hook that immediately returns
_XTRAMP_NOOP:
    RET
