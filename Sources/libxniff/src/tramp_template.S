.text
.globl _TRAMPOLINE_START_AFTER_PROLOGUE
.globl _TRAMPOLINE_INTERMEDIATE_ADRP
.globl _TRAMPOLINE_INTERMEDIATE_ADD
.globl _TRAMPOLINE_RELOAD_ADRP
.globl _TRAMPOLINE_RELOAD_ADD
.globl _TRAMPOLINE_AFTER_RESTORE
.globl _TRAMPOLINE_RETURN_ADRP
.globl _TRAMPOLINE_RETURN_ADD
_TRAMPOLINE_START_AFTER_PROLOGUE:
    // Valid BTI landing for BR from patched entry on BTI-enabled systems.
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

    // Save FP/SIMD state and NZCV so hooks can't perturb caller-visible state.
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

_TRAMPOLINE_INTERMEDIATE_ADRP:
    ADRP X16, _dummy_patch_hook@PAGE
_TRAMPOLINE_INTERMEDIATE_ADD:
    ADD  X16, X16, _dummy_patch_hook@PAGEOFF
    BLR  X16

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

_TRAMPOLINE_AFTER_RESTORE:
_TRAMPOLINE_RELOAD_ADRP:
    // Patched at runtime to re-materialize a relocated ADRP for a needed register (e.g., X0)
    ADRP    X16, _dummy_patch_hook@PAGE
_TRAMPOLINE_RELOAD_ADD:
    // Follow-up ADD for the same register as above
    ADD     X16, X16, _dummy_patch_hook@PAGEOFF

_TRAMPOLINE_RETURN_ADRP:
    ADRP    X16, _dummy_trampoline_return@page
_TRAMPOLINE_RETURN_ADD:
    ADD     X16, X16, _dummy_trampoline_return@pageoff
    BR      X16
