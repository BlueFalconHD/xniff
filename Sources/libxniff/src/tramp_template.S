.text
.globl _TRAMPOLINE_START_AFTER_PROLOGUE
.globl _TRAMPOLINE_INTERMEDIATE_ADRP
.globl _TRAMPOLINE_INTERMEDIATE_ADD
.globl _TRAMPOLINE_RELOAD_ADRP
.globl _TRAMPOLINE_RELOAD_ADD
.globl _TRAMPOLINE_RETURN_ADRP
.globl _TRAMPOLINE_RETURN_ADD
_TRAMPOLINE_START_AFTER_PROLOGUE:
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

_TRAMPOLINE_INTERMEDIATE_ADRP:
    ADRP X16, _dummy_patch_hook@PAGE
_TRAMPOLINE_INTERMEDIATE_ADD:
    ADD  X16, X16, _dummy_patch_hook@PAGEOFF
    BLR  X16

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
