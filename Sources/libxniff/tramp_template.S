.text
.globl _TRAMPOLINE_START_AFTER_PROLOGUE
.globl _TRAMPOLINE_INTERMEDIATE_ADRP
.globl _TRAMPOLINE_INTERMEDIATE_ADD
.globl _TRAMPOLINE_RELOAD_ADRP
.globl _TRAMPOLINE_RELOAD_ADD
.globl _TRAMPOLINE_RETURN_ADRP
.globl _TRAMPOLINE_RETURN_ADD
_TRAMPOLINE_START_AFTER_PROLOGUE:
    SUB     SP, SP, #0xA0
    STP     X19, X20, [SP, #0x00]
    STP     X21, X22, [SP, #0x10]
    STP     X23, X24, [SP, #0x20]
    STP     X25, X26, [SP, #0x30]
    STP     X27, X28, [SP, #0x40]
    STP     X29, X30, [SP, #0x50]

_TRAMPOLINE_INTERMEDIATE_ADRP:
    ADRP X16, _dummy_patch_hook@PAGE
_TRAMPOLINE_INTERMEDIATE_ADD:
    ADD  X16, X16, _dummy_patch_hook@PAGEOFF
    BLR  X16

    LDP     X19, X20, [SP, #0x00]
    LDP     X21, X22, [SP, #0x10]
    LDP     X23, X24, [SP, #0x20]
    LDP     X25, X26, [SP, #0x30]
    LDP     X27, X28, [SP, #0x40]
    LDP     X29, X30, [SP, #0x50]

    ADD     SP, SP, #0xA0

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
