.text
.align 2
.globl _XNIFF_REMOTE_CODE_START
.globl _XNIFF_REMOTE_LOADER_START
.globl _XNIFF_REMOTE_CODE_END
.globl _XNIFF_SPIN_LOOP

// Contiguous blob start (copy this whole range to target)
_XNIFF_REMOTE_CODE_START:

// Start routine for a thread: void* (*)(void*)
// X0 = arg pointer to struct {
//   +0  : char* path
//   +8  : int   flags
//   +16 : void* dlopen
//   +24 : void* pthread_exit
//   +32 : void* _pthread_set_self (optional; NULL if unavailable)
// }
_XNIFF_REMOTE_LOADER_START:
    // Save arg
    MOV     X9, X0
    // If pthread_set_self is available, call it with NULL to bootstrap TSD
    LDR     X17, [X9, #32]
    CBZ     X17, 1f
    MOV     X0, XZR
    BLR     X17
1:
    // Load path and flags, and dlopen address
    LDR     X1, [X9, #0]
    LDR     W2, [X9, #8]
    LDR     X16, [X9, #16]
    // Call dlopen(path, flags)
    MOV     X0, X1
    MOV     W1, W2
    BLR     X16
    // Call pthread_exit(0)
    LDR     X16, [X9, #24]
    MOV     X0, XZR
    BLR     X16
    MOV     X0, XZR
    RET

// Simple spin loop target for LR so the bootstrap Mach thread doesn’t crash
_XNIFF_SPIN_LOOP:
1:
    WFE
    B 1b

// End of contiguous blob
_XNIFF_REMOTE_CODE_END:
