.text
.align 2
.globl _XNIFF_SHCODE_START
.globl _XNIFF_SHCODE_END
.globl _XNIFF_PL_PTHREAD_CREATE_FROM_MACH_THREAD
.globl _XNIFF_PL_DLOPEN
.globl _XNIFF_PL_PTHREAD_EXIT
.globl _XNIFF_PL_DYLIB

// Self-contained ARM64 stub that:
// 1) Creates a real pthread via pthread_create_from_mach_thread (or pthread_create if patched as such)
// 2) The new pthread runs a start routine that calls dlopen(path, flags) and then pthread_exit(0)
// 3) The original Mach thread spins forever
//
// Pointers and path are stored as in-blob placeholders that the injector patches at runtime.

_XNIFF_SHCODE_START:
    // Prologue
    sub     sp, sp, #0x20
    stp     x29, x30, [sp, #0x10]
    add     x29, sp, #0x10

    // int pthread_create_from_mach_thread(pthread_t* x0, const pthread_attr_t* x1, void*(*)(void*), void* arg)
    mov     x0, sp              // pthread_t* storage (stack scratch)
    mov     x1, xzr             // attr = NULL
    adr     x2, _XNIFF_START_ROUTINE
    mov     x3, xzr             // arg = NULL
    ldr     x4, _XNIFF_PL_PTHREAD_CREATE_FROM_MACH_THREAD
    blr     x4

    // Keep the bootstrap Mach thread parked to avoid returning
    // Use a minimal idle loop as described in the reference article
    wfe
    b       .

// Start routine for the created pthread
_XNIFF_START_ROUTINE:
    // void* h = dlopen(path, flags)
    adr     x0, _XNIFF_PL_DYLIB // path string inside this blob
    mov     w1, #1              // RTLD_LAZY (1) per reference article
    ldr     x7, _XNIFF_PL_DLOPEN
    blr     x7

    // pthread_exit(0)
    ldr     x8, _XNIFF_PL_PTHREAD_EXIT
    mov     x0, xzr
    blr     x8
    ret

.align 3
// Placeholders (patched at runtime by the injector)
_XNIFF_PL_PTHREAD_CREATE_FROM_MACH_THREAD:
    .ascii  "PTHRDCRT"        // 8-byte placeholder
.align 3
_XNIFF_PL_DLOPEN:
    .ascii  "DLOPEN__"        // 8-byte placeholder
.align 3
_XNIFF_PL_PTHREAD_EXIT:
    .ascii  "PTHREXIT"        // 8-byte placeholder
.align 3
_XNIFF_PL_DYLIB:
    .asciz  "LIBLIBLIB"       // path placeholder (NUL-terminated)
    .space  503, 0             // total ~512 bytes available for path

_XNIFF_SHCODE_END:
