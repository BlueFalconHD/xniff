#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

typedef struct xniff_ctx_frame {
    // Saved at entry
    uint64_t lr_orig;      // +0x00: original LR (return target)
    uint64_t resume_pc;    // +0x08: resume PC (after entry patch window)

    // Register arguments snapshot at entry
    uint64_t x[8];         // +0x10..+0x48: x0..x7 (8 × 8 bytes)

    // Saved at exit
    uint64_t ret;          // +0x50: function return value (from x0 at exit)

    // Pad to fixed 128-byte frame size (one frame per 0x80)
    uint8_t  reserved[0x80 - 0x58]; // 0x28 bytes
} xniff_ctx_frame_t;

// Exported, noinline function we can patch remotely.
__attribute__((used, noinline, visibility("default")))
int do_something_useful(int count) {
    // Force a few instructions before the ADRP/ADD used for the printf string,
    // so the entry patch can safely resume after 12 bytes without skipping it.
#if defined(__aarch64__) || defined(__arm64__)
    // __asm__ volatile("nop\n\t"
    //                  "nop\n\t"
    //                  "nop\n\t"
    //                  "nop\n\t");
#endif
    printf("do_something_useful: doing some work with the secret counter\n\n");
    return count * 2;
}

// Exported remote hook that the CLI will call via a trampoline.
__attribute__((used, noinline, visibility("default")))
void xniff_remote_entry_hook(int count) {
    printf("::: passed secret counter value: %d\n", count);
}

__attribute__((used, noinline, visibility("default")))
void xniff_remote_exit_hook(uint64_t ret, xniff_ctx_frame_t* ctx) {
    printf("::: function returned %llu", (unsigned long long)ret);
}

int main(void) {
    printf("xniff-test: waiting for patch...\n");
    fflush(stdout);
    sleep(2);

    int counter = 0;

    while (1) {
        counter++;
        do_something_useful(counter);
        fflush(stdout);
        sleep(1);
    }
    return 0;
}
