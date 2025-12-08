#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

// Exported, noinline function we can patch remotely.
__attribute__((used, noinline, visibility("default")))
void do_something_useful(void) {
    // Force a few instructions before the ADRP/ADD used for the printf string,
    // so the entry patch can safely resume after 12 bytes without skipping it.
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("nop\n\t"
                     "nop\n\t"
                     "nop\n\t"
                     "nop\n\t");
#endif
    printf("do_something_useful: doing some work...\n");
}

// Exported remote hook that the CLI will call via a trampoline.
__attribute__((used, noinline, visibility("default")))
void xniff_remote_hook(void) {
    printf(">>> xniff_remote_hook: intercepted call! <<<\n");
}

int main(void) {
    printf("xniff-test: waiting for patch...\n");
    fflush(stdout);
    sleep(2);

    while (1) {
        do_something_useful();
        fflush(stdout);
        sleep(1);
    }
    return 0;
}
