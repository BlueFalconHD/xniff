#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

// Exported, noinline function we can patch remotely.
__attribute__((used, noinline, visibility("default")))
void do_something_useful(int count) {
    // Force a few instructions before the ADRP/ADD used for the printf string,
    // so the entry patch can safely resume after 12 bytes without skipping it.
#if defined(__aarch64__) || defined(__arm64__)
    // __asm__ volatile("nop\n\t"
    //                  "nop\n\t"
    //                  "nop\n\t"
    //                  "nop\n\t");
#endif
    printf("do_something_useful: doing some work with the secret counter\n\n");
}

// Exported remote hook that the CLI will call via a trampoline.
__attribute__((used, noinline, visibility("default")))
void xniff_remote_hook(int count) {
    printf(">>> xniff_remote_hook: intercepted call! <<<\n");
    printf(">>> secret counter value: %d <<<\n", count);
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
