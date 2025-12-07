#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "../shared/xniff.h"
#include "patch.h"

__attribute__((noinline)) int demo_target(int n) {
    printf("demo_target running: n=%d\n", n);
    return (n * 2) + 1;
}

__attribute__((used, noinline)) void demo_hook(void) {
    printf(">>> demo_hook called!\n");
}

int main(void) {
    const char *version = xniff_version();
    assert(version != NULL);
    printf("libxniff version: %s\n", version);

    printf("before patch: demo_target(3) => %d\n", demo_target(3));

    trampoline_bank_t bank;
    int rc = trampoline_bank_init(&bank, 16, 0);
    if (rc != 0) {
        fprintf(stderr, "failed to init trampoline bank\n");
        return 1;
    }

    size_t idx = 0;
    rc = trampoline_bank_install(&bank, (void *)demo_target, (void *)demo_hook, &idx);
    if (rc != 0) {
        fprintf(stderr, "failed to install trampoline\n");
        trampoline_bank_deinit(&bank);
        return 1;
    }
    printf("installed trampoline at slot %zu\n", idx);

    printf("after patch: demo_target(3) => %d\n", demo_target(3));

    trampoline_bank_deinit(&bank);
    return 0;
}
