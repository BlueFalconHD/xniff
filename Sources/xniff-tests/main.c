#include <assert.h>
#include <stdio.h>

#include "xniff.h"

int main(void) {
    const char *version = xniff_version();

    assert(version != NULL);
    if (version == NULL) {
        fprintf(stderr, "libxniff version unavailable\n");
        return 1;
    }

    printf("libxniff version: %s\n", version);
    return 0;
}
