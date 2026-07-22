#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "cli_output.h"

static void clear_color_environment(void) {
    unsetenv("XNIFF_COLOR");
    unsetenv("NO_COLOR");
    unsetenv("CLICOLOR");
    unsetenv("CLICOLOR_FORCE");
    unsetenv("FORCE_COLOR");
    unsetenv("TERM");
}

static bool expect_color(FILE *stream, bool expected) {
    return xniff_output_color_enabled(stream) == expected;
}

int selftest_cli_color(void) {
    FILE *stream = tmpfile();
    if (!stream) {
        perror("tmpfile");
        return 1;
    }

    clear_color_environment();
    bool passed = expect_color(stream, false);

    setenv("XNIFF_COLOR", "always", 1);
    passed = passed && expect_color(stream, true);
    setenv("NO_COLOR", "1", 1);
    passed = passed && expect_color(stream, true);
    setenv("XNIFF_COLOR", "0", 1);
    passed = passed && expect_color(stream, false);

    clear_color_environment();
    setenv("XNIFF_COLOR", "auto", 1);
    setenv("TERM", "dumb", 1);
    passed = passed && expect_color(stream, false);

    clear_color_environment();
    setenv("CLICOLOR_FORCE", "1", 1);
    passed = passed && expect_color(stream, true);
    setenv("NO_COLOR", "1", 1);
    passed = passed && expect_color(stream, false);

    clear_color_environment();
    setenv("FORCE_COLOR", "1", 1);
    passed = passed && expect_color(stream, true);
    setenv("FORCE_COLOR", "0", 1);
    passed = passed && expect_color(stream, false);

    clear_color_environment();
    setenv("CLICOLOR", "0", 1);
    passed = passed && expect_color(stream, false);

    fclose(stream);
    clear_color_environment();
    if (!passed) {
        fprintf(stderr, "FAIL: CLI color environment handling mismatch\n");
        return 1;
    }
    printf("OK: CLI color environment handling validated\n");
    return 0;
}
