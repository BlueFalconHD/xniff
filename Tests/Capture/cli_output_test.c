#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

typedef void (*output_action_t)(void);

static bool capture_output(output_action_t action, char *buffer,
                           size_t buffer_size) {
    FILE *capture = tmpfile();
    if (!capture) return false;
    int saved_stderr = dup(STDERR_FILENO);
    if (saved_stderr < 0 || dup2(fileno(capture), STDERR_FILENO) < 0) {
        if (saved_stderr >= 0) close(saved_stderr);
        fclose(capture);
        return false;
    }

    action();
    fflush(stderr);
    bool restored = dup2(saved_stderr, STDERR_FILENO) >= 0;
    close(saved_stderr);

    rewind(capture);
    size_t length = fread(buffer, 1, buffer_size - 1, capture);
    buffer[length] = '\0';
    fclose(capture);
    return restored;
}

static void write_banner(void) {
    xniff_output_banner();
}

static void write_status(void) {
    xniff_output_status("transport", "pid 1");
}

static void write_detail(void) {
    xniff_output_detail("transport", "pid 1");
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

    char output[256];
    clear_color_environment();
    setenv("XNIFF_COLOR", "never", 1);
    passed = passed && capture_output(write_banner, output, sizeof(output)) &&
             strncmp(output, "Xniff v", 7) == 0 && strstr(output, "👃") == NULL &&
             strchr(output, '\033') == NULL;
    passed = passed && capture_output(write_status, output, sizeof(output)) &&
             strcmp(output, "transport   pid 1\n") == 0;

    clear_color_environment();
    setenv("XNIFF_COLOR", "always", 1);
    passed = passed && capture_output(write_banner, output, sizeof(output)) &&
             strstr(output, "Xn👃ff") != NULL && strstr(output, " v") != NULL;
    setenv("XNIFF_VERBOSE", "1", 1);
    passed = passed && capture_output(write_detail, output, sizeof(output)) &&
             strstr(output, "\033[1;35mtransport") != NULL;

    fclose(stream);
    clear_color_environment();
    unsetenv("XNIFF_VERBOSE");
    if (!passed) {
        fprintf(stderr, "FAIL: CLI color environment handling mismatch\n");
        return 1;
    }
    printf("OK: CLI color environment handling validated\n");
    return 0;
}
