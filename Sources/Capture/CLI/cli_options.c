#include "cli_options.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli_output.h"
#include "xniff_transport.h"

static int find_double_dash(int argc, char **argv, int start) {
    for (int i = start; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) return i;
    }
    return -1;
}

static int parse_pid(const char *value, pid_t *pid_out) {
    char *end = NULL;
    errno = 0;
    long parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed <= 0) return -1;
    *pid_out = (pid_t)parsed;
    return 0;
}

static int parse_flags(int argc, char **argv, int start, int end,
                       xniff_cli_options_t *options) {
    bool saw_mode = false;
    if (end < 0 || end > argc) end = argc;
    for (int i = start; i < end; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "--mach") == 0 || strcmp(arg, "--xpc") == 0) {
            int mode = strcmp(arg, "--xpc") == 0 ? XNIFF_CAPTURE_MODE_XPC : XNIFF_CAPTURE_MODE_MACH;
            if (saw_mode && options->capture_mode != mode) {
                xniff_output_error("choose only one of --mach or --xpc");
                return -1;
            }
            saw_mode = true;
            options->capture_mode = mode;
        } else if (strcmp(arg, "--hooks") == 0) {
            if (++i >= end) {
                xniff_output_error("--hooks requires a dylib path");
                return -1;
            }
            options->hooks_path = argv[i];
        } else if (strcmp(arg, "--out") == 0) {
            if (++i >= end) {
                xniff_output_error("--out requires a path");
                return -1;
            }
            if (strcmp(argv[i], "-") == 0) {
                xniff_output_error("--out - would mix the dump with target output");
                return -1;
            }
            options->listener.out_bin = true;
            snprintf(options->listener.out_bin_path,
                     sizeof(options->listener.out_bin_path), "%s", argv[i]);
        } else if (strcmp(arg, "--target-user") == 0) {
            if (++i >= end) {
                xniff_output_error("--target-user requires sudo, a user name, or a numeric uid");
                return -1;
            }
            options->target_user = argv[i];
        } else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            return 1;
        } else {
            xniff_output_error("unknown option: %s", arg);
            return -1;
        }
    }
    return 0;
}

void xniff_cli_usage(const char *program) {
    xniff_output_section(stderr, "Usage");
    fprintf(stderr, "  %s attach <pid> [options]\n", program);
    fprintf(stderr, "  %s launch [options] -- <program> [args...]\n", program);
    fputc('\n', stderr);
    xniff_output_section(stderr, "Capture options");
    fprintf(stderr, "  --mach             Capture Mach messages (default)\n");
    fprintf(stderr, "  --xpc              Capture high-level XPC calls\n");
    fprintf(stderr, "  --hooks <path>     Override the hooks embedded in xniff\n");
    fprintf(stderr, "  --out <path>       Write an xniff dump\n");
    fprintf(stderr, "  --target-user <u>  Launch target as sudo's caller, a user name, or a uid\n");
    fputc('\n', stderr);
    xniff_output_section(stderr, "Environment");
    fprintf(stderr, "  XNIFF_COLOR <when>  Color output: auto, always, or never\n");
    fprintf(stderr, "  NO_COLOR            Disable color output\n");
    fprintf(stderr, "  XNIFF_VERBOSE=1     Show internal capture details\n");
}

int xniff_cli_parse(int argc, char **argv, xniff_cli_options_t *options) {
    if (!options || argc < 2) return -1;
    memset(options, 0, sizeof(*options));
    options->capture_mode = XNIFF_CAPTURE_MODE_MACH;

    const char *command = argv[1];
    int flags_start = 0;
    int flags_end = argc;
    if (strcmp(command, "attach") == 0) {
        if (argc < 3 || parse_pid(argv[2], &options->pid) != 0) return -1;
        options->command = XNIFF_CLI_ATTACH;
        flags_start = 3;
    } else if (strcmp(command, "launch") == 0) {
        int separator = find_double_dash(argc, argv, 2);
        if (separator < 0 || separator + 1 >= argc) {
            xniff_output_error("launch requires -- <program> [args...]");
            return -1;
        }
        options->command = XNIFF_CLI_LAUNCH;
        options->launch_argv = &argv[separator + 1];
        flags_start = 2;
        flags_end = separator;
    } else if (strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        return 1;
    } else {
        xniff_output_error("unknown command: %s", command);
        return -1;
    }

    int result = parse_flags(argc, argv, flags_start, flags_end, options);
    if (result == 0 && options->command != XNIFF_CLI_LAUNCH && options->target_user) {
        xniff_output_error("--target-user is only valid with launch");
        return -1;
    }
    return result;
}
