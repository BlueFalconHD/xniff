#pragma once

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

typedef struct {
    bool dump_files;
    bool parse_xpc;
    bool xpc_only;
    bool out_bin;
    char out_bin_path[PATH_MAX];
    size_t hex_preview_len;
} listener_opts_t;

typedef enum {
    XNIFF_CLI_NONE = 0,
    XNIFF_CLI_ATTACH,
    XNIFF_CLI_LAUNCH,
} xniff_cli_command_t;

typedef struct {
    xniff_cli_command_t command;
    pid_t pid;
    const char *hooks_path;
    const char *target_user;
    char *const *launch_argv;
    int capture_mode;
    listener_opts_t listener;
} xniff_cli_options_t;

void xniff_cli_usage(const char *program);
int xniff_cli_parse(int argc, char **argv, xniff_cli_options_t *options);
