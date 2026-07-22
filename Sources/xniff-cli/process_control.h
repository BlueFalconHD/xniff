#ifndef XNIFF_PROCESS_CONTROL_H
#define XNIFF_PROCESS_CONTROL_H

#include <sys/types.h>

#include "cli_options.h"

int xniff_attach(pid_t pid,
                 const char *dylib_path,
                 int mode,
                 const listener_opts_t *listener_options);

int xniff_launch(const char *dylib_path,
                 int mode,
                 const char *target_user,
                 char *const launch_argv[],
                 const listener_opts_t *listener_options);

#endif
