#ifndef XNIFF_PROCESS_CONTROL_H
#define XNIFF_PROCESS_CONTROL_H

#include <sys/types.h>
#include <stdbool.h>

#include "cli_options.h"

// Installs the Ctrl-C handler before the listener is forked. Both processes
// inherit it, allowing the listener to finish the record currently being
// written instead of being terminated in the middle of it.
int xniff_install_capture_signal_handler(void);
bool xniff_capture_stop_requested(void);

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
