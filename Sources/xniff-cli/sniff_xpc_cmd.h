// Combined command to start listener and inject hooks automatically.
#pragma once

#include <sys/types.h>

// mode: 1=mach, 2=xpc
int cmd_sniff_xpc(pid_t pid, const char *dylib_path, int mode);
