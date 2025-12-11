// Combined command to start listener, inject hooks, and patch XPC automatically.
#pragma once

#include <sys/types.h>

int cmd_sniff_xpc(pid_t pid, const char *dylib_path);

