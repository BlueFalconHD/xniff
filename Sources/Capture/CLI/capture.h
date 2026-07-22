#ifndef XNIFF_CAPTURE_H
#define XNIFF_CAPTURE_H

#include <sys/types.h>

#include "cli_options.h"
#include "shared_transport.h"

int xniff_capture_ring(pid_t pid,
                       int ready_fd,
                       xniff_shared_transport_t *transport,
                       const listener_opts_t *options);

#endif
