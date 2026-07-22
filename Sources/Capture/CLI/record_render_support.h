#ifndef XNIFF_RECORD_RENDER_SUPPORT_H
#define XNIFF_RECORD_RENDER_SUPPORT_H

#include <stddef.h>
#include <sys/types.h>

void xniff_format_timestamp(char *buffer,
                            size_t buffer_size,
                            double *monotonic_seconds_out);
const char *xniff_process_name(pid_t pid);

#endif
