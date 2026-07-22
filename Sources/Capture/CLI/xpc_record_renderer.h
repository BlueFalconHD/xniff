#ifndef XNIFF_XPC_RECORD_RENDERER_H
#define XNIFF_XPC_RECORD_RENDERER_H

#include <stddef.h>
#include <stdint.h>

#include "xniff_record.h"

int xniff_render_xpc_record(const uint8_t *body,
                            size_t body_length,
                            const xniff_record_fixed_header_t *fixed);

#endif
