#ifndef XNIFF_XPC_RECORD_RENDERER_H
#define XNIFF_XPC_RECORD_RENDERER_H

#include <stddef.h>
#include <stdint.h>

#include "../shared/xniff_ipc_v2.h"

int xniff_render_xpc_record(const uint8_t *body,
                            size_t body_length,
                            const xniff_ipc_v2_fixed_hdr_t *fixed,
                            uint16_t kind,
                            uint64_t event_index);

#endif
