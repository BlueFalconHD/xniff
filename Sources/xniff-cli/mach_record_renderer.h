#ifndef XNIFF_MACH_RECORD_RENDERER_H
#define XNIFF_MACH_RECORD_RENDERER_H

#include <stddef.h>
#include <stdint.h>

#include "../shared/xniff_record.h"

int xniff_render_mach_record(const uint8_t *body,
                             size_t body_length,
                             const xniff_record_fixed_header_t *fixed);

#endif
