#ifndef XNIFF_RECORD_RENDERER_H
#define XNIFF_RECORD_RENDERER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int xniff_render_record(const uint8_t *record,
                        size_t record_length,
                        bool include_hook_debug);

#endif
