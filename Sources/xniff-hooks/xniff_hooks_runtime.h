#pragma once

#include <stdbool.h>
#include <stdint.h>

bool xniff_hooks_streaming_is_enabled(void);
void xniff_hooks_set_streaming_enabled(bool enabled);

bool xniff_hooks_capture_mode_enabled(uint32_t mode);
bool xniff_hooks_debug_is_enabled(void);
bool xniff_hooks_backtrace_is_enabled(void);

void xniff_hooks_set_current_call_id(uint64_t call_id);
uint64_t xniff_hooks_current_call_id(void);
