#include "xniff_hooks_runtime.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "../shared/xniff_transport.h"

static uint32_t g_streaming_enabled = 0;
static _Thread_local uint64_t g_current_call_id = 0;

static bool xniff_env_enabled(const char *name, bool default_value) {
    const char *value = getenv(name);
    if (!value || !*value) return default_value;
    return strcmp(value, "0") != 0 && strcasecmp(value, "false") != 0 &&
           strcasecmp(value, "no") != 0;
}

bool xniff_hooks_streaming_is_enabled(void) {
    return __atomic_load_n(&g_streaming_enabled, __ATOMIC_ACQUIRE) != 0;
}

void xniff_hooks_set_streaming_enabled(bool enabled) {
    __atomic_store_n(&g_streaming_enabled, enabled ? 1u : 0u, __ATOMIC_RELEASE);
}

bool xniff_hooks_capture_mode_enabled(uint32_t mode) {
    if (!xniff_hooks_streaming_is_enabled()) return false;
    if (xniff_transport_is_internal()) return false;
    uint32_t configured = xniff_transport_capture_mode();
    return (configured & mode) != 0;
}

bool xniff_hooks_debug_is_enabled(void) {
    return xniff_env_enabled("XNIFF_HOOKS_DEBUG", false);
}

bool xniff_hooks_backtrace_is_enabled(void) {
    return xniff_env_enabled("XNIFF_BACKTRACE", false);
}

int xniff_hooks_write_record(xniff_record_builder_t *builder) {
    const uint8_t *record = NULL;
    size_t length = 0;
    if (xniff_record_finish(builder, &record, &length) != 0) return -1;
    return xniff_ring_write(record, length);
}

void xniff_hooks_set_current_call_id(uint64_t call_id) {
    g_current_call_id = call_id;
}

uint64_t xniff_hooks_current_call_id(void) {
    return g_current_call_id;
}
