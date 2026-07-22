#include "xpc_session_coalescer.h"

#include <stddef.h>

static _Thread_local uint64_t g_session_call_id = 0;
static _Thread_local uint64_t g_session_message = 0;

void xniff_xpc_session_scope_enter(xniff_xpc_session_scope_t *scope,
                                   uint64_t call_id,
                                   uint64_t message) {
    if (scope == NULL || call_id == 0 || message == 0) return;

    scope->previous_call_id = g_session_call_id;
    scope->previous_message = g_session_message;
    scope->entered = true;
    g_session_call_id = call_id;
    g_session_message = message;
}

void xniff_xpc_session_scope_leave(xniff_xpc_session_scope_t *scope) {
    if (scope == NULL || !scope->entered) return;

    g_session_call_id = scope->previous_call_id;
    g_session_message = scope->previous_message;
    scope->entered = false;
}

bool xniff_xpc_session_scope_match(uint64_t message, uint64_t *call_id_out) {
    if (message == 0 || call_id_out == NULL || message != g_session_message ||
        g_session_call_id == 0) {
        return false;
    }

    *call_id_out = g_session_call_id;
    return true;
}
