#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint64_t previous_call_id;
    uint64_t previous_message;
    bool entered;
} xniff_xpc_session_scope_t;

void xniff_xpc_session_scope_enter(xniff_xpc_session_scope_t *scope,
                                   uint64_t call_id,
                                   uint64_t message);
void xniff_xpc_session_scope_leave(xniff_xpc_session_scope_t *scope);
bool xniff_xpc_session_scope_match(uint64_t message, uint64_t *call_id_out);
