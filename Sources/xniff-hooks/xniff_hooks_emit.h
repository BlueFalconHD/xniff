#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "xniff_hooks_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

void xniff_emit_mach_msg_entry(const uint64_t args[8]);
void xniff_emit_mach_msg_exit(uint64_t ret, const uint64_t args[8], int has_separate_rcv_msg);

void xniff_emit_mach_msg2_entry(const uint64_t args[8]);
void xniff_emit_mach_msg2_exit(uint64_t ret, const uint64_t args[8]);

void xniff_emit_xpc_connection_create_entry(const uint64_t args[8]);
void xniff_emit_xpc_connection_create_exit(uint64_t ret, const uint64_t args[8]);

void xniff_emit_xpc_pipe_routine_entry(const uint64_t args[8]);
void xniff_emit_xpc_pipe_routine_exit(uint64_t ret, const uint64_t args[8]);

void xniff_emit_xpc_connection_send_message_entry(const uint64_t args[8]);
void xniff_emit_xpc_connection_send_message_with_reply_entry(const uint64_t args[8]);
void xniff_emit_xpc_connection_send_message_with_reply_async_response(uint64_t reply, const uint64_t args[8]);
void xniff_emit_xpc_connection_send_message_with_reply_sync_entry(const uint64_t args[8]);
void xniff_emit_xpc_connection_send_message_with_reply_sync_exit(uint64_t ret, const uint64_t args[8]);
void xniff_emit_xpc_connection_call_event_handler_entry(const uint64_t args[8]);
void xniff_emit_xpc_connection_check_in_entry(const uint64_t args[8]);
void xniff_emit_xpc_connection_check_in_exit(uint64_t ret, const uint64_t args[8]);
void xniff_emit_xpc_dictionary_send_reply_entry(const uint64_t args[8]);
void xniff_emit_xpc_session_send_message_entry(const uint64_t args[8]);
void xniff_emit_xpc_session_send_message_with_reply_async_entry(const uint64_t args[8]);
void xniff_emit_xpc_session_send_message_with_reply_async_response(uint64_t reply, uint64_t error,
                                                                   const uint64_t args[8]);
void xniff_emit_xpc_session_send_message_with_reply_sync_entry(const uint64_t args[8]);
void xniff_emit_xpc_session_send_message_with_reply_sync_exit(uint64_t ret, const uint64_t args[8]);

#ifdef __cplusplus
}
#endif
