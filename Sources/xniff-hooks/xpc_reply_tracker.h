#pragma once

#include <stdbool.h>
#include <stdint.h>

bool xniff_xpc_reply_tracker_record(uint64_t context, uint64_t call_id);
bool xniff_xpc_reply_tracker_take(uint64_t context, uint64_t *call_id_out);
void xniff_xpc_reply_tracker_clear(void);
