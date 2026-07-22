#include "record_renderer.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../shared/xniff_ipc.h"
#include "../shared/xniff_ipc_v2.h"
#include "mach_record_renderer.h"
#include "record_render_support.h"
#include "xpc_record_renderer.h"

static uint16_t event_kind(const xniff_ipc_v2_fixed_hdr_t *fixed) {
    if (fixed->api == XNIFF_API_XPC_HL) {
        return fixed->direction == XNIFF_DIR_EXIT
            ? XNIFF_EVT_XPC_EXIT
            : XNIFF_EVT_XPC_ENTRY;
    }
    if (fixed->api == XNIFF_API_MACH_MSG) {
        return fixed->direction == XNIFF_DIR_EXIT
            ? XNIFF_EVT_MACH_EXIT
            : XNIFF_EVT_MACH_ENTRY;
    }
    if (fixed->api == XNIFF_API_MACH_MSG2) {
        return fixed->direction == XNIFF_DIR_EXIT
            ? XNIFF_EVT_MACH2_EXIT
            : XNIFF_EVT_MACH2_ENTRY;
    }
    return fixed->api == XNIFF_API_DEBUG ? XNIFF_EVT_DEBUG_LOG : 0;
}

static void append_hook_debug_log(uint32_t pid,
                                  uint32_t thread_id,
                                  const char *timestamp,
                                  double monotonic_seconds,
                                  const char *line) {
    if (!line || !*line) return;
    char path[128];
    snprintf(path, sizeof(path), "/tmp/xniff-hooks-%d.log", (int)pid);
    FILE *output = fopen(path, "a");
    if (!output) return;
    fprintf(output, "[%s][+%0.6fs][tid=0x%x] %s\n",
            timestamp, monotonic_seconds, thread_id, line);
    fclose(output);
}

static int render_hook_debug(const uint8_t *body,
                             size_t body_length,
                             const xniff_ipc_v2_fixed_hdr_t *fixed) {
    size_t section_offset = sizeof(*fixed);
    while (section_offset + sizeof(xniff_ipc_v2_section_hdr_t) <= body_length) {
        xniff_ipc_v2_section_hdr_t section = {0};
        memcpy(&section, body + section_offset, sizeof(section));
        section_offset += sizeof(section);
        if (section_offset + section.sec_len > body_length) break;
        const uint8_t *value = body + section_offset;
        if (section.sec_type == XNIFF_V2_SEC_HOOK_DIAG &&
            section.sec_len >= sizeof(xniff_ipc_v2_diag_t)) {
            xniff_ipc_v2_diag_t diagnostic = {0};
            memcpy(&diagnostic, value, sizeof(diagnostic));
            size_t available = section.sec_len - sizeof(diagnostic);
            size_t message_length = diagnostic.msg_len;
            if (message_length > available) message_length = available;
            char *line = malloc(message_length + 1);
            if (!line) return -1;
            memcpy(line, value + sizeof(diagnostic), message_length);
            line[message_length] = '\0';

            char timestamp[64];
            double monotonic_seconds = 0;
            xniff_format_timestamp(timestamp, sizeof(timestamp),
                                   &monotonic_seconds);
            append_hook_debug_log(fixed->pid, fixed->tid_low, timestamp,
                                  monotonic_seconds, line);
            if (*line) {
                printf("[hook-debug][pid=%u][tid=0x%x] %s\n",
                       fixed->pid, fixed->tid_low, line);
            }
            free(line);
        }
        section_offset += section.sec_len;
    }
    return 0;
}

int xniff_render_record(const uint8_t *record,
                        size_t record_length,
                        uint64_t event_index,
                        bool include_hook_debug) {
    size_t header_length = sizeof(xniff_ipc_v2_entry_hdr_t);
    if (!record || record_length < header_length +
                                    sizeof(xniff_ipc_v2_fixed_hdr_t)) {
        return -1;
    }

    const uint8_t *body = record + header_length;
    size_t body_length = record_length - header_length;
    xniff_ipc_v2_fixed_hdr_t fixed = {0};
    memcpy(&fixed, body, sizeof(fixed));
    uint16_t kind = event_kind(&fixed);

    if (include_hook_debug && kind == XNIFF_EVT_DEBUG_LOG) {
        return render_hook_debug(body, body_length, &fixed);
    }
    if (fixed.api == XNIFF_API_XPC_HL) {
        return xniff_render_xpc_record(body, body_length, &fixed, kind,
                                       event_index);
    }
    if (fixed.api == XNIFF_API_MACH_MSG || fixed.api == XNIFF_API_MACH_MSG2) {
        return xniff_render_mach_record(body, body_length, &fixed, kind);
    }
    return 0;
}
