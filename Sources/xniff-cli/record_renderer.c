#include "record_renderer.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../shared/xniff_payload.h"
#include "../shared/xniff_record.h"
#include "mach_record_renderer.h"
#include "record_render_support.h"
#include "xpc_record_renderer.h"

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
                             const xniff_record_fixed_header_t *fixed) {
    xniff_record_section_iterator_t iterator;
    xniff_record_section_iterator_init(&iterator, body + sizeof(*fixed),
                                       body_length - sizeof(*fixed));
    xniff_record_section_t section;
    int section_result;
    while ((section_result = xniff_record_section_next(&iterator, &section)) > 0) {
        const uint8_t *value = section.data;
        if (section.type == XNIFF_SECTION_HOOK_DIAG &&
            section.length >= sizeof(xniff_diagnostic_section_t)) {
            xniff_diagnostic_section_t diagnostic = {0};
            memcpy(&diagnostic, value, sizeof(diagnostic));
            size_t available = section.length - sizeof(diagnostic);
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
    }
    return section_result;
}

int xniff_render_record(const uint8_t *record,
                        size_t record_length,
                        bool include_hook_debug) {
    size_t header_length = sizeof(xniff_record_header_t);
    if (!record || record_length < header_length +
                                    sizeof(xniff_record_fixed_header_t)) {
        return -1;
    }

    xniff_record_header_t header = {0};
    memcpy(&header, record, sizeof(header));
    if (header.version != XNIFF_RECORD_VERSION ||
        header.length != record_length) {
        return -1;
    }

    const uint8_t *body = record + header_length;
    size_t body_length = record_length - header_length;
    xniff_record_fixed_header_t fixed = {0};
    memcpy(&fixed, body, sizeof(fixed));
    if (!xniff_record_type_matches_api(header.type, fixed.api)) return -1;

    if (include_hook_debug && fixed.api == XNIFF_API_DEBUG) {
        return render_hook_debug(body, body_length, &fixed);
    }
    if (fixed.api == XNIFF_API_XPC) {
        return xniff_render_xpc_record(body, body_length, &fixed);
    }
    if (fixed.api == XNIFF_API_MACH_MSG || fixed.api == XNIFF_API_MACH_MSG2) {
        return xniff_render_mach_record(body, body_length, &fixed);
    }
    return 0;
}
