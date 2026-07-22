#include "mach_record_renderer.h"

#include <mach/mach.h>
#include <mach/message.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../shared/mach_private.h"
#include "../shared/xniff_payload.h"
#include "record_render_support.h"

static bool extract_sender_pid(const uint8_t *message,
                               size_t message_length,
                               uint32_t header_size,
                               uint32_t *pid_out) {
    if (!pid_out) return false;
    *pid_out = 0;
    if (!message || message_length < sizeof(mach_msg_header_t) ||
        header_size < sizeof(mach_msg_header_t)) {
        return false;
    }

    size_t trailer_offset = (size_t)round_msg(header_size);
    if (trailer_offset + sizeof(mach_msg_trailer_t) > message_length) return false;

    mach_msg_trailer_t trailer = {0};
    memcpy(&trailer, message + trailer_offset, sizeof(trailer));
    if (trailer.msgh_trailer_size < sizeof(mach_msg_audit_trailer_t) ||
        trailer_offset + trailer.msgh_trailer_size > message_length) {
        return false;
    }

    mach_msg_audit_trailer_t audit_trailer = {0};
    memcpy(&audit_trailer, message + trailer_offset, sizeof(audit_trailer));
    uint32_t pid = audit_trailer.msgh_audit.val[5];
    if (pid == 0 || pid == UINT32_MAX) return false;
    *pid_out = pid;
    return true;
}

static void print_mach_event(const xniff_mach_payload_t *payload,
                             const uint8_t *message,
                             size_t message_length) {
    const mach_msg_header_t *header = (const mach_msg_header_t *)message;
    const char *api_name = payload->api == XNIFF_API_MACH_MSG2
        ? "mach_msg2"
        : "mach_msg";
    const char *direction_name = payload->direction == XNIFF_DIRECTION_EXIT
        ? "exit"
        : "entry";

    char timestamp[64];
    double monotonic_seconds = 0;
    xniff_format_timestamp(timestamp, sizeof(timestamp), &monotonic_seconds);
    uint64_t option = ((uint64_t)payload->option_hi << 32) | payload->option_lo;
    bool is_send = payload->api == XNIFF_API_MACH_MSG
        ? (payload->option_lo & MACH_SEND_MSG) != 0
        : (option & MACH64_SEND_MSG) != 0;
    bool is_receive = payload->api == XNIFF_API_MACH_MSG
        ? (payload->option_lo & MACH_RCV_MSG) != 0
        : (option & MACH64_RCV_MSG) != 0;
    mach_port_t remote = header ? header->msgh_remote_port : MACH_PORT_NULL;
    mach_port_t local = header ? header->msgh_local_port : MACH_PORT_NULL;

    printf("[%s][+%0.6fs] %s %s\n", timestamp, monotonic_seconds,
           api_name, direction_name);
    printf("  mach.api: %u\n", payload->api);
    printf("  mach.direction: %u\n", payload->direction);
    printf("  mach.is_send: %s\n", is_send ? "true" : "false");
    printf("  mach.is_recv: %s\n", is_receive ? "true" : "false");
    printf("  mach.msgh_id: %d\n", header ? header->msgh_id : -1);
    printf("  mach.msgh_size: %u\n", payload->msgh_size);
    printf("  mach.copy_len: %u\n", payload->copy_len);
    printf("  mach.msgh_bits: 0x%08x\n", header ? (unsigned)header->msgh_bits : 0);
    printf("  mach.msg_addr: 0x%llx\n", (unsigned long long)payload->msg_addr);
    printf("  mach.aux_addr: 0x%llx\n", (unsigned long long)payload->aux_addr);
    printf("  mach.option64: 0x%016llx\n", (unsigned long long)option);
    printf("  mach.ret: 0x%llx\n", (unsigned long long)payload->ret_value);
    printf("  mach.desc_count: %u\n", payload->desc_count);
    printf("  mach.priority: %u\n", payload->priority);
    printf("  mach.timeout: %llu\n", (unsigned long long)payload->timeout);
    printf("  mach.remote_port: 0x%08x\n", remote);
    printf("  mach.local_port: 0x%08x\n", local);

    uint32_t sender_pid = 0;
    if (payload->direction == XNIFF_DIRECTION_EXIT && is_receive && payload->ret_value == 0) {
        uint32_t message_size = payload->msgh_size;
        if (message_size == 0 && header) message_size = header->msgh_size;
        if (message_size != 0) {
            (void)extract_sender_pid(message, message_length, message_size,
                                     &sender_pid);
        }
    }
    const char *sender_name = sender_pid ? xniff_process_name((pid_t)sender_pid) : NULL;
    if (sender_pid) {
        printf("  mach.peer_role: sender\n");
        printf("  mach.peer_pid: %u\n", sender_pid);
        if (sender_name) printf("  mach.peer_name: %s\n", sender_name);
    } else {
        printf("  mach.peer_role: %s\n", is_send ? "recipient" : "unknown");
    }

    size_t preview_length = message_length < 64 ? message_length : 64;
    if (header && preview_length) {
        printf("  mach.msg_preview_hex[%zu]: ", preview_length);
        for (size_t index = 0; index < preview_length; index++) {
            printf("%02x", message[index]);
        }
        printf("\n");
    }
}

int xniff_render_mach_record(const uint8_t *body,
                             size_t body_length,
                             const xniff_record_fixed_header_t *fixed) {
    if (!body || !fixed || body_length < sizeof(*fixed)) return -1;

    xniff_mach_payload_t payload = {
        .api = fixed->api,
        .direction = fixed->direction,
    };
    const uint8_t *message = NULL;
    size_t message_length = 0;
    xniff_record_section_iterator_t iterator;
    xniff_record_section_iterator_init(&iterator, body + sizeof(*fixed),
                                       body_length - sizeof(*fixed));
    xniff_record_section_t section;
    int section_result;
    while ((section_result = xniff_record_section_next(&iterator, &section)) > 0) {
        if (section.type == XNIFF_SECTION_MACH_HEADER_OPTIONS &&
            section.length >= sizeof(payload)) {
            memcpy(&payload, section.data, sizeof(payload));
        } else if (section.type == XNIFF_SECTION_MACH_INLINE_BYTES) {
            message = section.data;
            message_length = section.length;
        }
    }
    if (section_result < 0) return -1;
    print_mach_event(&payload, message, message_length);
    return 0;
}
