#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include "xniff_payload.h"
#include "xniff_record.h"
#include "xniff_transport.h"
#include "xpc_reply_tracker.h"

int selftest_target_user_options(void);
int selftest_target_identity(void);
int selftest_xpc_session_coalescer(void);
int selftest_shared_transport_tail(void);

static xniff_ring_t *g_test_ring = NULL;
static int g_test_wake_read_fd = -1;

static int prepare_test_transport(void) {
    g_test_ring = mmap(NULL, sizeof(*g_test_ring), PROT_READ | PROT_WRITE,
                       MAP_ANON | MAP_SHARED, -1, 0);
    if (g_test_ring == MAP_FAILED) {
        g_test_ring = NULL;
        return -1;
    }
    xniff_ring_initialize(g_test_ring);
    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return -1;
    g_test_wake_read_fd = sockets[0];
    if (xniff_transport_configure_direct(g_test_ring, sockets[1],
                                         XNIFF_CAPTURE_MODE_MACH) != 0) {
        return -1;
    }
    return 0;
}

static int selftest_transport_ring(void) {
    if (prepare_test_transport() != 0) {
        perror("prepare_test_transport");
        return 1;
    }
    const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef, 0x42};

    uint64_t w0 = g_test_ring->header.write_idx;
    uint64_t r0 = g_test_ring->header.read_idx;
    uint64_t d0 = g_test_ring->header.dropped_events;

    if (xniff_ring_write(payload, sizeof(payload)) != 0) {
        perror("xniff_ring_write");
        return 1;
    }

    uint64_t w1 = g_test_ring->header.write_idx;
    if (w1 != w0 + sizeof(payload)) {
        fprintf(stderr, "FAIL: write_idx mismatch (%llu -> %llu)\n",
                (unsigned long long)w0, (unsigned long long)w1);
        return 1;
    }
    if (g_test_ring->header.read_idx != r0) {
        fprintf(stderr, "FAIL: read_idx changed unexpectedly\n");
        return 1;
    }
    if (g_test_ring->header.dropped_events != d0) {
        fprintf(stderr, "FAIL: dropped_events changed unexpectedly\n");
        return 1;
    }

    uint8_t got[sizeof(payload)];
    size_t cap = (size_t)g_test_ring->header.capacity;
    size_t off = (size_t)(w0 % cap);
    size_t first = cap - off;
    if (first > sizeof(payload)) first = sizeof(payload);
    memcpy(got, g_test_ring->data + off, first);
    if (sizeof(payload) > first) memcpy(got + first, g_test_ring->data, sizeof(payload) - first);

    if (memcmp(got, payload, sizeof(payload)) != 0) {
        fprintf(stderr, "FAIL: payload mismatch in ring\n");
        return 1;
    }

    uint8_t kick = 0;
    if (recv(g_test_wake_read_fd, &kick, sizeof(kick), 0) != sizeof(kick) || kick != 1) {
        fprintf(stderr, "FAIL: shared ring write did not kick the consumer\n");
        return 1;
    }

    printf("OK: shared ring write/readback and socket kick validated\n");
    return 0;
}

static int selftest_transport_drop(void) {
    if (prepare_test_transport() != 0) {
        perror("prepare_test_transport");
        return 1;
    }
    uint64_t original_write = g_test_ring->header.write_idx;
    uint64_t original_read = g_test_ring->header.read_idx;
    uint64_t original_dropped_events = g_test_ring->header.dropped_events;
    uint64_t original_dropped_bytes = g_test_ring->header.dropped_bytes;

    g_test_ring->header.read_idx = 0;
    g_test_ring->header.write_idx = g_test_ring->header.capacity;
    const uint8_t byte = 0xaa;
    int result = xniff_ring_write(&byte, sizeof(byte));
    bool passed = result != 0 &&
                  g_test_ring->header.dropped_events == original_dropped_events + 1 &&
                  g_test_ring->header.dropped_bytes == original_dropped_bytes + 1;

    g_test_ring->header.write_idx = original_write;
    g_test_ring->header.read_idx = original_read;
    g_test_ring->header.dropped_events = original_dropped_events;
    g_test_ring->header.dropped_bytes = original_dropped_bytes;
    if (!passed) {
        fprintf(stderr, "FAIL: full ring did not report one dropped event\n");
        return 1;
    }
    printf("OK: ring drop accounting validated\n");
    return 0;
}

static int selftest_record_call_id(void) {
    const uint64_t expected_call_id = 0x123456789abcdef0ull;

    xniff_record_builder_t builder;
    xniff_record_builder_init(&builder);
    int result = xniff_record_begin(&builder, XNIFF_RECORD_TYPE_XPC, 42, 7, 99,
                                    XNIFF_DIRECTION_ENTRY, XNIFF_API_XPC,
                                    XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC);
    if (result == 0) {
        result = xniff_record_add_section(&builder, XNIFF_SECTION_CALL_ID, 0,
                                          &expected_call_id, sizeof(expected_call_id));
    }
    const uint8_t *record = NULL;
    size_t record_len = 0;
    if (result == 0) {
        result = xniff_record_finish(&builder, &record, &record_len);
    }
    if (result != 0) {
        xniff_record_builder_free(&builder);
        fprintf(stderr, "FAIL: could not build call-id record\n");
        return 1;
    }

    size_t section_offset = sizeof(xniff_record_header_t) +
                            sizeof(xniff_record_fixed_header_t);
    xniff_record_section_iterator_t iterator;
    xniff_record_section_iterator_init(&iterator, record + section_offset,
                                       record_len - section_offset);
    xniff_record_section_t section = {0};
    int section_result = xniff_record_section_next(&iterator, &section);
    uint64_t actual_call_id = 0;
    if (section_result > 0 && section.length >= sizeof(actual_call_id)) {
        memcpy(&actual_call_id, section.data, sizeof(actual_call_id));
    }
    bool passed = section_result > 0 && section.type == XNIFF_SECTION_CALL_ID &&
                  section.length == sizeof(expected_call_id) &&
                  actual_call_id == expected_call_id;
    xniff_record_builder_free(&builder);
    if (!passed) {
        fprintf(stderr, "FAIL: call-id section mismatch\n");
        return 1;
    }
    printf("OK: call-id record validated\n");
    return 0;
}

static int selftest_xpc_reply_tracker(void) {
    const uint64_t context = 0x12345000;
    uint64_t actual = 0;

    xniff_xpc_reply_tracker_clear();
    bool passed = !xniff_xpc_reply_tracker_record(0, 17) &&
                  xniff_xpc_reply_tracker_record(context, 17) &&
                  xniff_xpc_reply_tracker_record(context, 18) &&
                  xniff_xpc_reply_tracker_take(context, &actual) &&
                  actual == 18 &&
                  !xniff_xpc_reply_tracker_take(context, &actual);
    for (uint64_t index = 1; passed && index <= 9000; index++) {
        passed = xniff_xpc_reply_tracker_record(index << 12, index);
    }
    passed = passed &&
             xniff_xpc_reply_tracker_take(9000ull << 12, &actual) &&
             actual == 9000;
    xniff_xpc_reply_tracker_clear();
    if (!passed) {
        fprintf(stderr, "FAIL: XPC reply tracker did not preserve and consume correlation\n");
        return 1;
    }
    printf("OK: XPC reply tracker correlation validated\n");
    return 0;
}

int main(int argc, char **argv) {
    if (getenv("XNIFF_TEST_TRANSPORT_RING")) return selftest_transport_ring();

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--transport-ring") == 0) return selftest_transport_ring();
        if (strcmp(argv[i], "--transport-drop") == 0) return selftest_transport_drop();
        if (strcmp(argv[i], "--record-call-id") == 0) return selftest_record_call_id();
        if (strcmp(argv[i], "--shared-transport-tail") == 0) return selftest_shared_transport_tail();
        if (strcmp(argv[i], "--xpc-reply-tracker") == 0) return selftest_xpc_reply_tracker();
        if (strcmp(argv[i], "--xpc-session-coalescer") == 0) return selftest_xpc_session_coalescer();
        if (strcmp(argv[i], "--target-user-options") == 0) return selftest_target_user_options();
        if (strcmp(argv[i], "--target-identity") == 0) return selftest_target_identity();
    }

    printf("xniff-test: no tests selected (try --transport-ring)\n");
    return 0;
}
