#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../shared/xniff_ipc.h"

static int selftest_ipc_ring(void) {
    const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef, 0x42};

    uint64_t w0 = xniff_ipc_ring.hdr.write_idx;
    uint64_t r0 = xniff_ipc_ring.hdr.read_idx;
    uint64_t d0 = xniff_ipc_ring.hdr.dropped_events;

    if (xniff_ipc_ring_write(payload, sizeof(payload)) != 0) {
        perror("xniff_ipc_ring_write");
        return 1;
    }

    uint64_t w1 = xniff_ipc_ring.hdr.write_idx;
    if (w1 != w0 + sizeof(payload)) {
        fprintf(stderr, "FAIL: write_idx mismatch (%llu -> %llu)\n",
                (unsigned long long)w0, (unsigned long long)w1);
        return 1;
    }
    if (xniff_ipc_ring.hdr.read_idx != r0) {
        fprintf(stderr, "FAIL: read_idx changed unexpectedly\n");
        return 1;
    }
    if (xniff_ipc_ring.hdr.dropped_events != d0) {
        fprintf(stderr, "FAIL: dropped_events changed unexpectedly\n");
        return 1;
    }

    uint8_t got[sizeof(payload)];
    size_t cap = (size_t)xniff_ipc_ring.hdr.capacity;
    size_t off = (size_t)(w0 % cap);
    size_t first = cap - off;
    if (first > sizeof(payload)) first = sizeof(payload);
    memcpy(got, xniff_ipc_ring.data + off, first);
    if (sizeof(payload) > first) memcpy(got + first, xniff_ipc_ring.data, sizeof(payload) - first);

    if (memcmp(got, payload, sizeof(payload)) != 0) {
        fprintf(stderr, "FAIL: payload mismatch in ring\n");
        return 1;
    }

    printf("OK: ring write/readback validated\n");
    return 0;
}

int main(int argc, char **argv) {
    if (getenv("XNIFF_TEST_IPC_RING")) return selftest_ipc_ring();

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ipc-ring") == 0) return selftest_ipc_ring();
    }

    printf("xniff-test: no tests selected (try --ipc-ring)\n");
    return 0;
}
