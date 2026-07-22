#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "shared_transport.h"
#include "xniff_transport.h"

int selftest_shared_transport_tail(void) {
    xniff_shared_transport_t transport;
    if (xniff_shared_transport_create(&transport) != 0) {
        perror("xniff_shared_transport_create");
        return 1;
    }

    const uint8_t expected[] = {0x74, 0x61, 0x69, 0x6c};
    pid_t child = fork();
    if (child == 0) {
        xniff_shared_transport_prepare_target_child(&transport);
        if (xniff_transport_configure_direct(transport.ring,
                                             transport.wake_write_fd,
                                             XNIFF_CAPTURE_MODE_MACH) != 0 ||
            xniff_ring_write(expected, sizeof(expected)) != 0) {
            _exit(1);
        }
        _exit(0);
    }
    if (child < 0) {
        perror("fork");
        xniff_shared_transport_destroy(&transport);
        return 1;
    }

    xniff_shared_transport_release_controller_producer(&transport);
    bool producer_closed = false;
    while (!producer_closed) {
        if (xniff_shared_transport_wait(&transport, &producer_closed) != 0) {
            perror("xniff_shared_transport_wait");
            xniff_shared_transport_destroy(&transport);
            return 1;
        }
    }

    uint64_t read_index = 0;
    uint8_t *stream = NULL;
    size_t stream_length = 0;
    size_t stream_capacity = 0;
    int pull_result = xniff_shared_transport_pull(&transport, &read_index,
                                                  &stream, &stream_length,
                                                  &stream_capacity);
    int child_status = 0;
    (void)waitpid(child, &child_status, 0);
    bool passed = pull_result == 1 && stream_length == sizeof(expected) &&
                  memcmp(stream, expected, sizeof(expected)) == 0 &&
                  xniff_shared_transport_is_drained(&transport, read_index) &&
                  WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0;
    free(stream);
    xniff_shared_transport_destroy(&transport);
    if (!passed) {
        fprintf(stderr, "FAIL: shared transport did not preserve the producer tail\n");
        return 1;
    }
    printf("OK: shared transport drained data after producer exit\n");
    return 0;
}
