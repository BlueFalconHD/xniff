#include "capture.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xniff_record.h"
#include "xniff_transport.h"
#include "record_renderer.h"

static bool entry_length_is_valid(uint32_t length) {
    size_t minimum = sizeof(xniff_record_header_t) +
                     sizeof(xniff_record_fixed_header_t);
    return length >= minimum && length <= 64u * 1024u * 1024u;
}

static bool environment_flag_is_enabled(const char *name) {
    const char *value = name ? getenv(name) : NULL;
    return value && *value && strcmp(value, "0") != 0;
}

static int write_capture_header(FILE *output) {
    xniff_capture_file_header_t header = {
        .magic = XNIFF_CAPTURE_FILE_MAGIC,
        .version = XNIFF_CAPTURE_FILE_VERSION,
    };
    return fwrite(&header, sizeof(header), 1, output) == 1 ? 0 : -1;
}

static int write_record(FILE *output, const uint8_t *record, size_t length) {
    return fwrite(record, 1, length, output) == length ? 0 : -1;
}

static void close_output(FILE *output) {
    if (output && output != stdout) fclose(output);
}

int xniff_capture_ring(pid_t pid,
                       int ready_fd,
                       xniff_shared_transport_t *transport,
                       const listener_opts_t *options) {
    if (!options || !transport || !transport->ring || transport->wake_read_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (ready_fd >= 0) {
        const uint8_t ready = 1;
        (void)write(ready_fd, &ready, sizeof(ready));
        close(ready_fd);
    }

    FILE *output = NULL;
    if (options->out_bin) {
        output = fopen(options->out_bin_path, "wb");
        if (!output) {
            fprintf(stderr, "capture: failed opening --out path '%s': %s\n",
                    options->out_bin_path, strerror(errno));
            return -1;
        }
        if (write_capture_header(output) != 0) {
            fprintf(stderr, "capture: failed writing binary stream header\n");
            close_output(output);
            return -1;
        }
    }

    fprintf(stderr, "capture: streaming target_pid=%d shared_ring=%p\n",
            (int)pid, (void *)transport->ring);

    uint64_t local_read_index =
        __atomic_load_n(&transport->ring->header.read_idx, __ATOMIC_ACQUIRE);
    uint8_t *stream = NULL;
    size_t stream_length = 0;
    size_t stream_capacity = 0;
    uint64_t last_dropped_events = 0;
    uint64_t last_dropped_bytes = 0;
    bool producer_closed = false;
    bool include_hook_debug = environment_flag_is_enabled("XNIFF_HOOKS_DEBUG");

    for (;;) {
        xniff_ring_header_t *header = &transport->ring->header;
        if (!xniff_ring_is_valid(transport->ring)) {
            fprintf(stderr, "capture: invalid shared ring header\n");
            break;
        }

        uint64_t dropped_events =
            __atomic_load_n(&header->dropped_events, __ATOMIC_ACQUIRE);
        uint64_t dropped_bytes =
            __atomic_load_n(&header->dropped_bytes, __ATOMIC_ACQUIRE);
        if (dropped_events != last_dropped_events || dropped_bytes != last_dropped_bytes) {
            fprintf(stderr,
                    "capture: warning: target dropped %llu events (%llu bytes)\n",
                    (unsigned long long)(dropped_events - last_dropped_events),
                    (unsigned long long)(dropped_bytes - last_dropped_bytes),
                    (unsigned long long)dropped_events,
                    (unsigned long long)dropped_bytes);
            last_dropped_events = dropped_events;
            last_dropped_bytes = dropped_bytes;
        }

        if (xniff_shared_transport_pull(transport, &local_read_index, &stream,
                                        &stream_length, &stream_capacity) < 0) {
            fprintf(stderr, "capture: failed draining shared ring: %s\n", strerror(errno));
            break;
        }

        size_t consumed = 0;
        while (stream_length - consumed >= sizeof(xniff_record_header_t)) {
            const uint8_t *record = stream + consumed;
            xniff_record_header_t record_header = {0};
            memcpy(&record_header, record, sizeof(record_header));
            if (record_header.version != XNIFF_RECORD_VERSION ||
                !entry_length_is_valid(record_header.length)) {
                consumed++;
                continue;
            }

            size_t record_length = record_header.length;
            if (stream_length - consumed < record_length) break;
            int result = output
                ? write_record(output, record, record_length)
                : xniff_render_record(record, record_length, include_hook_debug);
            if (result != 0) {
                fprintf(stderr, "capture: failed processing record\n");
                close_output(output);
                free(stream);
                return -1;
            }
            consumed += record_length;
        }
        if (consumed != 0) {
            memmove(stream, stream + consumed, stream_length - consumed);
            stream_length -= consumed;
        }

        if (producer_closed &&
            xniff_shared_transport_is_drained(transport, local_read_index)) {
            if (stream_length != 0) {
                fprintf(stderr, "capture: warning: discarded %zu trailing transport bytes\n",
                        stream_length);
            }
            fprintf(stderr, "capture: target pid %d exited\ncapture: shared ring drained\n", (int)pid);
            close_output(output);
            free(stream);
            return 0;
        }
        if (xniff_shared_transport_wait(transport, &producer_closed) != 0) {
            fprintf(stderr, "capture: wake socket failed: %s\n", strerror(errno));
            break;
        }
    }

    close_output(output);
    free(stream);
    return -1;
}
