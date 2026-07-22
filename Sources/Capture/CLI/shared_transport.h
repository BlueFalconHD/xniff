#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <mach/mach.h>

#include "xniff_transport.h"

typedef struct {
    xniff_ring_t *ring;
    size_t ring_size;
    int ring_fd;
    int wake_read_fd;
    int wake_write_fd;
} xniff_shared_transport_t;

int xniff_shared_transport_create(xniff_shared_transport_t *transport);
void xniff_shared_transport_destroy(xniff_shared_transport_t *transport);

void xniff_shared_transport_prepare_target_child(xniff_shared_transport_t *transport);
void xniff_shared_transport_prepare_listener_child(xniff_shared_transport_t *transport);
void xniff_shared_transport_release_controller_reader(xniff_shared_transport_t *transport);
void xniff_shared_transport_release_controller_producer(xniff_shared_transport_t *transport);

int xniff_shared_transport_configure_target(xniff_shared_transport_t *transport,
                                            mach_port_t task,
                                            uint32_t capture_mode);

int xniff_shared_transport_pull(xniff_shared_transport_t *transport,
                                uint64_t *read_index,
                                uint8_t **stream,
                                size_t *stream_length,
                                size_t *stream_capacity);
int xniff_shared_transport_wait(xniff_shared_transport_t *transport,
                                bool *producer_closed);
bool xniff_shared_transport_is_drained(const xniff_shared_transport_t *transport,
                                       uint64_t read_index);
