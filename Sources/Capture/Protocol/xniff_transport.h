#ifndef XNIFF_TRANSPORT_H
#define XNIFF_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XNIFF_RING_MAGIC 0x58495247u /* 'XIRG' */
#define XNIFF_RING_VERSION 2u
#define XNIFF_RING_CAPACITY (1u << 23) /* 8 MiB stream buffer */

#define XNIFF_TRANSPORT_MAGIC 0x5854524Eu /* 'XTRN' */
#define XNIFF_TRANSPORT_VERSION 1u
#define XNIFF_RING_FD_ENV "XNIFF_RING_FD"
#define XNIFF_WAKE_FD_ENV "XNIFF_WAKE_FD"
#define XNIFF_CAPTURE_MODE_ENV "XNIFF_CAPTURE_MODE"

enum {
    XNIFF_CAPTURE_MODE_NONE = 0,
    XNIFF_CAPTURE_MODE_MACH = (1u << 0),
    XNIFF_CAPTURE_MODE_XPC = (1u << 1),
};

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t config_version;
    uint32_t capacity;
    uint32_t reserved;
    uint64_t write_idx;
    uint64_t read_idx;
    uint64_t dropped_bytes;
    uint64_t dropped_events;
} xniff_ring_header_t;

_Static_assert(sizeof(xniff_ring_header_t) == 48,
               "ring header wire layout changed");

typedef struct {
    xniff_ring_header_t header;
    uint8_t data[XNIFF_RING_CAPACITY];
} xniff_ring_t;

_Static_assert(offsetof(xniff_ring_t, data) == sizeof(xniff_ring_header_t),
               "ring header must be contiguous with data");

// Configuration stored in the injected hooks image. Attach mode writes all
// fields with ready=0, then publishes ready separately.
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t struct_size;
    uint64_t ring_address;
    int32_t wake_fd;
    uint32_t wake_fileport;
    uint32_t capture_mode;
    uint32_t reserved;
    uint64_t ready;
} xniff_transport_config_t;

_Static_assert(sizeof(xniff_transport_config_t) == 40,
               "transport configuration layout changed");

__attribute__((visibility("default")))
extern xniff_transport_config_t xniff_transport_configuration;

void xniff_ring_initialize(xniff_ring_t *ring);
bool xniff_ring_is_valid(const xniff_ring_t *ring);
int xniff_transport_configure_direct(xniff_ring_t *ring,
                                     int wake_fd,
                                     uint32_t capture_mode);
int xniff_transport_configure_from_environment(void);
uint32_t xniff_transport_capture_mode(void);
bool xniff_transport_is_internal(void);

// Appends one complete record to the configured shared-memory ring.
int xniff_ring_write(const void *buffer, size_t length);

#ifdef __cplusplus
}
#endif

#endif
