#include "xniff_transport.h"

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fileport.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

__attribute__((visibility("default"), used)) xniff_transport_config_t
    xniff_transport_configuration = {0};

static pthread_mutex_t g_ring_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_wake_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_wake_fd = -1;
static _Thread_local uint32_t g_transport_internal_depth = 0;

static inline uint64_t ring_load_u64(const uint64_t *p) {
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void ring_store_u64(uint64_t *p, uint64_t v) {
    __atomic_store_n(p, v, __ATOMIC_RELEASE);
}

void xniff_ring_initialize(xniff_ring_t *ring) {
    if (!ring) return;
    memset(ring, 0, sizeof(*ring));
    ring->header.magic = XNIFF_RING_MAGIC;
    ring->header.version = XNIFF_RING_VERSION;
    ring->header.config_version = XNIFF_TRANSPORT_VERSION;
    ring->header.capacity = XNIFF_RING_CAPACITY;
}

bool xniff_ring_is_valid(const xniff_ring_t *ring) {
    return ring && ring->header.magic == XNIFF_RING_MAGIC &&
           ring->header.version == XNIFF_RING_VERSION &&
           ring->header.config_version == XNIFF_TRANSPORT_VERSION &&
           ring->header.capacity == XNIFF_RING_CAPACITY;
}

static uint32_t parse_capture_mode(const char *value) {
    if (!value) return XNIFF_CAPTURE_MODE_NONE;
    if (strcmp(value, "mach") == 0) return XNIFF_CAPTURE_MODE_MACH;
    if (strcmp(value, "xpc") == 0) return XNIFF_CAPTURE_MODE_XPC;
    if (strcmp(value, "both") == 0) {
        return XNIFF_CAPTURE_MODE_MACH | XNIFF_CAPTURE_MODE_XPC;
    }
    return XNIFF_CAPTURE_MODE_NONE;
}

static int parse_fd(const char *value) {
    if (!value || !*value) return -1;
    char *end = NULL;
    errno = 0;
    long parsed = strtol(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed < 0 || parsed > INT32_MAX) return -1;
    return (int)parsed;
}

int xniff_transport_configure_direct(xniff_ring_t *ring,
                                     int wake_fd,
                                     uint32_t capture_mode) {
    if (!xniff_ring_is_valid(ring) || capture_mode == XNIFF_CAPTURE_MODE_NONE) {
        errno = EINVAL;
        return -1;
    }

    xniff_transport_config_t config = {0};
    config.magic = XNIFF_TRANSPORT_MAGIC;
    config.version = XNIFF_TRANSPORT_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.ring_address = (uint64_t)(uintptr_t)ring;
    config.wake_fd = wake_fd;
    config.capture_mode = capture_mode;
    config.ready = 0;
    xniff_transport_configuration = config;
    __atomic_store_n(&xniff_transport_configuration.ready, 1, __ATOMIC_RELEASE);
    return 0;
}

int xniff_transport_configure_from_environment(void) {
    int ring_fd = parse_fd(getenv(XNIFF_RING_FD_ENV));
    int wake_fd = parse_fd(getenv(XNIFF_WAKE_FD_ENV));
    uint32_t capture_mode = parse_capture_mode(getenv(XNIFF_CAPTURE_MODE_ENV));
    if (ring_fd < 0 || wake_fd < 0 || capture_mode == XNIFF_CAPTURE_MODE_NONE) return -1;

    struct stat status = {0};
    if (fstat(ring_fd, &status) != 0 || status.st_size < (off_t)sizeof(xniff_ring_t)) {
        return -1;
    }
    void *mapping = mmap(NULL, sizeof(xniff_ring_t), PROT_READ | PROT_WRITE,
                         MAP_SHARED, ring_fd, 0);
    if (mapping == MAP_FAILED) return -1;
    close(ring_fd);

    if (xniff_transport_configure_direct((xniff_ring_t *)mapping,
                                         wake_fd, capture_mode) != 0) {
        munmap(mapping, sizeof(xniff_ring_t));
        return -1;
    }
    return 0;
}

static xniff_ring_t *configured_ring(void) {
    if (__atomic_load_n(&xniff_transport_configuration.ready, __ATOMIC_ACQUIRE) == 0) return NULL;
    if (xniff_transport_configuration.magic != XNIFF_TRANSPORT_MAGIC ||
        xniff_transport_configuration.version != XNIFF_TRANSPORT_VERSION ||
        xniff_transport_configuration.struct_size != sizeof(xniff_transport_config_t)) {
        return NULL;
    }
    xniff_ring_t *ring =
        (xniff_ring_t *)(uintptr_t)xniff_transport_configuration.ring_address;
    if (!xniff_ring_is_valid(ring)) {
        return NULL;
    }
    return ring;
}

uint32_t xniff_transport_capture_mode(void) {
    return configured_ring() ? xniff_transport_configuration.capture_mode
                             : XNIFF_CAPTURE_MODE_NONE;
}

bool xniff_transport_is_internal(void) {
    return g_transport_internal_depth != 0;
}

static int configured_wake_fd(void) {
    if (g_wake_fd >= 0) return g_wake_fd;

    pthread_mutex_lock(&g_wake_lock);
    if (g_wake_fd < 0) {
        if (xniff_transport_configuration.wake_fd >= 0) {
            g_wake_fd = xniff_transport_configuration.wake_fd;
        } else if (xniff_transport_configuration.wake_fileport != MACH_PORT_NULL) {
            g_transport_internal_depth++;
            int fd = fileport_makefd((fileport_t)xniff_transport_configuration.wake_fileport);
            g_transport_internal_depth--;
            if (fd >= 0) {
                (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
                g_wake_fd = fd;
                (void)mach_port_deallocate(mach_task_self(),
                                           xniff_transport_configuration.wake_fileport);
                xniff_transport_configuration.wake_fileport = MACH_PORT_NULL;
            }
        }
    }
    int result = g_wake_fd;
    pthread_mutex_unlock(&g_wake_lock);
    return result;
}

static void kick_consumer(void) {
    int fd = configured_wake_fd();
    if (fd < 0) return;
    const uint8_t byte = 1;
    ssize_t result;
    do {
        result = send(fd, &byte, sizeof(byte), MSG_DONTWAIT | MSG_NOSIGNAL);
    } while (result < 0 && errno == EINTR);
}

static int ring_write_bytes(const void *buf, size_t len) {
    if (len == 0) return 0;
    if (!buf) return -1;

    xniff_ring_t *ring = configured_ring();
    if (!ring) {
        errno = ENOTCONN;
        return -1;
    }

    pthread_mutex_lock(&g_ring_lock);

    uint64_t cap = (uint64_t)ring->header.capacity;
    if (cap == 0 || cap > (uint64_t)XNIFF_RING_CAPACITY) {
        pthread_mutex_unlock(&g_ring_lock);
        return -1;
    }

    uint64_t w = ring_load_u64(&ring->header.write_idx);
    uint64_t r = ring_load_u64(&ring->header.read_idx);

    // Recover conservatively if counters look inconsistent.
    if (w < r || (w - r) > cap) {
        r = w;
        ring_store_u64(&ring->header.read_idx, r);
    }

    uint64_t used = w - r;
    uint64_t avail = cap - used;
    if ((uint64_t)len > avail) {
        ring_store_u64(&ring->header.dropped_bytes,
                       ring_load_u64(&ring->header.dropped_bytes) + (uint64_t)len);
        ring_store_u64(&ring->header.dropped_events,
                       ring_load_u64(&ring->header.dropped_events) + 1);
        pthread_mutex_unlock(&g_ring_lock);
        errno = ENOBUFS;
        return -1;
    }

    uint64_t off = w % cap;
    uint64_t first = cap - off;
    if (first > (uint64_t)len) first = (uint64_t)len;
    bool was_empty = w == r;
    memcpy(ring->data + off, buf, (size_t)first);
    if ((uint64_t)len > first) {
        memcpy(ring->data, (const uint8_t *)buf + first, (size_t)((uint64_t)len - first));
    }

    ring_store_u64(&ring->header.write_idx, w + (uint64_t)len);
    pthread_mutex_unlock(&g_ring_lock);
    if (was_empty) kick_consumer();
    return 0;
}

int xniff_ring_write(const void *buf, size_t len) {
    return ring_write_bytes(buf, len);
}
