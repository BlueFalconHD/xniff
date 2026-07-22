#include "xniff_ipc.h"

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

__attribute__((visibility("default"), used)) xniff_ipc_transport_config_t
    xniff_ipc_transport_config = {0};

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

void xniff_ipc_ring_initialize(xniff_ipc_ring_t *ring) {
    if (!ring) return;
    memset(ring, 0, sizeof(*ring));
    ring->hdr.magic = XNIFF_IPC_RING_MAGIC;
    ring->hdr.version = XNIFF_IPC_RING_VERSION;
    ring->hdr.config_version = XNIFF_IPC_TRANSPORT_VERSION;
    ring->hdr.capacity = XNIFF_IPC_RING_CAPACITY;
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

int xniff_ipc_transport_configure_direct(xniff_ipc_ring_t *ring,
                                         int wake_fd,
                                         uint32_t capture_mode) {
    if (!ring || ring->hdr.magic != XNIFF_IPC_RING_MAGIC ||
        ring->hdr.version != XNIFF_IPC_RING_VERSION ||
        ring->hdr.capacity != XNIFF_IPC_RING_CAPACITY ||
        capture_mode == XNIFF_CAPTURE_MODE_NONE) {
        errno = EINVAL;
        return -1;
    }

    xniff_ipc_transport_config_t config = {0};
    config.magic = XNIFF_IPC_TRANSPORT_MAGIC;
    config.version = XNIFF_IPC_TRANSPORT_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.ring_address = (uint64_t)(uintptr_t)ring;
    config.wake_fd = wake_fd;
    config.capture_mode = capture_mode;
    config.ready = 0;
    xniff_ipc_transport_config = config;
    __atomic_store_n(&xniff_ipc_transport_config.ready, 1, __ATOMIC_RELEASE);
    return 0;
}

int xniff_ipc_transport_configure_from_environment(void) {
    int ring_fd = parse_fd(getenv(XNIFF_IPC_RING_FD_ENV));
    int wake_fd = parse_fd(getenv(XNIFF_IPC_WAKE_FD_ENV));
    uint32_t capture_mode = parse_capture_mode(getenv(XNIFF_IPC_CAPTURE_MODE_ENV));
    if (ring_fd < 0 || wake_fd < 0 || capture_mode == XNIFF_CAPTURE_MODE_NONE) return -1;

    struct stat status = {0};
    if (fstat(ring_fd, &status) != 0 || status.st_size < (off_t)sizeof(xniff_ipc_ring_t)) {
        return -1;
    }
    void *mapping = mmap(NULL, sizeof(xniff_ipc_ring_t), PROT_READ | PROT_WRITE,
                         MAP_SHARED, ring_fd, 0);
    if (mapping == MAP_FAILED) return -1;
    close(ring_fd);

    if (xniff_ipc_transport_configure_direct((xniff_ipc_ring_t *)mapping,
                                             wake_fd, capture_mode) != 0) {
        munmap(mapping, sizeof(xniff_ipc_ring_t));
        return -1;
    }
    return 0;
}

static xniff_ipc_ring_t *configured_ring(void) {
    if (__atomic_load_n(&xniff_ipc_transport_config.ready, __ATOMIC_ACQUIRE) == 0) return NULL;
    if (xniff_ipc_transport_config.magic != XNIFF_IPC_TRANSPORT_MAGIC ||
        xniff_ipc_transport_config.version != XNIFF_IPC_TRANSPORT_VERSION ||
        xniff_ipc_transport_config.struct_size != sizeof(xniff_ipc_transport_config_t)) {
        return NULL;
    }
    xniff_ipc_ring_t *ring =
        (xniff_ipc_ring_t *)(uintptr_t)xniff_ipc_transport_config.ring_address;
    if (!ring || ring->hdr.magic != XNIFF_IPC_RING_MAGIC ||
        ring->hdr.version != XNIFF_IPC_RING_VERSION ||
        ring->hdr.capacity != XNIFF_IPC_RING_CAPACITY) {
        return NULL;
    }
    return ring;
}

uint32_t xniff_ipc_transport_capture_mode(void) {
    return configured_ring() ? xniff_ipc_transport_config.capture_mode
                             : XNIFF_CAPTURE_MODE_NONE;
}

bool xniff_ipc_transport_is_internal(void) {
    return g_transport_internal_depth != 0;
}

static int configured_wake_fd(void) {
    if (g_wake_fd >= 0) return g_wake_fd;

    pthread_mutex_lock(&g_wake_lock);
    if (g_wake_fd < 0) {
        if (xniff_ipc_transport_config.wake_fd >= 0) {
            g_wake_fd = xniff_ipc_transport_config.wake_fd;
        } else if (xniff_ipc_transport_config.wake_fileport != MACH_PORT_NULL) {
            g_transport_internal_depth++;
            int fd = fileport_makefd((fileport_t)xniff_ipc_transport_config.wake_fileport);
            g_transport_internal_depth--;
            if (fd >= 0) {
                (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
                g_wake_fd = fd;
                (void)mach_port_deallocate(mach_task_self(),
                                           xniff_ipc_transport_config.wake_fileport);
                xniff_ipc_transport_config.wake_fileport = MACH_PORT_NULL;
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

    xniff_ipc_ring_t *ring = configured_ring();
    if (!ring) {
        errno = ENOTCONN;
        return -1;
    }

    pthread_mutex_lock(&g_ring_lock);

    uint64_t cap = (uint64_t)ring->hdr.capacity;
    if (cap == 0 || cap > (uint64_t)XNIFF_IPC_RING_CAPACITY) {
        pthread_mutex_unlock(&g_ring_lock);
        return -1;
    }

    uint64_t w = ring_load_u64(&ring->hdr.write_idx);
    uint64_t r = ring_load_u64(&ring->hdr.read_idx);

    // Recover conservatively if counters look inconsistent.
    if (w < r || (w - r) > cap) {
        r = w;
        ring_store_u64(&ring->hdr.read_idx, r);
    }

    uint64_t used = w - r;
    uint64_t avail = cap - used;
    if ((uint64_t)len > avail) {
        ring_store_u64(&ring->hdr.dropped_bytes,
                       ring_load_u64(&ring->hdr.dropped_bytes) + (uint64_t)len);
        ring_store_u64(&ring->hdr.dropped_events,
                       ring_load_u64(&ring->hdr.dropped_events) + 1);
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

    ring_store_u64(&ring->hdr.write_idx, w + (uint64_t)len);
    pthread_mutex_unlock(&g_ring_lock);
    if (was_empty) kick_consumer();
    return 0;
}

int xniff_ipc_ring_write(const void *buf, size_t len) {
    return ring_write_bytes(buf, len);
}
