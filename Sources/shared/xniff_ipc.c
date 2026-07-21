#include "xniff_ipc.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>

// In-target ring buffer transport polled by xniff-cli.

__attribute__((visibility("default"), used)) xniff_ipc_ring_t xniff_ipc_ring = {
    .hdr =
        {
            .magic = XNIFF_IPC_RING_MAGIC,
            .version = XNIFF_IPC_RING_VERSION,
            .config_version = 1,
            .capacity = XNIFF_IPC_RING_CAPACITY,
            .capture_mode = XNIFF_CAPTURE_MODE_NONE,
            .write_idx = 0,
            .read_idx = 0,
            .dropped_bytes = 0,
            .dropped_events = 0,
        },
    .data = {0},
};

static pthread_mutex_t g_ring_lock = PTHREAD_MUTEX_INITIALIZER;

static inline uint64_t ring_load_u64(const uint64_t *p) {
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void ring_store_u64(uint64_t *p, uint64_t v) {
    __atomic_store_n(p, v, __ATOMIC_RELEASE);
}

static int ring_write_bytes(const void *buf, size_t len) {
    if (len == 0) return 0;
    if (!buf) return -1;

    pthread_mutex_lock(&g_ring_lock);

    uint64_t cap = (uint64_t)xniff_ipc_ring.hdr.capacity;
    if (cap == 0 || cap > (uint64_t)XNIFF_IPC_RING_CAPACITY) {
        pthread_mutex_unlock(&g_ring_lock);
        return -1;
    }

    uint64_t w = ring_load_u64(&xniff_ipc_ring.hdr.write_idx);
    uint64_t r = ring_load_u64(&xniff_ipc_ring.hdr.read_idx);

    // Recover conservatively if counters look inconsistent.
    if (w < r || (w - r) > cap) {
        r = w;
        ring_store_u64(&xniff_ipc_ring.hdr.read_idx, r);
    }

    uint64_t used = w - r;
    uint64_t avail = cap - used;
    if ((uint64_t)len > avail) {
        ring_store_u64(&xniff_ipc_ring.hdr.dropped_bytes,
                       ring_load_u64(&xniff_ipc_ring.hdr.dropped_bytes) + (uint64_t)len);
        ring_store_u64(&xniff_ipc_ring.hdr.dropped_events,
                       ring_load_u64(&xniff_ipc_ring.hdr.dropped_events) + 1);
        pthread_mutex_unlock(&g_ring_lock);
        errno = ENOBUFS;
        return -1;
    }

    uint64_t off = w % cap;
    uint64_t first = cap - off;
    if (first > (uint64_t)len) first = (uint64_t)len;
    memcpy(xniff_ipc_ring.data + off, buf, (size_t)first);
    if ((uint64_t)len > first) {
        memcpy(xniff_ipc_ring.data, (const uint8_t *)buf + first, (size_t)((uint64_t)len - first));
    }

    ring_store_u64(&xniff_ipc_ring.hdr.write_idx, w + (uint64_t)len);
    pthread_mutex_unlock(&g_ring_lock);
    return 0;
}

int xniff_ipc_ring_write(const void *buf, size_t len) {
    return ring_write_bytes(buf, len);
}
