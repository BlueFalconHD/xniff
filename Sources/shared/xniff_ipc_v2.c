#include "xniff_ipc_v2.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "xniff_ipc.h"

static uint64_t g_v2_seq = 0;

static int ensure_cap(xniff_ipc_v2_builder_t *b, size_t need) {
    if (!b) return -1;
    if (b->cap >= need) return 0;
    size_t nc = b->cap ? b->cap : 1024;
    while (nc < need) {
        if (nc > (SIZE_MAX / 2)) return -1;
        nc *= 2;
    }
    uint8_t *nb = (uint8_t *)realloc(b->buf, nc);
    if (!nb) return -1;
    b->buf = nb;
    b->cap = nc;
    return 0;
}

void xniff_ipc_v2_builder_init(xniff_ipc_v2_builder_t *b) {
    if (!b) return;
    memset(b, 0, sizeof(*b));
}

void xniff_ipc_v2_builder_free(xniff_ipc_v2_builder_t *b) {
    if (!b) return;
    free(b->buf);
    memset(b, 0, sizeof(*b));
}

static uint64_t now_mono_ns(void) {
    struct timespec ts = {0};
#ifdef CLOCK_MONOTONIC_RAW
    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

int xniff_ipc_v2_begin(xniff_ipc_v2_builder_t *b,
                       uint16_t entry_type,
                       uint32_t pid,
                       uint32_t tid_low,
                       uint64_t timestamp_ns,
                       uint16_t direction,
                       uint16_t api,
                       uint32_t function) {
    if (!b) return -1;
    b->len = 0;
    size_t base = sizeof(xniff_ipc_v2_entry_hdr_t) + sizeof(xniff_ipc_v2_fixed_hdr_t);
    if (ensure_cap(b, base) != 0) return -1;

    xniff_ipc_v2_entry_hdr_t h = {0};
    h.entry_len = (uint32_t)base;
    h.entry_type = entry_type;
    h.version = XNIFF_IPC_V2_VERSION;
    h.seq = __atomic_add_fetch(&g_v2_seq, 1, __ATOMIC_RELAXED);
    memcpy(b->buf, &h, sizeof(h));

    xniff_ipc_v2_fixed_hdr_t fh = {0};
    fh.pid = pid;
    fh.tid_low = tid_low;
    fh.timestamp_ns = timestamp_ns ? timestamp_ns : now_mono_ns();
    fh.direction = direction;
    fh.api = api;
    fh.function = function;
    memcpy(b->buf + sizeof(h), &fh, sizeof(fh));

    b->len = base;
    return 0;
}

int xniff_ipc_v2_add_section(xniff_ipc_v2_builder_t *b,
                             uint16_t sec_type,
                             uint16_t flags,
                             const void *payload,
                             size_t payload_len) {
    size_t base = sizeof(xniff_ipc_v2_entry_hdr_t) + sizeof(xniff_ipc_v2_fixed_hdr_t);
    if (!b || !b->buf || b->len < base) return -1;
    if (payload_len > UINT32_MAX) return -1;
    if (payload_len != 0 && !payload) return -1;

    size_t need = b->len + sizeof(xniff_ipc_v2_section_hdr_t) + payload_len;
    if (ensure_cap(b, need) != 0) return -1;

    xniff_ipc_v2_section_hdr_t sh = {0};
    sh.sec_type = sec_type;
    sh.flags = flags;
    sh.sec_len = (uint32_t)payload_len;

    memcpy(b->buf + b->len, &sh, sizeof(sh));
    b->len += sizeof(sh);
    if (payload_len != 0) {
        memcpy(b->buf + b->len, payload, payload_len);
        b->len += payload_len;
    }
    return 0;
}

int xniff_ipc_v2_write(xniff_ipc_v2_builder_t *b) {
    size_t base = sizeof(xniff_ipc_v2_entry_hdr_t) + sizeof(xniff_ipc_v2_fixed_hdr_t);
    if (!b || !b->buf || b->len < base) return -1;
    if (b->len > UINT32_MAX) return -1;

    xniff_ipc_v2_entry_hdr_t *h = (xniff_ipc_v2_entry_hdr_t *)b->buf;
    h->entry_len = (uint32_t)b->len;
    if (h->version != XNIFF_IPC_V2_VERSION) {
        errno = EINVAL;
        return -1;
    }
    return xniff_ipc_ring_write(b->buf, b->len);
}
