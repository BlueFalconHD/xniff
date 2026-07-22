#include "xniff_record.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t g_sequence = 0;

bool xniff_record_type_matches_api(uint16_t type, uint16_t api) {
    switch (type) {
        case XNIFF_RECORD_TYPE_MACH:
            return api == XNIFF_API_MACH_MSG || api == XNIFF_API_MACH_MSG2;
        case XNIFF_RECORD_TYPE_XPC:
            return api == XNIFF_API_XPC;
        case XNIFF_RECORD_TYPE_DIAG:
            return api == XNIFF_API_DEBUG;
        default:
            return false;
    }
}

static int ensure_cap(xniff_record_builder_t *b, size_t need) {
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

void xniff_record_builder_init(xniff_record_builder_t *b) {
    if (!b) return;
    memset(b, 0, sizeof(*b));
}

void xniff_record_builder_free(xniff_record_builder_t *b) {
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

int xniff_record_begin(xniff_record_builder_t *b,
                       uint16_t type,
                       uint32_t pid,
                       uint32_t tid_low,
                       uint64_t timestamp_ns,
                       uint16_t direction,
                       uint16_t api,
                       uint32_t function) {
    if (!b || !xniff_record_type_matches_api(type, api) ||
        (direction != XNIFF_DIRECTION_ENTRY &&
         direction != XNIFF_DIRECTION_EXIT)) {
        errno = EINVAL;
        return -1;
    }
    b->len = 0;
    size_t base = sizeof(xniff_record_header_t) + sizeof(xniff_record_fixed_header_t);
    if (ensure_cap(b, base) != 0) return -1;

    xniff_record_header_t h = {0};
    h.length = (uint32_t)base;
    h.type = type;
    h.version = XNIFF_RECORD_VERSION;
    h.sequence = __atomic_add_fetch(&g_sequence, 1, __ATOMIC_RELAXED);
    memcpy(b->buf, &h, sizeof(h));

    xniff_record_fixed_header_t fh = {0};
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

int xniff_record_add_section(xniff_record_builder_t *b,
                             uint16_t type,
                             uint16_t flags,
                             const void *payload,
                             size_t payload_len) {
    size_t base = sizeof(xniff_record_header_t) + sizeof(xniff_record_fixed_header_t);
    if (!b || !b->buf || b->len < base) return -1;
    if (payload_len > UINT32_MAX) return -1;
    if (payload_len != 0 && !payload) return -1;

    size_t need = b->len + sizeof(xniff_record_section_header_t) + payload_len;
    if (ensure_cap(b, need) != 0) return -1;

    xniff_record_section_header_t sh = {0};
    sh.type = type;
    sh.flags = flags;
    sh.length = (uint32_t)payload_len;

    memcpy(b->buf + b->len, &sh, sizeof(sh));
    b->len += sizeof(sh);
    if (payload_len != 0) {
        memcpy(b->buf + b->len, payload, payload_len);
        b->len += payload_len;
    }
    return 0;
}

int xniff_record_finish(xniff_record_builder_t *b,
                        const uint8_t **data,
                        size_t *length) {
    size_t base = sizeof(xniff_record_header_t) + sizeof(xniff_record_fixed_header_t);
    if (!b || !b->buf || b->len < base || !data || !length) return -1;
    if (b->len > UINT32_MAX) return -1;

    xniff_record_header_t *h = (xniff_record_header_t *)b->buf;
    h->length = (uint32_t)b->len;
    if (h->version != XNIFF_RECORD_VERSION) {
        errno = EINVAL;
        return -1;
    }
    *data = b->buf;
    *length = b->len;
    return 0;
}

void xniff_record_section_iterator_init(
    xniff_record_section_iterator_t *iterator,
    const void *sections,
    size_t length) {
    if (!iterator) return;
    iterator->cursor = (const uint8_t *)sections;
    iterator->remaining = sections ? length : 0;
}

int xniff_record_section_next(xniff_record_section_iterator_t *iterator,
                              xniff_record_section_t *section) {
    if (!iterator || !section) return -1;
    if (iterator->remaining == 0) return 0;
    if (!iterator->cursor ||
        iterator->remaining < sizeof(xniff_record_section_header_t)) {
        return -1;
    }

    xniff_record_section_header_t header = {0};
    memcpy(&header, iterator->cursor, sizeof(header));
    size_t framed_length = sizeof(header) + (size_t)header.length;
    if (framed_length > iterator->remaining) return -1;

    section->type = header.type;
    section->flags = header.flags;
    section->data = iterator->cursor + sizeof(header);
    section->length = header.length;
    iterator->cursor += framed_length;
    iterator->remaining -= framed_length;
    return 1;
}
