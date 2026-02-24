// xniff-hooks: high-level libxpc helpers used by Frida Gum interceptors.

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <errno.h>

#include <xpc/xpc.h>

#include "../shared/xniff_ipc.h"
#include "xniff_hooks_emit.h"
#include "xniff_hooks_ipc.h"

enum {
    XNIFF_XPC_STR_MAX = 16384u,
    XNIFF_XPC_SERIAL_DEFAULT_MAX = 16384u,
    XNIFF_XPC_SERIAL_ABS_MAX = 512u * 1024u,
    XNIFF_XPC_SERIAL_FLAG_TRUNCATED = 1u,
};

typedef void *(*xniff_xpc_make_serialization_fn)(xpc_object_t obj, size_t *len_out);

typedef struct {
    uint8_t slot;
    uint8_t format;
    uint16_t flags;
    uint32_t original_len;
    uint32_t stored_len;
    uint8_t *bytes;
} xniff_xpc_serial_blob_t;

static pthread_once_t g_serial_once = PTHREAD_ONCE_INIT;
static xniff_xpc_make_serialization_fn g_xpc_make_serialization = NULL;
static bool g_xpc_serial_enabled = true;
static uint32_t g_xpc_serial_max = XNIFF_XPC_SERIAL_DEFAULT_MAX;

static bool xniff_env_enabled_default_true(const char *name) {
    if (!name || !*name) return true;
    const char *v = getenv(name);
    if (!v || !*v) return true;
    if (strcmp(v, "0") == 0) return false;
    if (strcasecmp(v, "false") == 0) return false;
    if (strcasecmp(v, "no") == 0) return false;
    return true;
}

static uint32_t xniff_env_u32(const char *name, uint32_t defv, uint32_t maxv) {
    if (!name || !*name) return defv;
    const char *s = getenv(name);
    if (!s || !*s) return defv;
    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 0);
    if (errno != 0 || end == s) return defv;
    if (v > maxv) return maxv;
    return (uint32_t)v;
}

static void xniff_xpc_serial_init_once(void) {
    g_xpc_serial_enabled = xniff_env_enabled_default_true("XNIFF_XPC_SERIALIZE");
    g_xpc_serial_max = xniff_env_u32("XNIFF_XPC_SERIAL_MAX",
                                     XNIFF_XPC_SERIAL_DEFAULT_MAX,
                                     XNIFF_XPC_SERIAL_ABS_MAX);
    if (g_xpc_serial_max == 0) g_xpc_serial_enabled = false;
    g_xpc_make_serialization =
        (xniff_xpc_make_serialization_fn)dlsym(RTLD_DEFAULT, "xpc_make_serialization");
}

static inline uint32_t xniff_strnlen_u32(const char *s, uint32_t maxlen) {
    if (!s) return 0;
    size_t n = strnlen(s, (size_t)maxlen);
    return (uint32_t)n;
}

static char *xniff_xpc_desc(xpc_object_t obj, uint32_t *len_out) {
    if (len_out) *len_out = 0;
    if (!obj) return NULL;
    char *s = xpc_copy_description(obj);
    if (!s) return NULL;
    uint32_t n = xniff_strnlen_u32(s, XNIFF_XPC_STR_MAX);
    if (len_out) *len_out = n;
    return s; // free() by caller
}

static char *xniff_ptr_desc(uint64_t ptr, uint32_t *len_out) {
    if (len_out) *len_out = 0;
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ptr);
    if (n <= 0) return NULL;
    size_t m = (size_t)n;
    char *s = (char *)malloc(m + 1);
    if (!s) return NULL;
    memcpy(s, buf, m);
    s[m] = '\0';
    if (len_out) *len_out = (uint32_t)m;
    return s;
}

static void xniff_xpc_serial_blob_free(xniff_xpc_serial_blob_t *b) {
    if (!b) return;
    if (b->bytes) free(b->bytes);
    memset(b, 0, sizeof(*b));
}

static bool xniff_capture_xpc_serialized(xpc_object_t obj, uint8_t slot, xniff_xpc_serial_blob_t *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!obj) return false;

    (void)pthread_once(&g_serial_once, xniff_xpc_serial_init_once);
    if (!g_xpc_serial_enabled || !g_xpc_make_serialization) return false;

    size_t full_len = 0;
    void *full = g_xpc_make_serialization(obj, &full_len);
    if (!full || full_len == 0) {
        if (full) free(full);
        return false;
    }

    size_t keep = full_len;
    uint16_t flags = 0;
    if (keep > (size_t)g_xpc_serial_max) {
        keep = (size_t)g_xpc_serial_max;
        flags |= XNIFF_XPC_SERIAL_FLAG_TRUNCATED;
    }
    if (keep > (size_t)UINT32_MAX) keep = (size_t)UINT32_MAX;

    uint8_t *buf = (uint8_t *)malloc(keep);
    if (!buf) {
        free(full);
        return false;
    }
    memcpy(buf, full, keep);
    free(full);

    out->slot = slot;
    out->format = XNIFF_XPC_SERIAL_FORMAT_LIBXPC_V5;
    out->flags = flags;
    out->original_len = (full_len > (size_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)full_len;
    out->stored_len = (uint32_t)keep;
    out->bytes = buf;
    return true;
}

static void ipc_send_xpc_event_ex(
    uint16_t kind,
    const xniff_ipc_xpc_payload_t *pl_in,
    const char *s0, uint32_t l0,
    const char *s1, uint32_t l1,
    const char *s2, uint32_t l2,
    const char *s3, uint32_t l3,
    const xniff_xpc_serial_blob_t *serial_blobs,
    size_t serial_blob_count)
{
    if (!pl_in) return;

    uint64_t payload_len = (uint64_t)sizeof(*pl_in) + l0 + l1 + l2 + l3;
    for (size_t i = 0; i < serial_blob_count; i++) {
        const xniff_xpc_serial_blob_t *b = &serial_blobs[i];
        if (!b->bytes || b->stored_len == 0) continue;
        uint64_t ext_len = (uint64_t)sizeof(xniff_ipc_tlv_t) +
                           (uint64_t)sizeof(xniff_xpc_serialized_t) +
                           (uint64_t)b->stored_len;
        payload_len += ext_len;
    }
    if (payload_len > UINT32_MAX) return;

    xniff_hooks_ipc_lock();

    xniff_ipc_hdr_t hdr = {0};
    hdr.magic = XNIFF_IPC_MAGIC;
    hdr.version = XNIFF_IPC_VERSION;
    hdr.kind = kind;
    hdr.pid = (uint32_t)getpid();
    hdr.tid_low = (uint32_t)(uintptr_t)pthread_self();
    hdr.payload_len = (uint32_t)payload_len;

    xniff_ipc_xpc_payload_t pl = *pl_in;
    pl.str0_len = l0;
    pl.str1_len = l1;
    pl.str2_len = l2;
    pl.str3_len = l3;

    if (xniff_hooks_ipc_write_locked(&hdr, sizeof(hdr)) != 0) { xniff_hooks_ipc_unlock(); return; }
    if (xniff_hooks_ipc_write_locked(&pl, sizeof(pl)) != 0)   { xniff_hooks_ipc_unlock(); return; }

    if (l0 && s0) if (xniff_hooks_ipc_write_locked(s0, l0) != 0) { xniff_hooks_ipc_unlock(); return; }
    if (l1 && s1) if (xniff_hooks_ipc_write_locked(s1, l1) != 0) { xniff_hooks_ipc_unlock(); return; }
    if (l2 && s2) if (xniff_hooks_ipc_write_locked(s2, l2) != 0) { xniff_hooks_ipc_unlock(); return; }
    if (l3 && s3) if (xniff_hooks_ipc_write_locked(s3, l3) != 0) { xniff_hooks_ipc_unlock(); return; }

    for (size_t i = 0; i < serial_blob_count; i++) {
        const xniff_xpc_serial_blob_t *b = &serial_blobs[i];
        if (!b->bytes || b->stored_len == 0) continue;
        if ((uint64_t)sizeof(xniff_xpc_serialized_t) + (uint64_t)b->stored_len > UINT32_MAX) continue;

        xniff_ipc_tlv_t tlv = {0};
        tlv.type = XNIFF_TLV_XPC_SERIALIZED;
        tlv.length = (uint32_t)(sizeof(xniff_xpc_serialized_t) + b->stored_len);
        if (xniff_hooks_ipc_write_locked(&tlv, sizeof(tlv)) != 0) { xniff_hooks_ipc_unlock(); return; }

        xniff_xpc_serialized_t md = {0};
        md.slot = b->slot;
        md.format = b->format;
        md.flags = b->flags;
        md.original_len = b->original_len;
        md.stored_len = b->stored_len;
        if (xniff_hooks_ipc_write_locked(&md, sizeof(md)) != 0) { xniff_hooks_ipc_unlock(); return; }
        if (xniff_hooks_ipc_write_locked(b->bytes, b->stored_len) != 0) { xniff_hooks_ipc_unlock(); return; }
    }

    xniff_hooks_ipc_unlock();
}

static void ipc_send_xpc_event(
    uint16_t kind,
    const xniff_ipc_xpc_payload_t *pl_in,
    const char *s0, uint32_t l0,
    const char *s1, uint32_t l1,
    const char *s2, uint32_t l2,
    const char *s3, uint32_t l3)
{
    ipc_send_xpc_event_ex(kind, pl_in, s0, l0, s1, l1, s2, l2, s3, l3, NULL, 0);
}

static inline void pl_init_from_args(xniff_ipc_xpc_payload_t *pl, uint32_t func, uint32_t direction, uint64_t ret, const uint64_t args[8]) {
    memset(pl, 0, sizeof(*pl));
    pl->api = XNIFF_API_XPC_HL;
    pl->direction = direction;
    pl->func = func;
    pl->ret_value = ret;
    if (args) {
        for (int i = 0; i < 8; i++) pl->args[i] = args[i];
    }
}

void xniff_emit_xpc_connection_create_entry(const uint64_t args[8]) {
    const char *name = (const char *)(uintptr_t)(args ? args[0] : 0);
    uint32_t l0 = xniff_strnlen_u32(name, XNIFF_XPC_STR_MAX);

    xniff_ipc_xpc_payload_t pl;
    pl_init_from_args(&pl, XNIFF_XPC_FUNC_CONNECTION_CREATE, XNIFF_DIR_ENTRY, 0, args);
    ipc_send_xpc_event(XNIFF_EVT_XPC_ENTRY, &pl, name, l0, NULL, 0, NULL, 0, NULL, 0);
}

void xniff_emit_xpc_connection_create_exit(uint64_t ret, const uint64_t args[8]) {
    xpc_connection_t conn = (xpc_connection_t)(uintptr_t)ret;
    const char *cname = conn ? xpc_connection_get_name(conn) : NULL;
    uint32_t l0 = xniff_strnlen_u32(cname, XNIFF_XPC_STR_MAX);
    uint32_t l1 = 0;
    char *cdesc = xniff_xpc_desc(conn, &l1);

    xniff_ipc_xpc_payload_t pl;
    pl_init_from_args(&pl, XNIFF_XPC_FUNC_CONNECTION_CREATE, XNIFF_DIR_EXIT, ret, args);
    if (conn) pl.conn_pid = (uint32_t)xpc_connection_get_pid(conn);
    ipc_send_xpc_event(XNIFF_EVT_XPC_EXIT, &pl, cname, l0, cdesc, l1, NULL, 0, NULL, 0);
    if (cdesc) free(cdesc);
}

void xniff_emit_xpc_pipe_routine_entry(const uint64_t args[8]) {
    uint64_t pipe_ptr = (args ? args[0] : 0);
    xpc_object_t in_obj = (xpc_object_t)(uintptr_t)(args ? args[1] : 0);

    uint32_t l0 = 0, l1 = 0;
    char *pdesc = xniff_ptr_desc(pipe_ptr, &l0);
    char *idesc = xniff_xpc_desc(in_obj, &l1);

    xniff_ipc_xpc_payload_t pl;
    pl_init_from_args(&pl, XNIFF_XPC_FUNC_PIPE_ROUTINE, XNIFF_DIR_ENTRY, 0, args);
    xniff_xpc_serial_blob_t blob;
    bool has_blob = xniff_capture_xpc_serialized(in_obj, XNIFF_XPC_SERIAL_SLOT_MESSAGE, &blob);
    ipc_send_xpc_event_ex(XNIFF_EVT_XPC_ENTRY, &pl, pdesc, l0, idesc, l1, NULL, 0, NULL, 0,
                          has_blob ? &blob : NULL, has_blob ? 1u : 0u);
    if (has_blob) xniff_xpc_serial_blob_free(&blob);
    if (pdesc) free(pdesc);
    if (idesc) free(idesc);
}

void xniff_emit_xpc_pipe_routine_exit(uint64_t ret, const uint64_t args[8]) {
    uint64_t pipe_ptr = (args ? args[0] : 0);
    xpc_object_t in_obj = (xpc_object_t)(uintptr_t)(args ? args[1] : 0);
    uint64_t out_ptr = (args ? args[2] : 0);

    uint32_t l0 = 0, l1 = 0, l2 = 0;
    char *pdesc = xniff_ptr_desc(pipe_ptr, &l0);
    char *idesc = xniff_xpc_desc(in_obj, &l1);
    char *odesc = xniff_ptr_desc(out_ptr, &l2);

    xniff_ipc_xpc_payload_t pl;
    pl_init_from_args(&pl, XNIFF_XPC_FUNC_PIPE_ROUTINE, XNIFF_DIR_EXIT, ret, args);
    xniff_xpc_serial_blob_t blob;
    bool has_blob = xniff_capture_xpc_serialized(in_obj, XNIFF_XPC_SERIAL_SLOT_MESSAGE, &blob);
    ipc_send_xpc_event_ex(XNIFF_EVT_XPC_EXIT, &pl, pdesc, l0, idesc, l1, odesc, l2, NULL, 0,
                          has_blob ? &blob : NULL, has_blob ? 1u : 0u);
    if (has_blob) xniff_xpc_serial_blob_free(&blob);
    if (pdesc) free(pdesc);
    if (idesc) free(idesc);
    if (odesc) free(odesc);
}

static void send_connection_message_event_args(uint16_t kind, uint32_t direction, uint32_t func, uint64_t ret, const uint64_t args[8], bool include_reply_desc) {
    xpc_connection_t conn = (xpc_connection_t)(uintptr_t)(args ? args[0] : 0);
    xpc_object_t msg = (xpc_object_t)(uintptr_t)(args ? args[1] : 0);
    xpc_object_t reply = include_reply_desc ? (xpc_object_t)(uintptr_t)ret : NULL;

    const char *cname = conn ? xpc_connection_get_name(conn) : NULL;
    uint32_t l0 = xniff_strnlen_u32(cname, XNIFF_XPC_STR_MAX);

    uint32_t l1 = 0, l2 = 0, l3 = 0;
    char *mdesc = xniff_xpc_desc(msg, &l1);
    char *cdesc = xniff_xpc_desc((xpc_object_t)conn, &l2);
    char *rdesc = xniff_xpc_desc(reply, &l3);

    xniff_ipc_xpc_payload_t pl;
    pl_init_from_args(&pl, func, direction, ret, args);
    if (conn) pl.conn_pid = (uint32_t)xpc_connection_get_pid(conn);

    xniff_xpc_serial_blob_t blobs[2];
    size_t blob_count = 0;
    if (xniff_capture_xpc_serialized(msg, XNIFF_XPC_SERIAL_SLOT_MESSAGE, &blobs[blob_count])) {
        blob_count++;
    }
    if (include_reply_desc &&
        xniff_capture_xpc_serialized(reply, XNIFF_XPC_SERIAL_SLOT_REPLY, &blobs[blob_count])) {
        blob_count++;
    }

    ipc_send_xpc_event_ex(kind, &pl, cname, l0, mdesc, l1, cdesc, l2, rdesc, l3, blobs, blob_count);

    for (size_t i = 0; i < blob_count; i++) xniff_xpc_serial_blob_free(&blobs[i]);

    if (mdesc) free(mdesc);
    if (cdesc) free(cdesc);
    if (rdesc) free(rdesc);
}

void xniff_emit_xpc_connection_send_message_entry(const uint64_t args[8]) {
    send_connection_message_event_args(XNIFF_EVT_XPC_ENTRY, XNIFF_DIR_ENTRY, XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE, 0, args, false);
}

void xniff_emit_xpc_connection_send_message_with_reply_entry(const uint64_t args[8]) {
    send_connection_message_event_args(XNIFF_EVT_XPC_ENTRY, XNIFF_DIR_ENTRY, XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY, 0, args, false);
}

void xniff_emit_xpc_connection_send_message_with_reply_sync_entry(const uint64_t args[8]) {
    send_connection_message_event_args(XNIFF_EVT_XPC_ENTRY, XNIFF_DIR_ENTRY, XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC, 0, args, false);
}

void xniff_emit_xpc_connection_send_message_with_reply_sync_exit(uint64_t ret, const uint64_t args[8]) {
    send_connection_message_event_args(XNIFF_EVT_XPC_EXIT, XNIFF_DIR_EXIT, XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC, ret, args, true);
}

void xniff_emit_xpc_connection_call_event_handler_entry(const uint64_t args[8]) {
    xniff_ipc_xpc_payload_t pl;
    pl_init_from_args(&pl, XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER, XNIFF_DIR_ENTRY, 0, args);
    // This is a private libxpc internal. Avoid dereferencing conn/msg pointers here to keep
    // hook-side behavior conservative across OS updates.
    xpc_object_t event = (xpc_object_t)(uintptr_t)(args ? args[1] : 0);
    xniff_xpc_serial_blob_t blob;
    bool has_blob = xniff_capture_xpc_serialized(event, XNIFF_XPC_SERIAL_SLOT_EVENT, &blob);
    ipc_send_xpc_event_ex(XNIFF_EVT_XPC_ENTRY, &pl, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                          has_blob ? &blob : NULL, has_blob ? 1u : 0u);
    if (has_blob) xniff_xpc_serial_blob_free(&blob);
}

void xniff_emit_xpc_connection_call_event_handler_exit(uint64_t ret, const uint64_t args[8]) {
    xniff_ipc_xpc_payload_t pl;
    pl_init_from_args(&pl, XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER, XNIFF_DIR_EXIT, ret, args);
    xpc_object_t event = (xpc_object_t)(uintptr_t)(args ? args[1] : 0);
    xniff_xpc_serial_blob_t blob;
    bool has_blob = xniff_capture_xpc_serialized(event, XNIFF_XPC_SERIAL_SLOT_EVENT, &blob);
    ipc_send_xpc_event_ex(XNIFF_EVT_XPC_EXIT, &pl, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                          has_blob ? &blob : NULL, has_blob ? 1u : 0u);
    if (has_blob) xniff_xpc_serial_blob_free(&blob);
}
