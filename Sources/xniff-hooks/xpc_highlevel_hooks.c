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
#include <execinfo.h>

#include <xpc/xpc.h>
#include <mach/mach_vm.h>

#include "../shared/xniff_payload.h"
#include "../shared/xniff_transport.h"
#include "../shared/xniff_record.h"
#include "xniff_hooks_emit.h"
#include "xniff_hooks_backtrace.h"

enum {
    XNIFF_XPC_STR_MAX = 16384u,
    XNIFF_XPC_SERIAL_DEFAULT_MAX = 256u * 1024u,
    XNIFF_XPC_SERIAL_ABS_MAX = 512u * 1024u,
    XNIFF_XPC_SERIAL_FLAG_TRUNCATED = 1u,
};

typedef void *(*xniff_xpc_make_serialization_fn)(xpc_object_t obj, size_t *len_out);
typedef const char *(*xniff_xpc_conn_get_name_fn)(xpc_connection_t conn);
typedef uint32_t (*xniff_xpc_conn_get_u32_fn)(xpc_connection_t conn);
typedef void (*xniff_xpc_conn_get_audit_token_fn)(xpc_connection_t conn, uint32_t token[8]);
typedef xpc_connection_t (*xniff_xpc_dictionary_get_remote_connection_fn)(xpc_object_t dictionary);

typedef struct {
    uint8_t slot;
    uint8_t format;
    uint16_t flags;
    uint32_t original_len;
    uint32_t stored_len;
    uint8_t *bytes;
} xniff_xpc_serial_blob_t;

typedef struct {
    xniff_xpc_conn_meta_t md;
    const char *name_public;
    const char *name_private;
} xniff_xpc_conn_meta_capture_t;

static pthread_once_t g_serial_once = PTHREAD_ONCE_INIT;
static xniff_xpc_make_serialization_fn g_xpc_make_serialization = NULL;
static bool g_xpc_serial_enabled = true;
static uint32_t g_xpc_serial_max = XNIFF_XPC_SERIAL_DEFAULT_MAX;

static xniff_xpc_conn_get_u32_fn g_xpc_connection_get_pid = NULL;
static xniff_xpc_conn_get_u32_fn g_xpc_connection_get_pid_private = NULL;
static xniff_xpc_conn_get_name_fn g_xpc_connection_get_name = NULL;
static xniff_xpc_conn_get_u32_fn g_xpc_connection_get_euid = NULL;
static xniff_xpc_conn_get_u32_fn g_xpc_connection_get_egid = NULL;
static xniff_xpc_conn_get_u32_fn g_xpc_connection_get_asid = NULL;
static xniff_xpc_conn_get_audit_token_fn g_xpc_connection_get_audit_token = NULL;
static xniff_xpc_dictionary_get_remote_connection_fn g_xpc_dictionary_get_remote_connection = NULL;

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

static void *xniff_dlsym_with_alias(const char *name) {
    if (!name || !*name) return NULL;
    void *p = dlsym(RTLD_DEFAULT, name);
    if (p) return p;
    if (name[0] == '_') {
        p = dlsym(RTLD_DEFAULT, name + 1);
    } else {
        char alt[256];
        int n = snprintf(alt, sizeof(alt), "_%s", name);
        if (n > 0 && (size_t)n < sizeof(alt)) {
            p = dlsym(RTLD_DEFAULT, alt);
        }
    }
    return p;
}

static void *xniff_require_libxpc_symbol(void *sym) {
    if (!sym) return NULL;
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (dladdr(sym, &info) == 0) return NULL;
    if (!info.dli_fname) return NULL;
    if (strstr(info.dli_fname, "libxpc") == NULL) return NULL;
    return sym;
}

static void xniff_xpc_serial_init_once(void) {
    g_xpc_serial_enabled = xniff_env_enabled_default_true("XNIFF_XPC_SERIALIZE");
    g_xpc_serial_max = xniff_env_u32("XNIFF_XPC_SERIAL_MAX",
                                     XNIFF_XPC_SERIAL_DEFAULT_MAX,
                                     XNIFF_XPC_SERIAL_ABS_MAX);
    if (g_xpc_serial_max == 0) g_xpc_serial_enabled = false;
    g_xpc_make_serialization =
        (xniff_xpc_make_serialization_fn)xniff_dlsym_with_alias("xpc_make_serialization");

    g_xpc_connection_get_pid =
        (xniff_xpc_conn_get_u32_fn)xniff_dlsym_with_alias("xpc_connection_get_pid");
    g_xpc_connection_get_pid_private =
        (xniff_xpc_conn_get_u32_fn)xniff_require_libxpc_symbol(
            xniff_dlsym_with_alias("_xpc_connection_get_pid"));
    g_xpc_connection_get_name =
        (xniff_xpc_conn_get_name_fn)xniff_dlsym_with_alias("xpc_connection_get_name");
    g_xpc_connection_get_euid =
        (xniff_xpc_conn_get_u32_fn)xniff_dlsym_with_alias("xpc_connection_get_euid");
    g_xpc_connection_get_egid =
        (xniff_xpc_conn_get_u32_fn)xniff_dlsym_with_alias("xpc_connection_get_egid");
    g_xpc_connection_get_asid =
        (xniff_xpc_conn_get_u32_fn)xniff_dlsym_with_alias("xpc_connection_get_asid");
    g_xpc_connection_get_audit_token =
        (xniff_xpc_conn_get_audit_token_fn)xniff_require_libxpc_symbol(
            xniff_dlsym_with_alias("xpc_connection_get_audit_token"));
    g_xpc_dictionary_get_remote_connection =
        (xniff_xpc_dictionary_get_remote_connection_fn)xniff_dlsym_with_alias(
            "xpc_dictionary_get_remote_connection");
}

static bool xniff_ptr_readable(const void *p) {
    if (!p) return false;
    uintptr_t u = (uintptr_t)p;
    if (u < 0x1000u) return false;
    uint64_t tmp = 0;
    mach_vm_size_t out = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(),
                                              (mach_vm_address_t)u,
                                              (mach_vm_size_t)sizeof(tmp),
                                              (mach_vm_address_t)(uintptr_t)&tmp,
                                              &out);
    return (kr == KERN_SUCCESS && out == (mach_vm_size_t)sizeof(tmp));
}

static inline uint32_t xniff_strnlen_u32(const char *s, uint32_t maxlen) {
    if (!s) return 0;
    size_t n = strnlen(s, (size_t)maxlen);
    return (uint32_t)n;
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

static bool xniff_capture_xpc_conn_meta(xpc_connection_t conn, xniff_xpc_conn_meta_capture_t *out) {
    if (!conn || !out) return false;
    (void)pthread_once(&g_serial_once, xniff_xpc_serial_init_once);
    if (!xniff_ptr_readable((const void *)conn)) return false;

    memset(out, 0, sizeof(*out));
    out->md.version = XNIFF_XPC_CONN_META_VERSION;

    if (g_xpc_connection_get_name) {
        out->name_public = g_xpc_connection_get_name(conn);
        out->md.name_public_len = xniff_strnlen_u32(out->name_public, XNIFF_XPC_STR_MAX);
        if (out->md.name_public_len != 0) out->md.flags |= XNIFF_XPC_CONN_META_HAS_NAME_PUBLIC;
    }

    if (g_xpc_connection_get_pid) {
        out->md.pid_public = g_xpc_connection_get_pid(conn);
        out->md.flags |= XNIFF_XPC_CONN_META_HAS_PID_PUBLIC;
    }
    if (g_xpc_connection_get_pid_private) {
        out->md.pid_private = g_xpc_connection_get_pid_private(conn);
        out->md.flags |= XNIFF_XPC_CONN_META_HAS_PID_PRIVATE;
    }
    if (g_xpc_connection_get_euid) {
        out->md.euid_public = g_xpc_connection_get_euid(conn);
        out->md.flags |= XNIFF_XPC_CONN_META_HAS_EUID_PUBLIC;
    }
    if (g_xpc_connection_get_egid) {
        out->md.egid_public = g_xpc_connection_get_egid(conn);
        out->md.flags |= XNIFF_XPC_CONN_META_HAS_EGID_PUBLIC;
    }
    if (g_xpc_connection_get_asid) {
        out->md.asid_public = g_xpc_connection_get_asid(conn);
        out->md.flags |= XNIFF_XPC_CONN_META_HAS_ASID_PUBLIC;
    }
    if (g_xpc_connection_get_audit_token) {
        g_xpc_connection_get_audit_token(conn, out->md.audit_token);
        uint32_t combined = 0;
        for (size_t i = 0; i < 8; i++) combined |= out->md.audit_token[i];
        if (combined != 0) out->md.flags |= XNIFF_XPC_CONN_META_HAS_AUDIT_TOKEN;
    }

    return out->md.flags != 0;
}

static void ipc_send_xpc_event_ex(
    const xniff_xpc_payload_t *pl_in,
    const char *s0, uint32_t l0,
    const char *s1, uint32_t l1,
    const char *s2, uint32_t l2,
    const char *s3, uint32_t l3,
    const xniff_xpc_serial_blob_t *serial_blobs,
    size_t serial_blob_count,
    const xniff_xpc_conn_meta_capture_t *conn_meta,
    const xniff_xpc_object_ref_t *object_ref)
{
    if (!xniff_hooks_capture_mode_enabled(XNIFF_CAPTURE_MODE_XPC)) return;
    if (!pl_in) return;
    xniff_record_builder_t b;
    xniff_record_builder_init(&b);

    if (xniff_record_begin(&b,
                           XNIFF_RECORD_TYPE_XPC,
                           (uint32_t)getpid(),
                           (uint32_t)(uintptr_t)pthread_self(),
                           0,
                           (uint16_t)pl_in->direction,
                           XNIFF_API_XPC,
                           pl_in->func) != 0) {
        xniff_record_builder_free(&b);
        return;
    }

    xniff_xpc_payload_t pl = *pl_in;
    pl.str0_len = l0;
    pl.str1_len = l1;
    pl.str2_len = l2;
    pl.str3_len = l3;
    size_t call_len = sizeof(pl) + (size_t)l0 + (size_t)l1 + (size_t)l2 + (size_t)l3;
    uint8_t *call_sec = (uint8_t *)malloc(call_len);
    if (!call_sec) {
        xniff_record_builder_free(&b);
        return;
    }
    memcpy(call_sec, &pl, sizeof(pl));
    size_t off = sizeof(pl);
    if (l0 && s0) { memcpy(call_sec + off, s0, l0); off += l0; }
    if (l1 && s1) { memcpy(call_sec + off, s1, l1); off += l1; }
    if (l2 && s2) { memcpy(call_sec + off, s2, l2); off += l2; }
    if (l3 && s3) { memcpy(call_sec + off, s3, l3); off += l3; }
    (void)xniff_record_add_section(&b, XNIFF_SECTION_XPC_CALL_META, 0, call_sec, off);
    free(call_sec);
    uint64_t call_id = xniff_hooks_current_call_id();
    if (call_id != 0) {
        (void)xniff_record_add_section(&b, XNIFF_SECTION_CALL_ID, 0, &call_id, sizeof(call_id));
    }
    xniff_hooks_add_backtrace(&b);

    for (size_t i = 0; i < serial_blob_count; i++) {
        const xniff_xpc_serial_blob_t *sb = &serial_blobs[i];
        if (!sb->bytes || sb->stored_len == 0) continue;
        size_t sec_len = sizeof(xniff_xpc_serialized_t) + (size_t)sb->stored_len;
        uint8_t *sec = (uint8_t *)malloc(sec_len);
        if (!sec) continue;
        xniff_xpc_serialized_t md = {0};
        md.slot = sb->slot;
        md.format = sb->format;
        md.flags = sb->flags;
        md.original_len = sb->original_len;
        md.stored_len = sb->stored_len;
        memcpy(sec, &md, sizeof(md));
        memcpy(sec + sizeof(md), sb->bytes, sb->stored_len);
        (void)xniff_record_add_section(&b, XNIFF_SECTION_XPC_SERIALIZED, 0, sec, sec_len);
        free(sec);
    }

    if (conn_meta && conn_meta->md.flags != 0) {
        size_t sec_len = sizeof(conn_meta->md) +
                         (size_t)conn_meta->md.name_public_len +
                         (size_t)conn_meta->md.name_private_len;
        uint8_t *sec = (uint8_t *)malloc(sec_len);
        if (sec) {
            memcpy(sec, &conn_meta->md, sizeof(conn_meta->md));
            size_t so = sizeof(conn_meta->md);
            if (conn_meta->md.name_public_len != 0 && conn_meta->name_public) {
                memcpy(sec + so, conn_meta->name_public, conn_meta->md.name_public_len);
                so += conn_meta->md.name_public_len;
            }
            if (conn_meta->md.name_private_len != 0 && conn_meta->name_private) {
                memcpy(sec + so, conn_meta->name_private, conn_meta->md.name_private_len);
                so += conn_meta->md.name_private_len;
            }
            (void)xniff_record_add_section(&b, XNIFF_SECTION_XPC_CONN_META, 0, sec, so);
            free(sec);
        }
    }

    if (object_ref && object_ref->object != 0) {
        (void)xniff_record_add_section(&b, XNIFF_SECTION_XPC_OBJECT_REF, 0,
                                       object_ref, sizeof(*object_ref));
    }

    (void)xniff_hooks_write_record(&b);
    xniff_record_builder_free(&b);
}

static void ipc_send_xpc_event(
    const xniff_xpc_payload_t *pl_in,
    const char *s0, uint32_t l0,
    const char *s1, uint32_t l1,
    const char *s2, uint32_t l2,
    const char *s3, uint32_t l3)
{
    ipc_send_xpc_event_ex(pl_in, s0, l0, s1, l1, s2, l2, s3, l3,
                          NULL, 0, NULL, NULL);
}

static xniff_xpc_object_ref_t xniff_object_ref(uint16_t object_kind,
                                                uint16_t lifecycle,
                                                uint64_t object) {
    xniff_xpc_object_ref_t ref = {0};
    ref.version = XNIFF_XPC_OBJECT_REF_VERSION;
    ref.kind = object_kind;
    ref.lifecycle = lifecycle;
    ref.object = object;
    return ref;
}

static uint32_t xniff_conn_meta_peer_pid(const xniff_xpc_conn_meta_capture_t *capture) {
    if (!capture) return 0;
    const xniff_xpc_conn_meta_t *md = &capture->md;
    if ((md->flags & XNIFF_XPC_CONN_META_HAS_PID_PUBLIC) && md->pid_public != 0) {
        return md->pid_public;
    }
    if ((md->flags & XNIFF_XPC_CONN_META_HAS_PID_PRIVATE) && md->pid_private != 0) {
        return md->pid_private;
    }
    if (md->flags & XNIFF_XPC_CONN_META_HAS_AUDIT_TOKEN) {
        return md->audit_token[5];
    }
    return 0;
}

static inline void pl_init_from_args(xniff_xpc_payload_t *pl, uint32_t func, uint32_t direction, uint64_t ret, const uint64_t args[8]) {
    memset(pl, 0, sizeof(*pl));
    pl->api = XNIFF_API_XPC;
    pl->direction = direction;
    pl->func = func;
    pl->ret_value = ret;
    if (args) {
        for (int i = 0; i < 8; i++) pl->args[i] = args[i];
    }
}

void xniff_emit_xpc_connection_create_entry(const uint64_t args[8]) {
    xniff_emit_xpc_named_create_entry(XNIFF_XPC_FUNC_CONNECTION_CREATE, args);
}

void xniff_emit_xpc_connection_create_exit(uint64_t ret, const uint64_t args[8]) {
    xniff_emit_xpc_connection_create_exit_for_function(
        XNIFF_XPC_FUNC_CONNECTION_CREATE, ret, args);
}

void xniff_emit_xpc_named_create_entry(uint32_t function, const uint64_t args[8]) {
    const char *name = (const char *)(uintptr_t)(args ? args[0] : 0);
    uint32_t name_len = xniff_strnlen_u32(name, XNIFF_XPC_STR_MAX);

    xniff_xpc_payload_t pl;
    pl_init_from_args(&pl, function, XNIFF_DIRECTION_ENTRY, 0, args);
    ipc_send_xpc_event(&pl, name, name_len,
                       NULL, 0, NULL, 0, NULL, 0);
}

static bool xniff_create_function_has_name(uint32_t function) {
    return function == XNIFF_XPC_FUNC_CONNECTION_CREATE ||
           function == XNIFF_XPC_FUNC_CONNECTION_CREATE_MACH_SERVICE ||
           function == XNIFF_XPC_FUNC_SESSION_CREATE_XPC_SERVICE ||
           function == XNIFF_XPC_FUNC_SESSION_CREATE_MACH_SERVICE;
}

void xniff_emit_xpc_connection_create_exit_for_function(uint32_t function, uint64_t ret,
                                                        const uint64_t args[8]) {
    xpc_connection_t conn = (xpc_connection_t)(uintptr_t)ret;
    xniff_xpc_conn_meta_capture_t conn_meta;
    bool has_conn_meta = xniff_capture_xpc_conn_meta(conn, &conn_meta);
    const char *cname = (has_conn_meta && conn_meta.name_public) ? conn_meta.name_public : NULL;
    if (!cname && xniff_create_function_has_name(function)) {
        cname = (const char *)(uintptr_t)(args ? args[0] : 0);
    }
    uint32_t l0 = xniff_strnlen_u32(cname, XNIFF_XPC_STR_MAX);

    xniff_xpc_payload_t pl;
    pl_init_from_args(&pl, function, XNIFF_DIRECTION_EXIT, ret, args);
    pl.conn_pid = xniff_conn_meta_peer_pid(has_conn_meta ? &conn_meta : NULL);
    xniff_xpc_object_ref_t ref = xniff_object_ref(
        XNIFF_XPC_OBJECT_CONNECTION, XNIFF_XPC_OBJECT_CREATED, ret);
    ipc_send_xpc_event_ex(&pl, cname, l0, NULL, 0, NULL, 0, NULL, 0,
                          NULL, 0, has_conn_meta ? &conn_meta : NULL, &ref);
}

void xniff_emit_xpc_session_create_exit(uint32_t function, uint64_t ret,
                                        const uint64_t args[8]) {
    const char *name = xniff_create_function_has_name(function)
        ? (const char *)(uintptr_t)(args ? args[0] : 0)
        : NULL;
    uint32_t name_len = xniff_strnlen_u32(name, XNIFF_XPC_STR_MAX);
    xniff_xpc_payload_t pl;
    pl_init_from_args(&pl, function, XNIFF_DIRECTION_EXIT, ret, args);
    xniff_xpc_object_ref_t ref = xniff_object_ref(
        XNIFF_XPC_OBJECT_SESSION, XNIFF_XPC_OBJECT_CREATED, ret);
    ipc_send_xpc_event_ex(&pl, name, name_len,
                          NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, &ref);
}

void xniff_emit_xpc_connection_lifecycle(uint32_t function, uint32_t direction, uint64_t ret,
                                         const uint64_t args[8], uint16_t lifecycle) {
    xpc_connection_t conn = (xpc_connection_t)(uintptr_t)(args ? args[0] : 0);
    xniff_xpc_conn_meta_capture_t conn_meta;
    bool has_conn_meta = xniff_capture_xpc_conn_meta(conn, &conn_meta);
    const char *name = (has_conn_meta && conn_meta.name_public) ? conn_meta.name_public : NULL;
    uint32_t name_len = xniff_strnlen_u32(name, XNIFF_XPC_STR_MAX);
    xniff_xpc_payload_t pl;
    pl_init_from_args(&pl, function, direction, ret, args);
    pl.conn_pid = xniff_conn_meta_peer_pid(has_conn_meta ? &conn_meta : NULL);
    xniff_xpc_object_ref_t ref = xniff_object_ref(
        XNIFF_XPC_OBJECT_CONNECTION, lifecycle, (uint64_t)(uintptr_t)conn);
    ipc_send_xpc_event_ex(&pl, name, name_len, NULL, 0, NULL, 0, NULL, 0,
                          NULL, 0, has_conn_meta ? &conn_meta : NULL, &ref);
}

void xniff_emit_xpc_session_lifecycle(uint32_t function, uint32_t direction, uint64_t ret,
                                      const uint64_t args[8], uint16_t lifecycle) {
    uint64_t session = args ? args[0] : 0;
    xniff_xpc_payload_t pl;
    pl_init_from_args(&pl, function, direction, ret, args);
    xniff_xpc_object_ref_t ref = xniff_object_ref(
        XNIFF_XPC_OBJECT_SESSION, lifecycle, session);
    ipc_send_xpc_event_ex(&pl, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                          NULL, 0, NULL, &ref);
}

void xniff_emit_xpc_pipe_routine_entry(const uint64_t args[8]) {
    xpc_object_t in_obj = (xpc_object_t)(uintptr_t)(args ? args[1] : 0);

    xniff_xpc_payload_t pl;
    pl_init_from_args(&pl, XNIFF_XPC_FUNC_PIPE_ROUTINE, XNIFF_DIRECTION_ENTRY, 0, args);
    xniff_xpc_serial_blob_t blob;
    bool has_blob = xniff_capture_xpc_serialized(in_obj, XNIFF_XPC_SERIAL_SLOT_MESSAGE, &blob);
    ipc_send_xpc_event_ex(&pl, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                          has_blob ? &blob : NULL, has_blob ? 1u : 0u, NULL, NULL);
    if (has_blob) xniff_xpc_serial_blob_free(&blob);
}

void xniff_emit_xpc_pipe_routine_exit(uint64_t ret, const uint64_t args[8]) {
    xpc_object_t reply = NULL;
    const void *reply_out = (const void *)(uintptr_t)(args ? args[2] : 0);
    if (reply_out) {
        mach_vm_size_t copied = 0;
        (void)mach_vm_read_overwrite(mach_task_self(),
                                     (mach_vm_address_t)(uintptr_t)reply_out,
                                     (mach_vm_size_t)sizeof(reply),
                                     (mach_vm_address_t)(uintptr_t)&reply,
                                     &copied);
        if (copied != (mach_vm_size_t)sizeof(reply)) reply = NULL;
    }

    xniff_xpc_payload_t pl;
    pl_init_from_args(&pl, XNIFF_XPC_FUNC_PIPE_ROUTINE, XNIFF_DIRECTION_EXIT, ret, args);
    xniff_xpc_serial_blob_t blob;
    bool has_blob = xniff_capture_xpc_serialized(reply, XNIFF_XPC_SERIAL_SLOT_REPLY, &blob);
    ipc_send_xpc_event_ex(&pl, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                          has_blob ? &blob : NULL, has_blob ? 1u : 0u, NULL, NULL);
    if (has_blob) xniff_xpc_serial_blob_free(&blob);
}

static void send_message_event_args(uint32_t direction, uint32_t func,
                                    uint64_t ret, const uint64_t args[8],
                                    bool include_reply_desc, bool connection_metadata) {
    xpc_connection_t conn = (xpc_connection_t)(uintptr_t)(args ? args[0] : 0);
    xpc_object_t msg = (xpc_object_t)(uintptr_t)(args ? args[1] : 0);
    xpc_object_t reply = include_reply_desc ? (xpc_object_t)(uintptr_t)ret : NULL;

    xniff_xpc_conn_meta_capture_t conn_meta;
    bool has_conn_meta = connection_metadata && xniff_capture_xpc_conn_meta(conn, &conn_meta);
    const char *cname = (has_conn_meta && conn_meta.name_public) ? conn_meta.name_public : NULL;
    uint32_t l0 = xniff_strnlen_u32(cname, XNIFF_XPC_STR_MAX);

    xniff_xpc_payload_t pl;
    pl_init_from_args(&pl, func, direction, ret, args);
    pl.conn_pid = xniff_conn_meta_peer_pid(has_conn_meta ? &conn_meta : NULL);

    xniff_xpc_serial_blob_t blobs[2];
    size_t blob_count = 0;
    if (xniff_capture_xpc_serialized(msg, XNIFF_XPC_SERIAL_SLOT_MESSAGE, &blobs[blob_count])) {
        blob_count++;
    }
    if (include_reply_desc &&
        xniff_capture_xpc_serialized(reply, XNIFF_XPC_SERIAL_SLOT_REPLY, &blobs[blob_count])) {
        blob_count++;
    }

    bool is_session = func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE ||
                      func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC ||
                      func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC;
    xniff_xpc_object_ref_t ref = xniff_object_ref(
        is_session ? XNIFF_XPC_OBJECT_SESSION : XNIFF_XPC_OBJECT_CONNECTION,
        XNIFF_XPC_OBJECT_OBSERVED, (uint64_t)(uintptr_t)conn);
    ipc_send_xpc_event_ex(&pl, cname, l0, NULL, 0, NULL, 0, NULL, 0,
                          blobs, blob_count, has_conn_meta ? &conn_meta : NULL, &ref);

    for (size_t i = 0; i < blob_count; i++) xniff_xpc_serial_blob_free(&blobs[i]);
}

void xniff_emit_xpc_connection_send_message_entry(const uint64_t args[8]) {
    send_message_event_args(XNIFF_DIRECTION_ENTRY, XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE, 0, args, false, true);
}

void xniff_emit_xpc_connection_send_message_with_reply_entry(const uint64_t args[8]) {
    send_message_event_args(XNIFF_DIRECTION_ENTRY, XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY, 0, args, false, true);
}

void xniff_emit_xpc_connection_send_message_with_reply_async_response(uint64_t reply,
                                                                       const uint64_t args[8]) {
    send_message_event_args(XNIFF_DIRECTION_EXIT,
                            XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY,
                            reply, args, true, true);
}

void xniff_emit_xpc_connection_send_message_with_reply_sync_entry(const uint64_t args[8]) {
    send_message_event_args(XNIFF_DIRECTION_ENTRY, XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC, 0, args, false, true);
}

void xniff_emit_xpc_connection_send_message_with_reply_sync_exit(uint64_t ret, const uint64_t args[8]) {
    send_message_event_args(XNIFF_DIRECTION_EXIT, XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC, ret, args, true, true);
}

void xniff_emit_xpc_dictionary_send_reply_entry(const uint64_t args[8]) {
    xpc_object_t reply = (xpc_object_t)(uintptr_t)(args ? args[0] : 0);
    (void)pthread_once(&g_serial_once, xniff_xpc_serial_init_once);
    xpc_connection_t conn = g_xpc_dictionary_get_remote_connection
        ? g_xpc_dictionary_get_remote_connection(reply)
        : NULL;
    xniff_xpc_conn_meta_capture_t conn_meta;
    bool has_conn_meta = xniff_capture_xpc_conn_meta(conn, &conn_meta);
    const char *name = (has_conn_meta && conn_meta.name_public) ? conn_meta.name_public : NULL;
    uint32_t name_len = xniff_strnlen_u32(name, XNIFF_XPC_STR_MAX);
    xniff_xpc_payload_t pl;
    pl_init_from_args(&pl, XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY, XNIFF_DIRECTION_ENTRY, 0, args);
    pl.conn_pid = xniff_conn_meta_peer_pid(has_conn_meta ? &conn_meta : NULL);
    xniff_xpc_serial_blob_t blob;
    bool has_blob = xniff_capture_xpc_serialized(reply, XNIFF_XPC_SERIAL_SLOT_REPLY, &blob);
    xniff_xpc_object_ref_t ref = xniff_object_ref(
        XNIFF_XPC_OBJECT_CONNECTION, XNIFF_XPC_OBJECT_OBSERVED,
        (uint64_t)(uintptr_t)conn);
    ipc_send_xpc_event_ex(&pl, name, name_len,
                          NULL, 0, NULL, 0, NULL, 0,
                          has_blob ? &blob : NULL, has_blob ? 1u : 0u,
                          has_conn_meta ? &conn_meta : NULL, &ref);
    if (has_blob) xniff_xpc_serial_blob_free(&blob);
}

void xniff_emit_xpc_session_send_message_entry(const uint64_t args[8]) {
    send_message_event_args(XNIFF_DIRECTION_ENTRY,
                            XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE, 0, args, false, false);
}

void xniff_emit_xpc_session_send_message_with_reply_async_entry(const uint64_t args[8]) {
    send_message_event_args(XNIFF_DIRECTION_ENTRY,
                            XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC,
                            0, args, false, false);
}

void xniff_emit_xpc_session_send_message_with_reply_async_response(uint64_t reply, uint64_t error,
                                                                    const uint64_t args[8]) {
    uint64_t callback_args[8] = {0};
    if (args) memcpy(callback_args, args, sizeof(callback_args));
    // The request belongs to the caller and may no longer be live when an
    // asynchronous response arrives. The response remains correlated by the
    // hook call ID, so never attempt to serialize the stale request pointer.
    callback_args[1] = 0;
    callback_args[3] = error;
    uint64_t response = reply != 0 ? reply : error;
    send_message_event_args(XNIFF_DIRECTION_EXIT,
                            XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC,
                            response, callback_args, true, false);
}

void xniff_emit_xpc_session_send_message_with_reply_sync_entry(const uint64_t args[8]) {
    send_message_event_args(XNIFF_DIRECTION_ENTRY,
                            XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC,
                            0, args, false, false);
}

void xniff_emit_xpc_session_send_message_with_reply_sync_exit(uint64_t ret, const uint64_t args[8]) {
    uint64_t response = ret;
    if (response == 0 && args && args[2] != 0) {
        xpc_object_t error = NULL;
        mach_vm_size_t copied = 0;
        (void)mach_vm_read_overwrite(mach_task_self(),
                                     (mach_vm_address_t)args[2],
                                     (mach_vm_size_t)sizeof(error),
                                     (mach_vm_address_t)(uintptr_t)&error,
                                     &copied);
        if (copied == (mach_vm_size_t)sizeof(error)) {
            response = (uint64_t)(uintptr_t)error;
        }
    }
    send_message_event_args(XNIFF_DIRECTION_EXIT,
                            XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC,
                            response, args, true, false);
}

void xniff_emit_xpc_connection_call_event_handler_entry(const uint64_t args[8]) {
    xniff_xpc_payload_t pl;
    pl_init_from_args(&pl, XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER, XNIFF_DIRECTION_ENTRY, 0, args);
    // This is a private libxpc internal. Avoid walking event internals directly; only
    // capture serialized bytes and best-effort connection metadata via getters.
    xpc_connection_t dispatch_conn = (xpc_connection_t)(uintptr_t)(args ? args[0] : 0);
    xpc_object_t event = (xpc_object_t)(uintptr_t)(args ? args[1] : 0);
    bool event_is_connection = event && xpc_get_type(event) == XPC_TYPE_CONNECTION;
    xpc_connection_t attributed_conn = event_is_connection
        ? (xpc_connection_t)event
        : dispatch_conn;
    xniff_xpc_conn_meta_capture_t conn_meta;
    bool has_conn_meta = xniff_capture_xpc_conn_meta(attributed_conn, &conn_meta);
    xniff_xpc_conn_meta_capture_t listener_meta;
    bool has_listener_meta = event_is_connection &&
        xniff_capture_xpc_conn_meta(dispatch_conn, &listener_meta);
    const char *name = has_listener_meta && listener_meta.name_public
        ? listener_meta.name_public
        : (has_conn_meta ? conn_meta.name_public : NULL);
    uint32_t name_len = xniff_strnlen_u32(name, XNIFF_XPC_STR_MAX);
    pl.conn_pid = xniff_conn_meta_peer_pid(has_conn_meta ? &conn_meta : NULL);
    xniff_xpc_serial_blob_t blob;
    bool has_blob = !event_is_connection &&
        xniff_capture_xpc_serialized(event, XNIFF_XPC_SERIAL_SLOT_EVENT, &blob);
    xniff_xpc_object_ref_t ref = xniff_object_ref(
        XNIFF_XPC_OBJECT_CONNECTION,
        event_is_connection ? XNIFF_XPC_OBJECT_CREATED : XNIFF_XPC_OBJECT_OBSERVED,
        (uint64_t)(uintptr_t)attributed_conn);
    ipc_send_xpc_event_ex(&pl, name, name_len,
                          NULL, 0, NULL, 0, NULL, 0,
                          has_blob ? &blob : NULL, has_blob ? 1u : 0u,
                          has_conn_meta ? &conn_meta : NULL, &ref);
    if (has_blob) xniff_xpc_serial_blob_free(&blob);
}

static void send_connection_meta_event_args(uint32_t direction, uint32_t func,
                                            uint64_t ret, const uint64_t args[8]) {
    xpc_connection_t conn = (xpc_connection_t)(uintptr_t)(args ? args[0] : 0);
    xniff_xpc_conn_meta_capture_t conn_meta;
    bool has_conn_meta = xniff_capture_xpc_conn_meta(conn, &conn_meta);
    const char *cname = (has_conn_meta && conn_meta.name_public) ? conn_meta.name_public : NULL;
    uint32_t l0 = xniff_strnlen_u32(cname, XNIFF_XPC_STR_MAX);

    xniff_xpc_payload_t pl;
    pl_init_from_args(&pl, func, direction, ret, args);
    pl.conn_pid = xniff_conn_meta_peer_pid(has_conn_meta ? &conn_meta : NULL);
    xniff_xpc_object_ref_t ref = xniff_object_ref(
        XNIFF_XPC_OBJECT_CONNECTION, XNIFF_XPC_OBJECT_OBSERVED,
        (uint64_t)(uintptr_t)conn);

    ipc_send_xpc_event_ex(&pl, cname, l0, NULL, 0, NULL, 0, NULL, 0,
                          NULL, 0, has_conn_meta ? &conn_meta : NULL, &ref);
}

void xniff_emit_xpc_connection_check_in_entry(const uint64_t args[8]) {
    send_connection_meta_event_args(XNIFF_DIRECTION_ENTRY,
                                    XNIFF_XPC_FUNC_CONNECTION_CHECK_IN, 0, args);
}

void xniff_emit_xpc_connection_check_in_exit(uint64_t ret, const uint64_t args[8]) {
    send_connection_meta_event_args(XNIFF_DIRECTION_EXIT,
                                    XNIFF_XPC_FUNC_CONNECTION_CHECK_IN, ret, args);
}
