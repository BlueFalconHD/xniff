#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../shared/mach_private.h"
#include "../shared/xniff_ipc.h"
#include "../shared/xniff_ipc_v2.h"
#include "record_renderer.h"

static FILE *xniff_diag_stream(void) {
    return stderr;
}

#define XNIFF_DIAGF(...) fprintf(xniff_diag_stream(), __VA_ARGS__)

static void format_time(char *buf, size_t sz, double *mono_s_out) {
    struct timespec ts_rt = {0}, ts_mono = {0};
#ifdef CLOCK_REALTIME
    clock_gettime(CLOCK_REALTIME, &ts_rt);
#else
    struct timeval tv; gettimeofday(&tv, NULL); ts_rt.tv_sec = tv.tv_sec; ts_rt.tv_nsec = tv.tv_usec*1000;
#endif
#ifdef CLOCK_MONOTONIC_RAW
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts_mono);
#elif defined(CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, &ts_mono);
#else
    ts_mono = ts_rt;
#endif
    struct tm tm; time_t t = (time_t)ts_rt.tv_sec; localtime_r(&t, &tm);
    int n = (int)strftime(buf, sz, "%F %T", &tm);
    if (n > 0 && (size_t)n < sz) {
        snprintf(buf + n, sz - (size_t)n, ".%03ld", ts_rt.tv_nsec/1000000);
    }
    if (mono_s_out) *mono_s_out = (double)ts_mono.tv_sec + (double)ts_mono.tv_nsec/1e9;
}

static uint16_t v2_kind_from_fixed(const xniff_ipc_v2_fixed_hdr_t *fh) {
    if (!fh) return 0;
    if (fh->api == XNIFF_API_XPC_HL) {
        return (fh->direction == XNIFF_DIR_EXIT) ? XNIFF_EVT_XPC_EXIT : XNIFF_EVT_XPC_ENTRY;
    }
    if (fh->api == XNIFF_API_MACH_MSG) {
        return (fh->direction == XNIFF_DIR_EXIT) ? XNIFF_EVT_MACH_EXIT : XNIFF_EVT_MACH_ENTRY;
    }
    if (fh->api == XNIFF_API_MACH_MSG2) {
        return (fh->direction == XNIFF_DIR_EXIT) ? XNIFF_EVT_MACH2_EXIT : XNIFF_EVT_MACH2_ENTRY;
    }
    if (fh->api == XNIFF_API_DEBUG) {
        return XNIFF_EVT_DEBUG_LOG;
    }
    return 0;
}

static const char *proc_name_cached(pid_t pid);

typedef struct xniff_conn_meta {
    uint32_t owner_pid;
    uint16_t object_kind;
    uint64_t conn_ptr;
    uint32_t peer_pid;
    char service[256];
    uint64_t next_seq;
    unsigned long long last_recv_event_id;
    uint32_t last_recv_tid_low;
    double last_recv_mono_s;
    struct xniff_conn_meta *next;
} xniff_conn_meta_t;

typedef struct {
    const char *flow;             // send / recv / rpc / meta
    const char *role;             // request / response / incoming / one-way / metadata
    const char *peer_role;        // sender / recipient / unknown
    uint64_t call_id;
    uint64_t conn_ptr;
    uint64_t msg_ptr;
    uint64_t conn_seq;
    unsigned long long response_to_event_id;
    const char *service_name;
    uint32_t peer_pid;
    const char *peer_name;
} xniff_xpc_analysis_t;

typedef struct {
    bool present;
    uint8_t slot;
    uint8_t format;
    uint16_t flags;
    uint32_t original_len;
    uint32_t stored_len;
    const uint8_t *bytes;
} xniff_xpc_serial_item_t;

typedef struct {
    xniff_xpc_serial_item_t message;
    xniff_xpc_serial_item_t reply;
    xniff_xpc_serial_item_t event;
} xniff_xpc_serialized_set_t;

typedef struct {
    bool present;
    xniff_xpc_conn_meta_t meta;
    char *name_public;
    char *name_private;
} xniff_xpc_conn_meta_item_t;

typedef struct {
    bool present;
    xniff_xpc_object_ref_t ref;
} xniff_xpc_object_ref_item_t;

static xniff_conn_meta_t *g_conn_meta = NULL;

static bool str_nonempty(const char *s) {
    return s && *s;
}

static void str_copy_trunc(char *dst, size_t dst_sz, const char *src) {
    if (!dst || dst_sz == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, src, dst_sz - 1);
    dst[dst_sz - 1] = '\0';
}

static uint64_t xpc_conn_ptr_for_event(const xniff_ipc_hdr_t *ihdr, const xniff_ipc_xpc_payload_t *pl) {
    if (!ihdr || !pl) return 0;
    if (pl->func == XNIFF_XPC_FUNC_CONNECTION_CREATE ||
        pl->func == XNIFF_XPC_FUNC_CONNECTION_CREATE_MACH_SERVICE ||
        pl->func == XNIFF_XPC_FUNC_CONNECTION_CREATE_FROM_ENDPOINT ||
        pl->func == XNIFF_XPC_FUNC_ARRAY_CREATE_CONNECTION ||
        pl->func == XNIFF_XPC_FUNC_DICTIONARY_CREATE_CONNECTION ||
        pl->func == XNIFF_XPC_FUNC_SESSION_CREATE_XPC_SERVICE ||
        pl->func == XNIFF_XPC_FUNC_SESSION_CREATE_MACH_SERVICE) {
        if (ihdr->kind == XNIFF_EVT_XPC_EXIT && pl->ret_value != 0) return pl->ret_value;
        return 0;
    }
    return pl->args[0];
}

static uint64_t xpc_msg_ptr_for_event(const xniff_ipc_xpc_payload_t *pl) {
    if (!pl) return 0;
    if (pl->func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE ||
        pl->func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY ||
        pl->func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC ||
        pl->func == XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER ||
        pl->func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE ||
        pl->func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC ||
        pl->func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC) {
        return pl->args[1];
    }
    if (pl->func == XNIFF_XPC_FUNC_PIPE_ROUTINE) {
        return pl->args[1];
    }
    return 0;
}

static const char *xpc_flow_for_event(const xniff_ipc_xpc_payload_t *pl) {
    if (!pl) return "unknown";
    switch (pl->func) {
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE:
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY:
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC:
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE:
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC:
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC:
            return "send";
        case XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER:
            return "recv";
        case XNIFF_XPC_FUNC_PIPE_ROUTINE:
            return "rpc";
        case XNIFF_XPC_FUNC_CONNECTION_CREATE:
        case XNIFF_XPC_FUNC_CONNECTION_CREATE_MACH_SERVICE:
        case XNIFF_XPC_FUNC_CONNECTION_CREATE_FROM_ENDPOINT:
        case XNIFF_XPC_FUNC_ARRAY_CREATE_CONNECTION:
        case XNIFF_XPC_FUNC_DICTIONARY_CREATE_CONNECTION:
        case XNIFF_XPC_FUNC_SESSION_CREATE_XPC_SERVICE:
        case XNIFF_XPC_FUNC_SESSION_CREATE_MACH_SERVICE:
        case XNIFF_XPC_FUNC_CONNECTION_ACTIVATE:
        case XNIFF_XPC_FUNC_CONNECTION_RESUME:
        case XNIFF_XPC_FUNC_CONNECTION_CANCEL:
        case XNIFF_XPC_FUNC_SESSION_ACTIVATE:
        case XNIFF_XPC_FUNC_SESSION_CANCEL:
            return "meta";
        case XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY:
            return "reply";
    }
    return "unknown";
}

static const char *xpc_role_for_event(const xniff_ipc_xpc_payload_t *pl) {
    if (!pl) return "unknown";
    switch (pl->func) {
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY:
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC:
            return pl->direction == XNIFF_DIR_ENTRY ? "request" : "response";
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC:
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC:
        case XNIFF_XPC_FUNC_PIPE_ROUTINE:
            return pl->direction == XNIFF_DIR_ENTRY ? "request" : "response";
        case XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY:
            return "response";
        case XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER:
            return "incoming";
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE:
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE:
            return "one-way";
        default:
            return "metadata";
    }
}

static const char *xpc_peer_role_for_flow(const char *flow) {
    if (!flow) return "unknown";
    if (strcmp(flow, "send") == 0) return "recipient";
    if (strcmp(flow, "recv") == 0) return "sender";
    if (strcmp(flow, "reply") == 0) return "requester";
    return "unknown";
}

static xniff_conn_meta_t *conn_meta_find_or_create(uint32_t owner_pid, uint16_t object_kind,
                                                   uint64_t conn_ptr, bool create) {
    if (conn_ptr == 0) return NULL;
    xniff_conn_meta_t *m = g_conn_meta;
    while (m) {
        if (m->owner_pid == owner_pid && m->object_kind == object_kind &&
            m->conn_ptr == conn_ptr) return m;
        m = m->next;
    }
    if (!create) return NULL;
    m = (xniff_conn_meta_t *)calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->owner_pid = owner_pid;
    m->object_kind = object_kind;
    m->conn_ptr = conn_ptr;
    m->next = g_conn_meta;
    g_conn_meta = m;
    return m;
}

static void analyze_xpc_event(
    unsigned long long event_id,
    const xniff_ipc_hdr_t *ihdr,
    const xniff_ipc_xpc_payload_t *pl,
    const char *s0,
    const xniff_xpc_object_ref_item_t *object_ref,
    double mono_s,
    xniff_xpc_analysis_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));

    if (!ihdr || !pl) {
        out->flow = "unknown";
        out->peer_role = "unknown";
        return;
    }

    out->flow = xpc_flow_for_event(pl);
    out->role = xpc_role_for_event(pl);
    out->peer_role = xpc_peer_role_for_flow(out->flow);
    out->conn_ptr = object_ref && object_ref->present
        ? object_ref->ref.object
        : xpc_conn_ptr_for_event(ihdr, pl);
    out->msg_ptr = xpc_msg_ptr_for_event(pl);

    uint16_t object_kind = object_ref && object_ref->present
        ? object_ref->ref.kind
        : XNIFF_XPC_OBJECT_CONNECTION;
    xniff_conn_meta_t *m = conn_meta_find_or_create(
        ihdr->pid, object_kind, out->conn_ptr, out->conn_ptr != 0);
    if (m) {
        if (pl->conn_pid != 0) m->peer_pid = pl->conn_pid;
        if (str_nonempty(s0)) str_copy_trunc(m->service, sizeof(m->service), s0);

        if (ihdr->kind == XNIFF_EVT_XPC_ENTRY) {
            if (strcmp(out->flow, "send") == 0 || strcmp(out->flow, "recv") == 0 || strcmp(out->flow, "rpc") == 0) {
                m->next_seq++;
                out->conn_seq = m->next_seq;
            } else {
                out->conn_seq = m->next_seq;
            }
        } else {
            out->conn_seq = m->next_seq;
        }

        out->peer_pid = (m->peer_pid != 0) ? m->peer_pid : pl->conn_pid;
        out->service_name = str_nonempty(m->service) ? m->service : NULL;
    } else {
        out->peer_pid = pl->conn_pid;
        out->service_name = str_nonempty(s0) ? s0 : NULL;
    }

    out->peer_name = (out->peer_pid != 0) ? proc_name_cached((pid_t)out->peer_pid) : NULL;
}

static const char *xpc_serial_slot_name(uint8_t slot) {
    switch (slot) {
        case XNIFF_XPC_SERIAL_SLOT_MESSAGE: return "message";
        case XNIFF_XPC_SERIAL_SLOT_REPLY:   return "reply";
        case XNIFF_XPC_SERIAL_SLOT_EVENT:   return "event";
    }
    return "unknown";
}

static const char *xpc_serial_format_name(uint8_t format) {
    switch (format) {
        case XNIFF_XPC_SERIAL_FORMAT_LIBXPC_V5: return "libxpc_v5";
    }
    return "unknown";
}

static xniff_xpc_serial_item_t *xpc_serial_item_for_slot(xniff_xpc_serialized_set_t *xs, uint8_t slot) {
    if (!xs) return NULL;
    switch (slot) {
        case XNIFF_XPC_SERIAL_SLOT_MESSAGE: return &xs->message;
        case XNIFF_XPC_SERIAL_SLOT_REPLY:   return &xs->reply;
        case XNIFF_XPC_SERIAL_SLOT_EVENT:   return &xs->event;
    }
    return NULL;
}

static void xpc_serialized_init(xniff_xpc_serialized_set_t *xs) {
    if (!xs) return;
    memset(xs, 0, sizeof(*xs));
}

static void xpc_serialized_free(xniff_xpc_serialized_set_t *xs) {
    if (!xs) return;
    memset(xs, 0, sizeof(*xs));
}

static void xpc_conn_meta_init(xniff_xpc_conn_meta_item_t *cm) {
    if (!cm) return;
    memset(cm, 0, sizeof(*cm));
}

static void xpc_conn_meta_free(xniff_xpc_conn_meta_item_t *cm) {
    if (!cm) return;
    if (cm->name_public) free(cm->name_public);
    if (cm->name_private) free(cm->name_private);
    memset(cm, 0, sizeof(*cm));
}

static void xpc_parse_section(uint16_t sec_type,
                              const uint8_t *val,
                              size_t val_len,
                              xniff_xpc_serialized_set_t *xs,
                              xniff_xpc_conn_meta_item_t *cm,
                              xniff_xpc_object_ref_item_t *object_ref) {
    if (!val || !xs) return;
    if (sec_type == XNIFF_V2_SEC_XPC_SERIALIZED && val_len >= sizeof(xniff_xpc_serialized_t)) {
        xniff_xpc_serialized_t md = {0};
        memcpy(&md, val, sizeof(md));
        size_t bytes_avail = val_len - sizeof(md);
        size_t stored = md.stored_len;
        if (stored > bytes_avail) stored = bytes_avail;

        xniff_xpc_serial_item_t *dst = xpc_serial_item_for_slot(xs, md.slot);
        if (!dst) return;

        dst->present = true;
        dst->slot = md.slot;
        dst->format = md.format;
        dst->flags = md.flags;
        dst->original_len = md.original_len;
        dst->stored_len = (uint32_t)stored;
        dst->bytes = val + sizeof(md);
        return;
    }

    if (cm && sec_type == XNIFF_V2_SEC_XPC_CONN_META && val_len >= sizeof(xniff_xpc_conn_meta_t)) {
        xniff_xpc_conn_meta_t md = {0};
        memcpy(&md, val, sizeof(md));
        size_t str_off = sizeof(md);
        cm->present = true;
        cm->meta = md;

        if (cm->name_public) { free(cm->name_public); cm->name_public = NULL; }
        if (cm->name_private) { free(cm->name_private); cm->name_private = NULL; }

        if (md.name_public_len != 0 && str_off + md.name_public_len <= val_len) {
            cm->name_public = (char *)malloc((size_t)md.name_public_len + 1);
            if (cm->name_public) {
                memcpy(cm->name_public, val + str_off, md.name_public_len);
                cm->name_public[md.name_public_len] = '\0';
            }
            str_off += md.name_public_len;
        }
        if (md.name_private_len != 0 && str_off + md.name_private_len <= val_len) {
            cm->name_private = (char *)malloc((size_t)md.name_private_len + 1);
            if (cm->name_private) {
                memcpy(cm->name_private, val + str_off, md.name_private_len);
                cm->name_private[md.name_private_len] = '\0';
            }
        }
        return;
    }

    if (object_ref && sec_type == XNIFF_V2_SEC_XPC_OBJECT_REF &&
        val_len >= sizeof(xniff_xpc_object_ref_t)) {
        xniff_xpc_object_ref_t ref = {0};
        memcpy(&ref, val, sizeof(ref));
        if (ref.version == XNIFF_XPC_OBJECT_REF_VERSION && ref.object != 0) {
            object_ref->present = true;
            object_ref->ref = ref;
        }
    }
}

typedef struct {
    pid_t pid;
    char name[128];
} pid_name_cache_entry_t;

static pid_name_cache_entry_t g_pid_name_cache[128];
static size_t g_pid_name_cache_next = 0;

static const char *proc_name_cached(pid_t pid) {
    if (pid <= 0) return NULL;

    for (size_t i = 0; i < sizeof(g_pid_name_cache) / sizeof(g_pid_name_cache[0]); i++) {
        if (g_pid_name_cache[i].pid == pid && g_pid_name_cache[i].name[0] != '\0') {
            return g_pid_name_cache[i].name;
        }
    }

    char tmp[128];
    memset(tmp, 0, sizeof(tmp));
    int n = proc_name(pid, tmp, (uint32_t)sizeof(tmp));
    if (n <= 0) return NULL;
    tmp[sizeof(tmp) - 1] = '\0';

    pid_name_cache_entry_t *e =
        &g_pid_name_cache[g_pid_name_cache_next++ % (sizeof(g_pid_name_cache) / sizeof(g_pid_name_cache[0]))];
    e->pid = pid;
    strncpy(e->name, tmp, sizeof(e->name) - 1);
    e->name[sizeof(e->name) - 1] = '\0';
    return e->name;
}

static bool mach_extract_sender_pid_from_trailer(const uint8_t *msg, size_t msg_len, uint32_t msgh_size, uint32_t *pid_out) {
    if (!pid_out) return false;
    *pid_out = 0;
    if (!msg || msg_len < sizeof(mach_msg_header_t)) return false;
    if (msgh_size < (uint32_t)sizeof(mach_msg_header_t)) return false;

    size_t off = (size_t)round_msg(msgh_size);
    if (off + sizeof(mach_msg_trailer_t) > msg_len) return false;

    mach_msg_trailer_t t;
    memcpy(&t, msg + off, sizeof(t));
    if (t.msgh_trailer_size < sizeof(mach_msg_trailer_t)) return false;
    if (off + (size_t)t.msgh_trailer_size > msg_len) return false;

    // Audit trailer (or larger) includes an audit_token_t with the sender pid.
    if ((size_t)t.msgh_trailer_size < sizeof(mach_msg_audit_trailer_t)) return false;

    mach_msg_audit_trailer_t at;
    memcpy(&at, msg + off, sizeof(at));

    // audit_token_t is opaque; pid is commonly stored in val[5].
    uint32_t pid = at.msgh_audit.val[5];
    if (pid == 0 || pid == UINT32_MAX) return false;
    *pid_out = pid;
    return true;
}

static void append_hook_debug_log(uint32_t pid, uint32_t tid_low,
                                  const char *tbuf, double mono_s,
                                  const char *line) {
    if (!line || !*line) return;
    char path[128];
    snprintf(path, sizeof(path), "/tmp/xniff-hooks-%d.log", (int)pid);
    FILE *fp = fopen(path, "a");
    if (!fp) return;
    fprintf(fp, "[%s][+%0.6fs][tid=0x%x] %s\n",
            tbuf ? tbuf : "?", mono_s, tid_low, line);
    fclose(fp);
}

static const char *xpc_func_to_name(uint32_t func) {
    switch (func) {
        case XNIFF_XPC_FUNC_CONNECTION_CREATE: return "xpc_connection_create";
        case XNIFF_XPC_FUNC_PIPE_ROUTINE: return "xpc_pipe_routine";
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE: return "xpc_connection_send_message";
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY: return "xpc_connection_send_message_with_reply";
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC: return "xpc_connection_send_message_with_reply_sync";
        case XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER: return "_xpc_connection_call_event_handler";
        case XNIFF_XPC_FUNC_CONNECTION_CHECK_IN: return "_xpc_connection_check_in";
        case XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY: return "xpc_dictionary_send_reply";
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE: return "xpc_session_send_message";
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC: return "xpc_session_send_message_with_reply_async";
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC: return "xpc_session_send_message_with_reply_sync";
        case XNIFF_XPC_FUNC_CONNECTION_CREATE_MACH_SERVICE: return "xpc_connection_create_mach_service";
        case XNIFF_XPC_FUNC_CONNECTION_CREATE_FROM_ENDPOINT: return "xpc_connection_create_from_endpoint";
        case XNIFF_XPC_FUNC_ARRAY_CREATE_CONNECTION: return "xpc_array_create_connection";
        case XNIFF_XPC_FUNC_DICTIONARY_CREATE_CONNECTION: return "xpc_dictionary_create_connection";
        case XNIFF_XPC_FUNC_SESSION_CREATE_XPC_SERVICE: return "xpc_session_create_xpc_service";
        case XNIFF_XPC_FUNC_SESSION_CREATE_MACH_SERVICE: return "xpc_session_create_mach_service";
        case XNIFF_XPC_FUNC_CONNECTION_ACTIVATE: return "xpc_connection_activate";
        case XNIFF_XPC_FUNC_CONNECTION_RESUME: return "xpc_connection_resume";
        case XNIFF_XPC_FUNC_CONNECTION_CANCEL: return "xpc_connection_cancel";
        case XNIFF_XPC_FUNC_SESSION_ACTIVATE: return "xpc_session_activate";
        case XNIFF_XPC_FUNC_SESSION_CANCEL: return "xpc_session_cancel";
    }
    return "unknown";
}

typedef struct {
    const char *slot_name[4];
} xpc_string_schema_t;

static xpc_string_schema_t xpc_string_schema_for_event(uint16_t kind, uint32_t func) {
    xpc_string_schema_t sc = {{NULL, NULL, NULL, NULL}};
    switch (func) {
        case XNIFF_XPC_FUNC_CONNECTION_CREATE:
        case XNIFF_XPC_FUNC_CONNECTION_CREATE_MACH_SERVICE:
        case XNIFF_XPC_FUNC_SESSION_CREATE_XPC_SERVICE:
        case XNIFF_XPC_FUNC_SESSION_CREATE_MACH_SERVICE:
            if (kind == XNIFF_EVT_XPC_ENTRY) {
                sc.slot_name[0] = "target_service_name";
            } else {
                sc.slot_name[0] = "connection_name";
                sc.slot_name[1] = "connection_description";
            }
            break;
        case XNIFF_XPC_FUNC_PIPE_ROUTINE:
            sc.slot_name[0] = "pipe_description";
            sc.slot_name[1] = "request_description";
            if (kind == XNIFF_EVT_XPC_EXIT) sc.slot_name[2] = "reply_description";
            break;
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE:
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY:
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC:
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE:
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC:
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC:
            sc.slot_name[0] = "connection_name";
            sc.slot_name[1] = "message_description";
            sc.slot_name[2] = "connection_description";
            if (kind == XNIFF_EVT_XPC_EXIT) sc.slot_name[3] = "reply_description";
            break;
        case XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER:
            // no string slots are currently captured in the hook layer
            break;
    }
    return sc;
}

static const char *xpc_arg_name(uint32_t func, size_t idx) {
    switch (func) {
        case XNIFF_XPC_FUNC_CONNECTION_CREATE:
        case XNIFF_XPC_FUNC_CONNECTION_CREATE_MACH_SERVICE:
        case XNIFF_XPC_FUNC_SESSION_CREATE_XPC_SERVICE:
        case XNIFF_XPC_FUNC_SESSION_CREATE_MACH_SERVICE:
            if (idx == 0) return "service_name_ptr";
            if (idx == 1) return "target_queue_ptr";
            return NULL;
        case XNIFF_XPC_FUNC_CONNECTION_CREATE_FROM_ENDPOINT:
            if (idx == 0) return "endpoint_ptr";
            return NULL;
        case XNIFF_XPC_FUNC_ARRAY_CREATE_CONNECTION:
            if (idx == 0) return "array_ptr";
            if (idx == 1) return "index";
            return NULL;
        case XNIFF_XPC_FUNC_DICTIONARY_CREATE_CONNECTION:
            if (idx == 0) return "dictionary_ptr";
            if (idx == 1) return "key_ptr";
            return NULL;
        case XNIFF_XPC_FUNC_CONNECTION_ACTIVATE:
        case XNIFF_XPC_FUNC_CONNECTION_RESUME:
        case XNIFF_XPC_FUNC_CONNECTION_CANCEL:
            if (idx == 0) return "connection_ptr";
            return NULL;
        case XNIFF_XPC_FUNC_SESSION_ACTIVATE:
        case XNIFF_XPC_FUNC_SESSION_CANCEL:
            if (idx == 0) return "session_ptr";
            return NULL;
        case XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY:
            if (idx == 0) return "reply_ptr";
            return NULL;
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE:
            if (idx == 0) return "session_ptr";
            if (idx == 1) return "message_ptr";
            return NULL;
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC:
            if (idx == 0) return "session_ptr";
            if (idx == 1) return "message_ptr";
            if (idx == 2) return "reply_handler_ptr";
            return NULL;
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC:
            if (idx == 0) return "session_ptr";
            if (idx == 1) return "message_ptr";
            if (idx == 2) return "error_out_ptr";
            return NULL;
        case XNIFF_XPC_FUNC_PIPE_ROUTINE:
            if (idx == 0) return "pipe_ptr";
            if (idx == 1) return "request_ptr_ptr";
            if (idx == 2) return "reply_ptr_ptr";
            return NULL;
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE:
            if (idx == 0) return "connection_ptr";
            if (idx == 1) return "message_ptr";
            return NULL;
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY:
            if (idx == 0) return "connection_ptr";
            if (idx == 1) return "message_ptr";
            if (idx == 2) return "reply_queue_ptr";
            if (idx == 3) return "reply_handler_ptr";
            return NULL;
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC:
            if (idx == 0) return "connection_ptr";
            if (idx == 1) return "message_ptr";
            return NULL;
        case XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER:
            if (idx == 0) return "connection_ptr";
            if (idx == 1) return "event_ptr";
            return NULL;
    }
    return NULL;
}

static void print_xpc_serial_item(const xniff_xpc_serial_item_t *it) {
    if (!it || !it->present) return;
    printf("  xpc.serialized.%s: format=%s(%u) stored=%u original=%u%s\n",
           xpc_serial_slot_name(it->slot),
           xpc_serial_format_name(it->format),
           (unsigned)it->format,
           it->stored_len,
           it->original_len,
           (it->flags & 1u) ? " truncated" : "");
}

static void print_xpc_string_fields(uint16_t kind, uint32_t func,
                                    const char *s0, const char *s1,
                                    const char *s2, const char *s3) {
    const char *vals[4] = {s0, s1, s2, s3};
    xpc_string_schema_t sc = xpc_string_schema_for_event(kind, func);
    for (size_t i = 0; i < 4; i++) {
        const char *val = vals[i];
        if (!val) continue;
        const char *name = sc.slot_name[i];
        if (!name) {
            printf("  xpc.string_slot_%zu: %s\n", i, val);
            continue;
        }
        printf("  xpc.%s: %s\n", name, val);
    }
}

static void print_xpc_named_args(uint32_t func, const uint64_t args[8]) {
    for (size_t i = 0; i < 8; i++) {
        const char *name = xpc_arg_name(func, i);
        if (!name) continue;
        printf("  xpc.%s: 0x%llx\n", name, (unsigned long long)args[i]);
    }
}

static char *wire_copy_str(const uint8_t *buf, size_t total, size_t *off_io, uint32_t slen) {
    if (!buf || !off_io) return NULL;
    size_t off = *off_io;
    if (slen == 0) return NULL;
    if (off > total || (size_t)slen > total - off) return NULL;
    char *s = (char *)malloc((size_t)slen + 1);
    if (!s) return NULL;
    memcpy(s, buf + off, slen);
    s[slen] = '\0';
    *off_io = off + (size_t)slen;
    return s;
}

static void print_xpc_event(
    const xniff_ipc_hdr_t *ihdr,
    const xniff_ipc_xpc_payload_t *pl,
    const xniff_xpc_analysis_t *xa,
    const xniff_xpc_serialized_set_t *xs,
    const xniff_xpc_conn_meta_item_t *cm,
    const xniff_xpc_object_ref_item_t *object_ref,
    const char *s0,
    const char *s1,
    const char *s2,
    const char *s3,
    const char *tbuf,
    double mono_s)
{
    const char *kstr = "?";
    if (ihdr->kind == XNIFF_EVT_XPC_ENTRY) kstr = "xpc entry";
    else if (ihdr->kind == XNIFF_EVT_XPC_EXIT) kstr = "xpc exit";

    uint32_t peer_pid = xa ? xa->peer_pid : pl->conn_pid;
    const char *peer_name = (xa && xa->peer_name) ? xa->peer_name : ((peer_pid != 0) ? proc_name_cached((pid_t)peer_pid) : NULL);
    const char *flow = (xa && xa->flow) ? xa->flow : "unknown";
    const char *role = (xa && xa->role) ? xa->role : "unknown";
    const char *service_name = (xa && xa->service_name) ? xa->service_name : (str_nonempty(s0) ? s0 : NULL);
    uint64_t conn_ptr = xa ? xa->conn_ptr : 0;
    uint64_t msg_ptr = xa ? xa->msg_ptr : 0;

    printf("[%s][+%0.6fs] %s\n", tbuf, mono_s, kstr);
    printf("  xpc.func: %s (%u)\n", xpc_func_to_name(pl->func), pl->func);
    printf("  xpc.flow: %s\n", flow);
    printf("  xpc.role: %s\n", role);
    if (xa && xa->call_id != 0) {
        printf("  xpc.call_id: %llu\n", (unsigned long long)xa->call_id);
    }
    printf("  xpc.conn_ptr: 0x%llx\n", (unsigned long long)conn_ptr);
    if (object_ref && object_ref->present) {
        printf("  xpc.object_kind: %s\n",
               object_ref->ref.kind == XNIFF_XPC_OBJECT_SESSION ? "session" : "connection");
        printf("  xpc.object_lifecycle: %u\n", object_ref->ref.lifecycle);
    }
    printf("  xpc.msg_ptr: 0x%llx\n", (unsigned long long)msg_ptr);
    printf("  xpc.conn_pid: %u\n", peer_pid);
    if (peer_name) printf("  xpc.conn_name: %s\n", peer_name);
    if (service_name) printf("  xpc.service_name: %s\n", service_name);
    if (xa && xa->conn_seq != 0) printf("  xpc.conn_seq: %llu\n", (unsigned long long)xa->conn_seq);
    if (xa && xa->response_to_event_id != 0) printf("  xpc.response_to_event_id: %llu\n", xa->response_to_event_id);
    printf("  xpc.ret: 0x%llx\n", (unsigned long long)pl->ret_value);
    print_xpc_named_args(pl->func, pl->args);
    print_xpc_string_fields(ihdr->kind, pl->func, s0, s1, s2, s3);
    if (cm && cm->present) {
        const xniff_xpc_conn_meta_t *md = &cm->meta;
        printf("  xpc.conn_meta.flags: 0x%x\n", md->flags);
        if (md->flags & XNIFF_XPC_CONN_META_HAS_NAME_PUBLIC) {
            printf("  xpc.conn_meta.name_public: %s\n", cm->name_public ? cm->name_public : "");
        }
        if (md->flags & XNIFF_XPC_CONN_META_HAS_NAME_PRIVATE) {
            printf("  xpc.conn_meta.name_private: %s\n", cm->name_private ? cm->name_private : "");
        }
        if (md->flags & XNIFF_XPC_CONN_META_HAS_PID_PUBLIC) printf("  xpc.conn_meta.pid_public: %u\n", md->pid_public);
        if (md->flags & XNIFF_XPC_CONN_META_HAS_INSTANCE) printf("  xpc.conn_meta.instance: 0x%llx\n", (unsigned long long)md->instance);
        if (md->flags & XNIFF_XPC_CONN_META_HAS_PEER_INSTANCE) printf("  xpc.conn_meta.peer_instance: 0x%llx\n", (unsigned long long)md->peer_instance);
        if (md->flags & XNIFF_XPC_CONN_META_HAS_BS_TYPE) printf("  xpc.conn_meta.bs_type: 0x%llx\n", (unsigned long long)md->bs_type);
    }
    if (xs) {
        print_xpc_serial_item(&xs->message);
        print_xpc_serial_item(&xs->reply);
        print_xpc_serial_item(&xs->event);
    }
}

static void print_event(int kind, const xniff_ipc_mach_payload_t *pl, const uint8_t *msg_bytes, size_t msg_len) {
    const mach_msg_header_t *hdr = (const mach_msg_header_t *)msg_bytes;
    const char *kstr = "?";
    switch (kind) {
        case XNIFF_EVT_MACH_ENTRY:  kstr = "mach_msg entry"; break;
        case XNIFF_EVT_MACH_EXIT:   kstr = "mach_msg exit"; break;
        case XNIFF_EVT_MACH2_ENTRY: kstr = "mach_msg2 entry"; break;
        case XNIFF_EVT_MACH2_EXIT:  kstr = "mach_msg2 exit"; break;
    }

    char tbuf[64]; double mono_s = 0.0; format_time(tbuf, sizeof(tbuf), &mono_s);
    uint64_t option64 = ((uint64_t)pl->option_hi << 32) | (uint64_t)pl->option_lo;
    bool is_send = false, is_recv = false;
    if (pl->api == XNIFF_API_MACH_MSG) {
        is_send = (pl->option_lo & MACH_SEND_MSG) != 0;
        is_recv = (pl->option_lo & MACH_RCV_MSG) != 0;
    } else {
        is_send = (option64 & MACH64_SEND_MSG) != 0;
        is_recv = (option64 & MACH64_RCV_MSG) != 0;
    }
    unsigned bits = hdr ? (unsigned)hdr->msgh_bits : 0;
    mach_port_t remote = hdr ? hdr->msgh_remote_port : MACH_PORT_NULL;
    mach_port_t local  = hdr ? hdr->msgh_local_port  : MACH_PORT_NULL;
    printf("[%s][+%0.6fs] %s\n", tbuf, mono_s, kstr);
    printf("  mach.api: %u\n", pl->api);
    printf("  mach.direction: %u\n", pl->direction);
    printf("  mach.is_send: %s\n", is_send ? "true" : "false");
    printf("  mach.is_recv: %s\n", is_recv ? "true" : "false");
    printf("  mach.msgh_id: %d\n", hdr ? hdr->msgh_id : -1);
    printf("  mach.msgh_size: %u\n", pl->msgh_size);
    printf("  mach.copy_len: %u\n", pl->copy_len);
    printf("  mach.msgh_bits: 0x%08x\n", bits);
    printf("  mach.msg_addr: 0x%llx\n", (unsigned long long)pl->msg_addr);
    printf("  mach.aux_addr: 0x%llx\n", (unsigned long long)pl->aux_addr);
    printf("  mach.option64: 0x%016llx\n", (unsigned long long)option64);
    printf("  mach.ret: 0x%llx\n", (unsigned long long)pl->ret_value);
    printf("  mach.desc_count: %u\n", pl->desc_count);
    printf("  mach.priority: %u\n", pl->priority);
    printf("  mach.timeout: %llu\n", (unsigned long long)pl->timeout);
    printf("  mach.remote_port: 0x%08x\n", remote);
    printf("  mach.local_port: 0x%08x\n", local);

    uint32_t sender_pid = 0;
    if (pl->direction == XNIFF_DIR_EXIT && is_recv && pl->ret_value == 0) {
        uint32_t sz = pl->msgh_size;
        if (sz == 0 && hdr) sz = (uint32_t)hdr->msgh_size;
        if (sz != 0) (void)mach_extract_sender_pid_from_trailer(msg_bytes, msg_len, sz, &sender_pid);
    }
    const char *sender_name = (sender_pid != 0) ? proc_name_cached((pid_t)sender_pid) : NULL;
    if (sender_pid) {
        printf("  mach.peer_role: sender\n");
        printf("  mach.peer_pid: %u\n", sender_pid);
        if (sender_name) printf("  mach.peer_name: %s\n", sender_name);
    } else if (is_send) {
        printf("  mach.peer_role: recipient\n");
    } else {
        printf("  mach.peer_role: unknown\n");
    }

    // Optionally, print a short hexdump of the first 64 bytes of the message
    size_t dump_len = msg_len < 64 ? msg_len : 64;
    if (hdr && dump_len) {
        const uint8_t *p = (const uint8_t *)hdr;
        printf("  mach.msg_preview_hex[%zu]: ", dump_len);
        for (size_t i = 0; i < dump_len; i++) printf("%02x", p[i]);
        printf("\n");
    }

}

int xniff_render_record(const uint8_t *record,
                        size_t record_length,
                        uint64_t event_index,
                        bool include_hook_debug) {
    if (!record || record_length < sizeof(xniff_ipc_v2_entry_hdr_t) +
                                    sizeof(xniff_ipc_v2_fixed_hdr_t)) {
        return -1;
    }

    const uint8_t *body = record + sizeof(xniff_ipc_v2_entry_hdr_t);
    size_t body_length = record_length - sizeof(xniff_ipc_v2_entry_hdr_t);
    xniff_ipc_v2_fixed_hdr_t fixed = {0};
    memcpy(&fixed, body, sizeof(fixed));
    uint16_t kind = v2_kind_from_fixed(&fixed);
    size_t section_offset = sizeof(fixed);

    if (include_hook_debug && kind == XNIFF_EVT_DEBUG_LOG) {
        while (section_offset + sizeof(xniff_ipc_v2_section_hdr_t) <= body_length) {
            xniff_ipc_v2_section_hdr_t section = {0};
            memcpy(&section, body + section_offset, sizeof(section));
            section_offset += sizeof(section);
            if (section_offset + section.sec_len > body_length) break;
            const uint8_t *value = body + section_offset;
            if (section.sec_type == XNIFF_V2_SEC_HOOK_DIAG &&
                section.sec_len >= sizeof(xniff_ipc_v2_diag_t)) {
                xniff_ipc_v2_diag_t diagnostic = {0};
                memcpy(&diagnostic, value, sizeof(diagnostic));
                size_t available = section.sec_len - sizeof(diagnostic);
                size_t message_length = diagnostic.msg_len;
                if (message_length > available) message_length = available;
                char *line = malloc(message_length + 1);
                if (line) {
                    memcpy(line, value + sizeof(diagnostic), message_length);
                    line[message_length] = '\0';
                    char timestamp[64];
                    double monotonic_seconds = 0;
                    format_time(timestamp, sizeof(timestamp), &monotonic_seconds);
                    append_hook_debug_log(fixed.pid, fixed.tid_low, timestamp,
                                          monotonic_seconds, line);
                    if (*line) {
                        printf("[hook-debug][pid=%u][tid=0x%x] %s\n",
                               fixed.pid, fixed.tid_low, line);
                    }
                    free(line);
                }
            }
            section_offset += section.sec_len;
        }
        return 0;
    }

    if (fixed.api == XNIFF_API_XPC_HL) {
        xniff_ipc_xpc_payload_t payload = {
            .api = fixed.api,
            .direction = fixed.direction,
            .func = fixed.function,
        };
        char *strings[4] = {0};
        uint64_t call_id = 0;
        xniff_xpc_serialized_set_t serialized;
        xniff_xpc_conn_meta_item_t connection_metadata;
        xniff_xpc_object_ref_item_t object_reference = {0};
        xpc_serialized_init(&serialized);
        xpc_conn_meta_init(&connection_metadata);

        while (section_offset + sizeof(xniff_ipc_v2_section_hdr_t) <= body_length) {
            xniff_ipc_v2_section_hdr_t section = {0};
            memcpy(&section, body + section_offset, sizeof(section));
            section_offset += sizeof(section);
            if (section_offset + section.sec_len > body_length) break;
            const uint8_t *value = body + section_offset;
            if (section.sec_type == XNIFF_V2_SEC_XPC_CALL_META &&
                section.sec_len >= sizeof(payload)) {
                memcpy(&payload, value, sizeof(payload));
                size_t string_offset = sizeof(payload);
                strings[0] = wire_copy_str(value, section.sec_len, &string_offset,
                                           payload.str0_len);
                strings[1] = wire_copy_str(value, section.sec_len, &string_offset,
                                           payload.str1_len);
                strings[2] = wire_copy_str(value, section.sec_len, &string_offset,
                                           payload.str2_len);
                strings[3] = wire_copy_str(value, section.sec_len, &string_offset,
                                           payload.str3_len);
            } else if (section.sec_type == XNIFF_V2_SEC_CALL_ID &&
                       section.sec_len >= sizeof(call_id)) {
                memcpy(&call_id, value, sizeof(call_id));
            } else {
                xpc_parse_section(section.sec_type, value, section.sec_len,
                                  &serialized, &connection_metadata,
                                  &object_reference);
            }
            section_offset += section.sec_len;
        }

        xniff_ipc_hdr_t event_header = {
            .kind = kind,
            .pid = fixed.pid,
            .tid_low = fixed.tid_low,
        };
        char timestamp[64];
        double monotonic_seconds = 0;
        format_time(timestamp, sizeof(timestamp), &monotonic_seconds);
        xniff_xpc_analysis_t analysis;
        analyze_xpc_event(event_index, &event_header, &payload, strings[0],
                          &object_reference, monotonic_seconds, &analysis);
        analysis.call_id = call_id;
        print_xpc_event(&event_header, &payload, &analysis, &serialized,
                        &connection_metadata, &object_reference, strings[0],
                        strings[1], strings[2], strings[3], timestamp,
                        monotonic_seconds);
        xpc_serialized_free(&serialized);
        xpc_conn_meta_free(&connection_metadata);
        for (size_t index = 0; index < 4; index++) free(strings[index]);
        return 0;
    }

    if (fixed.api == XNIFF_API_MACH_MSG || fixed.api == XNIFF_API_MACH_MSG2) {
        xniff_ipc_mach_payload_t payload = {
            .api = fixed.api,
            .direction = fixed.direction,
        };
        const uint8_t *message = NULL;
        size_t message_length = 0;
        while (section_offset + sizeof(xniff_ipc_v2_section_hdr_t) <= body_length) {
            xniff_ipc_v2_section_hdr_t section = {0};
            memcpy(&section, body + section_offset, sizeof(section));
            section_offset += sizeof(section);
            if (section_offset + section.sec_len > body_length) break;
            const uint8_t *value = body + section_offset;
            if (section.sec_type == XNIFF_V2_SEC_MACH_HEADER_OPTIONS &&
                section.sec_len >= sizeof(payload)) {
                memcpy(&payload, value, sizeof(payload));
            } else if (section.sec_type == XNIFF_V2_SEC_MACH_INLINE_BYTES) {
                message = value;
                message_length = section.sec_len;
            }
            section_offset += section.sec_len;
        }
        print_event(kind, &payload, message, message_length);
    }
    return 0;
}
