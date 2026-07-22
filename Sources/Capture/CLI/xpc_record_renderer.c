#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xniff_payload.h"
#include "xniff_record.h"
#include "record_render_support.h"
#include "xpc_record_renderer.h"

typedef struct xniff_conn_meta {
    uint32_t owner_pid;
    uint16_t object_kind;
    uint64_t conn_ptr;
    uint32_t peer_pid;
    char service[256];
    uint64_t next_seq;
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

static uint64_t xpc_conn_ptr_for_event(uint16_t direction,
                                       const xniff_xpc_payload_t *pl) {
    if (!pl) return 0;
    if (pl->func == XNIFF_XPC_FUNC_CONNECTION_CREATE ||
        pl->func == XNIFF_XPC_FUNC_CONNECTION_CREATE_MACH_SERVICE ||
        pl->func == XNIFF_XPC_FUNC_CONNECTION_CREATE_FROM_ENDPOINT ||
        pl->func == XNIFF_XPC_FUNC_ARRAY_CREATE_CONNECTION ||
        pl->func == XNIFF_XPC_FUNC_DICTIONARY_CREATE_CONNECTION ||
        pl->func == XNIFF_XPC_FUNC_SESSION_CREATE_XPC_SERVICE ||
        pl->func == XNIFF_XPC_FUNC_SESSION_CREATE_MACH_SERVICE) {
        if (direction == XNIFF_DIRECTION_EXIT && pl->ret_value != 0) {
            return pl->ret_value;
        }
        return 0;
    }
    return pl->args[0];
}

static uint64_t xpc_msg_ptr_for_event(const xniff_xpc_payload_t *pl) {
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

static const char *xpc_flow_for_event(const xniff_xpc_payload_t *pl) {
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

static const char *xpc_role_for_event(const xniff_xpc_payload_t *pl) {
    if (!pl) return "unknown";
    switch (pl->func) {
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY:
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC:
            return pl->direction == XNIFF_DIRECTION_ENTRY ? "request" : "response";
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC:
        case XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC:
        case XNIFF_XPC_FUNC_PIPE_ROUTINE:
            return pl->direction == XNIFF_DIRECTION_ENTRY ? "request" : "response";
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
    const xniff_record_fixed_header_t *fixed,
    const xniff_xpc_payload_t *pl,
    const char *s0,
    const xniff_xpc_object_ref_item_t *object_ref,
    xniff_xpc_analysis_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));

    if (!fixed || !pl) {
        out->flow = "unknown";
        out->peer_role = "unknown";
        return;
    }

    out->flow = xpc_flow_for_event(pl);
    out->role = xpc_role_for_event(pl);
    out->peer_role = xpc_peer_role_for_flow(out->flow);
    out->conn_ptr = object_ref && object_ref->present
        ? object_ref->ref.object
        : xpc_conn_ptr_for_event(fixed->direction, pl);
    out->msg_ptr = xpc_msg_ptr_for_event(pl);

    uint16_t object_kind = object_ref && object_ref->present
        ? object_ref->ref.kind
        : XNIFF_XPC_OBJECT_CONNECTION;
    xniff_conn_meta_t *m = conn_meta_find_or_create(
        fixed->pid, object_kind, out->conn_ptr, out->conn_ptr != 0);
    if (m) {
        if (pl->conn_pid != 0) m->peer_pid = pl->conn_pid;
        if (str_nonempty(s0)) str_copy_trunc(m->service, sizeof(m->service), s0);

        if (fixed->direction == XNIFF_DIRECTION_ENTRY) {
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

    out->peer_name = (out->peer_pid != 0)
        ? xniff_process_name((pid_t)out->peer_pid)
        : NULL;
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
    if (sec_type == XNIFF_SECTION_XPC_SERIALIZED && val_len >= sizeof(xniff_xpc_serialized_t)) {
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

    if (cm && sec_type == XNIFF_SECTION_XPC_CONN_META && val_len >= sizeof(xniff_xpc_conn_meta_t)) {
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

    if (object_ref && sec_type == XNIFF_SECTION_XPC_OBJECT_REF &&
        val_len >= sizeof(xniff_xpc_object_ref_t)) {
        xniff_xpc_object_ref_t ref = {0};
        memcpy(&ref, val, sizeof(ref));
        if (ref.version == XNIFF_XPC_OBJECT_REF_VERSION && ref.object != 0) {
            object_ref->present = true;
            object_ref->ref = ref;
        }
    }
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

static xpc_string_schema_t xpc_string_schema_for_event(uint16_t direction,
                                                        uint32_t func) {
    xpc_string_schema_t sc = {{NULL, NULL, NULL, NULL}};
    switch (func) {
        case XNIFF_XPC_FUNC_CONNECTION_CREATE:
        case XNIFF_XPC_FUNC_CONNECTION_CREATE_MACH_SERVICE:
        case XNIFF_XPC_FUNC_SESSION_CREATE_XPC_SERVICE:
        case XNIFF_XPC_FUNC_SESSION_CREATE_MACH_SERVICE:
            if (direction == XNIFF_DIRECTION_ENTRY) {
                sc.slot_name[0] = "target_service_name";
            } else {
                sc.slot_name[0] = "connection_name";
                sc.slot_name[1] = "connection_description";
            }
            break;
        case XNIFF_XPC_FUNC_PIPE_ROUTINE:
            sc.slot_name[0] = "pipe_description";
            sc.slot_name[1] = "request_description";
            if (direction == XNIFF_DIRECTION_EXIT) {
                sc.slot_name[2] = "reply_description";
            }
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
            if (direction == XNIFF_DIRECTION_EXIT) {
                sc.slot_name[3] = "reply_description";
            }
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

static void print_xpc_string_fields(uint16_t direction, uint32_t func,
                                    const char *s0, const char *s1,
                                    const char *s2, const char *s3) {
    const char *vals[4] = {s0, s1, s2, s3};
    xpc_string_schema_t sc = xpc_string_schema_for_event(direction, func);
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
    uint16_t direction,
    const xniff_xpc_payload_t *pl,
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
    const char *kind_name = direction == XNIFF_DIRECTION_EXIT
        ? "xpc exit"
        : "xpc entry";

    uint32_t peer_pid = xa ? xa->peer_pid : pl->conn_pid;
    const char *peer_name = (xa && xa->peer_name)
        ? xa->peer_name
        : ((peer_pid != 0) ? xniff_process_name((pid_t)peer_pid) : NULL);
    const char *flow = (xa && xa->flow) ? xa->flow : "unknown";
    const char *role = (xa && xa->role) ? xa->role : "unknown";
    const char *service_name = (xa && xa->service_name) ? xa->service_name : (str_nonempty(s0) ? s0 : NULL);
    uint64_t conn_ptr = xa ? xa->conn_ptr : 0;
    uint64_t msg_ptr = xa ? xa->msg_ptr : 0;

    printf("[%s][+%0.6fs] %s\n", tbuf, mono_s, kind_name);
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
    printf("  xpc.ret: 0x%llx\n", (unsigned long long)pl->ret_value);
    print_xpc_named_args(pl->func, pl->args);
    print_xpc_string_fields(direction, pl->func, s0, s1, s2, s3);
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

int xniff_render_xpc_record(const uint8_t *body,
                            size_t body_length,
                            const xniff_record_fixed_header_t *fixed) {
    if (!body || !fixed || body_length < sizeof(*fixed)) return -1;

    xniff_xpc_payload_t payload = {
        .api = fixed->api,
        .direction = fixed->direction,
        .func = fixed->function,
    };
    char *strings[4] = {0};
    uint64_t call_id = 0;
    xniff_xpc_serialized_set_t serialized;
    xniff_xpc_conn_meta_item_t connection_metadata;
    xniff_xpc_object_ref_item_t object_reference = {0};
    xpc_serialized_init(&serialized);
    xpc_conn_meta_init(&connection_metadata);

    xniff_record_section_iterator_t iterator;
    xniff_record_section_iterator_init(&iterator, body + sizeof(*fixed),
                                       body_length - sizeof(*fixed));
    xniff_record_section_t section;
    int section_result;
    while ((section_result = xniff_record_section_next(&iterator, &section)) > 0) {
        const uint8_t *value = section.data;
        if (section.type == XNIFF_SECTION_XPC_CALL_META &&
            section.length >= sizeof(payload)) {
            for (size_t index = 0; index < 4; index++) {
                free(strings[index]);
                strings[index] = NULL;
            }
            memcpy(&payload, value, sizeof(payload));
            size_t string_offset = sizeof(payload);
            strings[0] = wire_copy_str(value, section.length, &string_offset,
                                       payload.str0_len);
            strings[1] = wire_copy_str(value, section.length, &string_offset,
                                       payload.str1_len);
            strings[2] = wire_copy_str(value, section.length, &string_offset,
                                       payload.str2_len);
            strings[3] = wire_copy_str(value, section.length, &string_offset,
                                       payload.str3_len);
        } else if (section.type == XNIFF_SECTION_CALL_ID &&
                   section.length >= sizeof(call_id)) {
            memcpy(&call_id, value, sizeof(call_id));
        } else {
            xpc_parse_section(section.type, value, section.length,
                              &serialized, &connection_metadata,
                              &object_reference);
        }
    }
    if (section_result < 0) {
        xpc_serialized_free(&serialized);
        xpc_conn_meta_free(&connection_metadata);
        for (size_t index = 0; index < 4; index++) free(strings[index]);
        return -1;
    }

    char timestamp[64];
    double monotonic_seconds = 0;
    xniff_format_timestamp(timestamp, sizeof(timestamp), &monotonic_seconds);
    xniff_xpc_analysis_t analysis;
    analyze_xpc_event(fixed, &payload, strings[0], &object_reference, &analysis);
    analysis.call_id = call_id;
    print_xpc_event(fixed->direction, &payload, &analysis, &serialized,
                    &connection_metadata, &object_reference, strings[0],
                    strings[1], strings[2], strings[3], timestamp,
                    monotonic_seconds);

    xpc_serialized_free(&serialized);
    xpc_conn_meta_free(&connection_metadata);
    for (size_t index = 0; index < 4; index++) free(strings[index]);
    return 0;
}
