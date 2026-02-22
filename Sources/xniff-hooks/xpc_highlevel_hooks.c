// xniff-hooks: high-level libxpc helpers used by Frida Gum interceptors.

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#include <xpc/xpc.h>

#include "../shared/xniff_ipc.h"
#include "xniff_hooks_emit.h"
#include "xniff_hooks_ipc.h"

enum { XNIFF_XPC_STR_MAX = 16384u };

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

static void ipc_send_xpc_event(
    uint16_t kind,
    const xniff_ipc_xpc_payload_t *pl_in,
    const char *s0, uint32_t l0,
    const char *s1, uint32_t l1,
    const char *s2, uint32_t l2,
    const char *s3, uint32_t l3)
{
    if (!pl_in) return;

    xniff_hooks_ipc_lock();
    int fd = xniff_hooks_ipc_ensure_fd_locked();
    if (fd < 0) { xniff_hooks_ipc_unlock(); return; }

    xniff_ipc_hdr_t hdr = {0};
    hdr.magic = XNIFF_IPC_MAGIC;
    hdr.version = XNIFF_IPC_VERSION;
    hdr.kind = kind;
    hdr.pid = (uint32_t)getpid();
    hdr.tid_low = (uint32_t)(uintptr_t)pthread_self();
    hdr.payload_len = (uint32_t)(sizeof(*pl_in) + l0 + l1 + l2 + l3);

    xniff_ipc_xpc_payload_t pl = *pl_in;
    pl.str0_len = l0;
    pl.str1_len = l1;
    pl.str2_len = l2;
    pl.str3_len = l3;

    if (xniff_ipc_send_all(fd, &hdr, sizeof(hdr)) != 0) { xniff_hooks_ipc_drop_locked(); xniff_hooks_ipc_unlock(); return; }
    if (xniff_ipc_send_all(fd, &pl, sizeof(pl)) != 0)   { xniff_hooks_ipc_drop_locked(); xniff_hooks_ipc_unlock(); return; }

    if (l0 && s0) if (xniff_ipc_send_all(fd, s0, l0) != 0) { xniff_hooks_ipc_drop_locked(); xniff_hooks_ipc_unlock(); return; }
    if (l1 && s1) if (xniff_ipc_send_all(fd, s1, l1) != 0) { xniff_hooks_ipc_drop_locked(); xniff_hooks_ipc_unlock(); return; }
    if (l2 && s2) if (xniff_ipc_send_all(fd, s2, l2) != 0) { xniff_hooks_ipc_drop_locked(); xniff_hooks_ipc_unlock(); return; }
    if (l3 && s3) if (xniff_ipc_send_all(fd, s3, l3) != 0) { xniff_hooks_ipc_drop_locked(); xniff_hooks_ipc_unlock(); return; }

    xniff_hooks_ipc_unlock();
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
    xpc_object_t pipe = (xpc_object_t)(uintptr_t)(args ? args[0] : 0);
    xpc_object_t *in  = (xpc_object_t *)(uintptr_t)(args ? args[1] : 0);
    xpc_object_t in_obj = (in ? *in : NULL);

    uint32_t l0 = 0, l1 = 0;
    char *pdesc = xniff_xpc_desc(pipe, &l0);
    char *idesc = xniff_xpc_desc(in_obj, &l1);

    xniff_ipc_xpc_payload_t pl;
    pl_init_from_args(&pl, XNIFF_XPC_FUNC_PIPE_ROUTINE, XNIFF_DIR_ENTRY, 0, args);
    ipc_send_xpc_event(XNIFF_EVT_XPC_ENTRY, &pl, pdesc, l0, idesc, l1, NULL, 0, NULL, 0);
    if (pdesc) free(pdesc);
    if (idesc) free(idesc);
}

void xniff_emit_xpc_pipe_routine_exit(uint64_t ret, const uint64_t args[8]) {
    xpc_object_t pipe = (xpc_object_t)(uintptr_t)(args ? args[0] : 0);
    xpc_object_t *in  = (xpc_object_t *)(uintptr_t)(args ? args[1] : 0);
    xpc_object_t *out = (xpc_object_t *)(uintptr_t)(args ? args[2] : 0);
    xpc_object_t in_obj  = (in ? *in : NULL);
    xpc_object_t out_obj = (out ? *out : NULL);

    uint32_t l0 = 0, l1 = 0, l2 = 0;
    char *pdesc = xniff_xpc_desc(pipe, &l0);
    char *idesc = xniff_xpc_desc(in_obj, &l1);
    char *odesc = xniff_xpc_desc(out_obj, &l2);

    xniff_ipc_xpc_payload_t pl;
    pl_init_from_args(&pl, XNIFF_XPC_FUNC_PIPE_ROUTINE, XNIFF_DIR_EXIT, ret, args);
    ipc_send_xpc_event(XNIFF_EVT_XPC_EXIT, &pl, pdesc, l0, idesc, l1, odesc, l2, NULL, 0);
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
    ipc_send_xpc_event(kind, &pl, cname, l0, mdesc, l1, cdesc, l2, rdesc, l3);

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
