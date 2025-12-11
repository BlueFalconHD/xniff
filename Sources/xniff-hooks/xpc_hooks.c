// xniff-xpc-hooks: exported entry/exit hooks for Mach message tracing
// This library is intended to be injected into a running process so that
// xniff-cli can install trampolines targeting these hooks.

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <pthread.h>

#include "../shared/xniff_ipc.h"
#include "../shared/mach_private.h"

#include <mach/mach.h>
#include <mach/message.h>

typedef struct xniff_ctx_frame {
    // Saved at entry
    uint64_t lr_orig;      // +0x00: original LR (return target)
    uint64_t resume_pc;    // +0x08: resume PC (after entry patch window)

    // Register arguments snapshot at entry
    uint64_t x[8];         // +0x10..+0x48: x0..x7 (8 x 8 bytes)

    // Saved at exit
    uint64_t ret;          // +0x50: function return value (from x0 at exit)

    // Pad to fixed 128-byte frame size (one frame per 0x80)
    uint8_t  reserved[0x80 - 0x58]; // 0x28 bytes
} xniff_ctx_frame_t;

_Static_assert(sizeof(xniff_ctx_frame_t) == 0x80, "xniff_ctx_frame_t must be 128 bytes");

static int g_ipc_fd = -1; // lazily connect per-process

static int ensure_ipc_fd(void) {
    if (g_ipc_fd != -1) return g_ipc_fd;
    char path[108];
    (void)xniff_ipc_path_for_pid(getpid(), path, sizeof(path));
    int fd = xniff_ipc_client_connect(getpid());
    if (fd >= 0) g_ipc_fd = fd;
    return g_ipc_fd;
}

static size_t attachments_size_for_msg(const mach_msg_header_t *msg) {
    if (!msg) return 0;
    if (!(msg->msgh_bits & MACH_MSGH_BITS_COMPLEX)) return 0;
    const uint8_t *base = (const uint8_t *)msg;
    mach_msg_size_t total = msg->msgh_size;
    if (total < sizeof(*msg) + sizeof(mach_msg_body_t)) return 0;
    const mach_msg_body_t *body = (const mach_msg_body_t *)(base + sizeof(*msg));
    mach_msg_descriptor_t *desc = (mach_msg_descriptor_t *)((uint8_t *)body + sizeof(*body));
    mach_msg_size_t dcount = body->msgh_descriptor_count;
    size_t sum = 0;
    for (mach_msg_size_t i = 0; i < dcount; i++, desc++) {
        mach_msg_descriptor_type_t t = desc->type.type;
        if (t == MACH_MSG_OOL_DESCRIPTOR) {
            const mach_msg_ool_descriptor_t *ool = &desc->out_of_line;
            size_t tlv = sizeof(xniff_ipc_tlv_t) + sizeof(xniff_ool_data_t) + (size_t)ool->size;
            sum += tlv;
        } else if (t == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
            const mach_msg_ool_ports_descriptor_t *op = &desc->ool_ports;
            size_t ports_bytes = (size_t)op->count * sizeof(mach_port_t);
            size_t tlv = sizeof(xniff_ipc_tlv_t) + sizeof(xniff_ool_ports_t) + ports_bytes;
            sum += tlv;
        }
    }
    return sum;
}

static void ipc_send_msg_full(int kind, const xniff_ipc_mach_payload_t *pl_in,
                              const mach_msg_header_t *msg) {
    if (!msg || !pl_in) return;
    if (ensure_ipc_fd() < 0) { return; }

    uint32_t copy_len = msg->msgh_size;
    const uint8_t *base = (const uint8_t *)msg;

    // Compute attachment TLVs size in advance
    size_t att_sz = attachments_size_for_msg(msg);

    xniff_ipc_hdr_t hdr = {0};
    hdr.magic = XNIFF_IPC_MAGIC;
    hdr.version = XNIFF_IPC_VERSION;
    hdr.kind = (uint16_t)kind;
    hdr.pid = (uint32_t)getpid();
    hdr.tid_low = (uint32_t)(uintptr_t)pthread_self();
    hdr.payload_len = (uint32_t)(sizeof(xniff_ipc_mach_payload_t) + copy_len + att_sz);

    xniff_ipc_mach_payload_t pl = *pl_in;
    pl.msgh_size = msg->msgh_size;
    pl.copy_len = copy_len;
    pl.msg_addr = (uint64_t)(uintptr_t)msg;

    // Send header, payload, and inline bytes (blocking to ensure ordering)
    if (xniff_ipc_send_all(g_ipc_fd, &hdr, sizeof(hdr)) != 0) { return; }
    if (xniff_ipc_send_all(g_ipc_fd, &pl, sizeof(pl)) != 0) { return; }
    if (xniff_ipc_send_all(g_ipc_fd, base, copy_len) != 0)  { return; }

    // Send attachments
    if (msg->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
        if (copy_len >= sizeof(*msg) + sizeof(mach_msg_body_t)) {
            const mach_msg_body_t *body = (const mach_msg_body_t *)(base + sizeof(*msg));
            mach_msg_descriptor_t *desc = (mach_msg_descriptor_t *)((uint8_t *)body + sizeof(*body));
            mach_msg_size_t dcount = body->msgh_descriptor_count;
            size_t att_count = 0;
            for (mach_msg_size_t i = 0; i < dcount; i++, desc++) {
                mach_msg_descriptor_type_t t = desc->type.type;
                if (t == MACH_MSG_OOL_DESCRIPTOR) {
                    const mach_msg_ool_descriptor_t *ool = &desc->out_of_line;
                    xniff_ipc_tlv_t h = { .type = XNIFF_TLV_OOL_DATA, .length = (uint32_t)(sizeof(xniff_ool_data_t) + ool->size) };
                    xniff_ool_data_t md = {0};
                    md.index = (uint32_t)i;
                    md.flags = (ool->deallocate ? 1u : 0u) | (ool->copy ? 2u : 0u);
                    md.address = (uint64_t)(uintptr_t)ool->address;
                    md.size = (uint32_t)ool->size;
                    if (xniff_ipc_send_all(g_ipc_fd, &h, sizeof(h)) != 0) { return; }
                    if (xniff_ipc_send_all(g_ipc_fd, &md, sizeof(md)) != 0) { return; }
                    if (ool->address && ool->size) {
                        if (xniff_ipc_send_all(g_ipc_fd, ool->address, ool->size) != 0) { return; }
                    }
                    att_count++;
                } else if (t == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
                    const mach_msg_ool_ports_descriptor_t *op = &desc->ool_ports;
                    size_t ports_bytes = (size_t)op->count * sizeof(mach_port_t);
                    xniff_ipc_tlv_t h = { .type = XNIFF_TLV_OOL_PORTS, .length = (uint32_t)(sizeof(xniff_ool_ports_t) + ports_bytes) };
                    xniff_ool_ports_t md = {0};
                    md.index = (uint32_t)i;
                    md.count = (uint32_t)op->count;
                    md.address = (uint64_t)(uintptr_t)op->address;
                    md.elem_size = (uint32_t)sizeof(mach_port_t);
                    if (xniff_ipc_send_all(g_ipc_fd, &h, sizeof(h)) != 0) { return; }
                    if (xniff_ipc_send_all(g_ipc_fd, &md, sizeof(md)) != 0) { return; }
                    if (op->address && ports_bytes) {
                        if (xniff_ipc_send_all(g_ipc_fd, op->address, ports_bytes) != 0) { return; }
                    }
                    att_count++;
                }
            }
            (void)0;
        }
    }
}


__attribute__((used, noinline, visibility("default")))
void xniff_remote_entry_hook(mach_msg_header_t *msg, mach_msg_option_t option) {
    xniff_ipc_mach_payload_t pl = {0};
    pl.api = XNIFF_API_MACH_MSG;
    pl.direction = XNIFF_DIR_ENTRY;
    pl.option_lo = (uint32_t)option;
    pl.option_hi = 0;
    pl.ret_value = 0;
    pl.desc_count = 0;
    pl.priority = 0;
    pl.timeout = 0; // TODO: get from stack
    pl.args[0] = (uint64_t)(uintptr_t)msg;
    pl.args[1] = (uint64_t)option;
    ipc_send_msg_full(XNIFF_EVT_MACH_ENTRY, &pl, msg);
}

__attribute__((used, noinline, visibility("default")))
void xniff_remote_exit_hook(uint64_t ret, const xniff_ctx_frame_t* ctx) {
    mach_msg_option_t option = 0;
    if (ctx) option = (mach_msg_option_t)ctx->x[1];
    if (ctx) {
        mach_msg_header_t* reply = (mach_msg_header_t*)(ctx->x[7] ? ctx->x[7] : ctx->x[0]);
        if (reply) {
            xniff_ipc_mach_payload_t pl = {0};
            pl.api = XNIFF_API_MACH_MSG;
            pl.direction = XNIFF_DIR_EXIT;
            pl.option_lo = (uint32_t)option;
            pl.ret_value = ret;
            for (int i = 0; i < 8; i++) pl.args[i] = ctx->x[i];
            pl.timeout = ctx->x[5];
            ipc_send_msg_full(XNIFF_EVT_MACH_EXIT, &pl, reply);
        }
    }
}

typedef struct {
    mach_msg_header_t* send_msg;
    mach_msg_header_t* rcv_msg;    /* may equal send_msg if no separate rcv */
    void*              aux;        /* optional */
    uint32_t           send_size;
    uint32_t           rcv_size;
    uint32_t           desc_count; /* from packed arg, for reference only */

    mach_msg_bits_t    bits;
    mach_port_t        remote;
    mach_port_t        local;
    mach_port_name_t   voucher;
    mach_msg_id_t      msgh_id;

    uint32_t           priority;
    uint64_t           timeout;

    uint64_t option64;
    bool               is_vector;
} xniff_msg2_parsed_t;

static inline void xniff_unpack_u32x2(uint64_t v, uint32_t* lo, uint32_t* hi) {
    if (lo) *lo = (uint32_t)(v & 0xffffffffu);
    if (hi) *hi = (uint32_t)(v >> 32);
}

static inline void xniff_parse_msg2_args(
    void* data,
    uint64_t option64,
    uint64_t bits_send,
    uint64_t remote_local,
    uint64_t voucher_id,
    uint64_t desc_rcvname,
    uint64_t rcv_prio,
    uint64_t timeout,
    xniff_msg2_parsed_t* out)
{
    uint32_t lo = 0, hi = 0;

    out->option64 = option64;
    out->is_vector = (option64 & MACH64_MSG_VECTOR) != 0;
    out->timeout = timeout;

    xniff_unpack_u32x2(bits_send, &lo, &hi);
    out->bits = (mach_msg_bits_t)lo;
    out->send_size = hi;

    xniff_unpack_u32x2(remote_local, &lo, &hi);
    out->remote = (mach_port_t)lo;
    out->local  = (mach_port_t)hi;

    xniff_unpack_u32x2(voucher_id, &lo, &hi);
    out->voucher = (mach_port_name_t)lo;
    out->msgh_id = (mach_msg_id_t)hi;

    xniff_unpack_u32x2(desc_rcvname, &lo, &hi);
    out->desc_count = lo;
    mach_port_t rcv_name = (mach_port_t)hi;
    (void)rcv_name;

    xniff_unpack_u32x2(rcv_prio, &lo, &hi);
    out->rcv_size = lo;
    out->priority = hi;

    if (out->is_vector) {
        mach_msg_vector_t* vec = (mach_msg_vector_t*)data;
        mach_msg_vector_t* mv  = &vec[MACH_MSGV_IDX_MSG];
        mach_msg_vector_t* aux = &vec[MACH_MSGV_IDX_AUX];

        out->send_msg = (mach_msg_header_t*)(uintptr_t)mv->msgv_data;
        out->rcv_msg  = (mach_msg_header_t*)(mv->msgv_rcv_addr ? (uintptr_t)mv->msgv_rcv_addr
                                                                : (uintptr_t)mv->msgv_data);
        out->send_size = mv->msgv_send_size;
        out->rcv_size  = mv->msgv_rcv_size;
        out->aux       = (void*)(uintptr_t)aux->msgv_data;
    } else {
        out->send_msg = (mach_msg_header_t*)data;
        out->rcv_msg  = (mach_msg_header_t*)data;
        out->aux      = NULL;
    }
}

__attribute__((used, noinline, visibility("default")))
void xniff_msg2_entry_hook(
    void*                 data,
    mach_msg_option64_t   option64,
    uint64_t              msgh_bits_and_send_size,
    uint64_t              msgh_remote_and_local_port,
    uint64_t              msgh_voucher_and_id,
    uint64_t              desc_count_and_rcv_name,
    uint64_t              rcv_size_and_priority,
    uint64_t              timeout)
{
    xniff_msg2_parsed_t p;
    xniff_parse_msg2_args(
        data, option64,
        msgh_bits_and_send_size,
        msgh_remote_and_local_port,
        msgh_voucher_and_id,
        desc_count_and_rcv_name,
        rcv_size_and_priority,
        timeout, &p);

    if (!p.send_msg) { return; }

    xniff_ipc_mach_payload_t pl = {0};
    pl.api = XNIFF_API_MACH_MSG2;
    pl.direction = XNIFF_DIR_ENTRY;
    pl.option_lo = (uint32_t)(option64 & 0xffffffffu);
    pl.option_hi = (uint32_t)(option64 >> 32);
    pl.timeout = p.timeout;
    pl.priority = p.priority;
    pl.desc_count = p.desc_count;
    pl.aux_addr = (uint64_t)(uintptr_t)p.aux;
    pl.args[0] = (uint64_t)(uintptr_t)data;
    pl.args[1] = (uint64_t)option64;
    pl.args[2] = msgh_bits_and_send_size;
    pl.args[3] = msgh_remote_and_local_port;
    pl.args[4] = msgh_voucher_and_id;
    pl.args[5] = desc_count_and_rcv_name;
    pl.args[6] = rcv_size_and_priority;
    pl.args[7] = timeout;
    ipc_send_msg_full(XNIFF_EVT_MACH2_ENTRY, &pl, p.send_msg);
}

__attribute__((used, noinline, visibility("default")))
void xniff_msg2_exit_hook(uint64_t ret, const xniff_ctx_frame_t* ctx)
{
    if (!ctx) { return; }

    void*               data     = (void*)ctx->x[0];
    mach_msg_option64_t option64 = (mach_msg_option64_t)ctx->x[1];
    uint64_t            bits_send= ctx->x[2];
    uint64_t            r_l      = ctx->x[3];
    uint64_t            v_id     = ctx->x[4];
    uint64_t            d_name   = ctx->x[5];
    uint64_t            r_p      = ctx->x[6];
    uint64_t            timeout  = ctx->x[7];

    xniff_msg2_parsed_t p;
    xniff_parse_msg2_args(
        data, option64, bits_send, r_l, v_id, d_name, r_p, timeout, &p);

    if ((p.option64 & MACH64_RCV_MSG) == 0) {
        return;
    }

    if (!p.rcv_msg) {
        return;
    }

    if (ret != MACH_MSG_SUCCESS) {
        return;
    }

    xniff_ipc_mach_payload_t pl = {0};
    pl.api = XNIFF_API_MACH_MSG2;
    pl.direction = XNIFF_DIR_EXIT;
    pl.option_lo = (uint32_t)(p.option64 & 0xffffffffu);
    pl.option_hi = (uint32_t)(p.option64 >> 32);
    pl.timeout = p.timeout;
    pl.priority = p.priority;
    pl.desc_count = p.desc_count;
    pl.aux_addr = (uint64_t)(uintptr_t)p.aux;
    pl.ret_value = ret;
    for (int i = 0; i < 8; i++) pl.args[i] = ctx->x[i];
    ipc_send_msg_full(XNIFF_EVT_MACH2_EXIT, &pl, p.rcv_msg);
}
