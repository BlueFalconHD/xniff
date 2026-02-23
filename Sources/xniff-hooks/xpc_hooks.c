// xniff-hooks: in-process Frida Gum hooks for Mach message tracing.
// This library is intended to be injected into a running process. It installs
// interceptors and streams events back to xniff-cli via the existing IPC protocol.

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
#include <limits.h>
#include <pthread.h>
#include <time.h>

#include "../shared/xniff_ipc.h"
#include "../shared/mach_private.h"

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/message.h>

#include "xniff_hooks_emit.h"
#include "xniff_hooks_ipc.h"

typedef struct {
    uint32_t max_msg_copy;       // max inline bytes copied per event
    uint32_t max_ool_total;      // max total OOL bytes per event (0 = unlimited)
    uint32_t max_ool_per_desc;   // max OOL bytes per descriptor (0 = unlimited)
    uint32_t max_desc;           // max descriptors walked
    uint32_t max_payload;        // max total IPC payload (excluding 20-byte header)
} xniff_hook_limits_t;

static xniff_hook_limits_t g_limits;
static pthread_once_t g_limits_once = PTHREAD_ONCE_INIT;

static uint32_t env_u32(const char *name, uint32_t defv) {
    const char *s = getenv(name);
    if (!s || !*s) return defv;
    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 0);
    if (errno != 0 || end == s) return defv;
    if (v > UINT32_MAX) return UINT32_MAX;
    return (uint32_t)v;
}

static void limits_init_once(void) {
    // Keep these conservative by default; tune via env vars when needed.
    g_limits.max_msg_copy     = env_u32("XNIFF_MAX_MSG_COPY",     256u * 1024u);
    g_limits.max_ool_total    = env_u32("XNIFF_MAX_OOL_TOTAL",    1024u * 1024u);
    g_limits.max_ool_per_desc = env_u32("XNIFF_MAX_OOL_PER_DESC", 256u * 1024u);
    g_limits.max_desc         = env_u32("XNIFF_MAX_DESCRIPTORS",  64u);
    g_limits.max_payload      = env_u32("XNIFF_MAX_IPC_PAYLOAD",  4u * 1024u * 1024u);
}

static const xniff_hook_limits_t *limits(void) {
    (void)pthread_once(&g_limits_once, limits_init_once);
    return &g_limits;
}

static size_t xniff_safe_copy(const void *src, void *dst, size_t len) {
    if (!src || !dst || len == 0) return 0;
    mach_vm_size_t out = 0;
    kern_return_t kr = mach_vm_read_overwrite(
        mach_task_self(),
        (mach_vm_address_t)(uintptr_t)src,
        (mach_vm_size_t)len,
        (mach_vm_address_t)(uintptr_t)dst,
        &out);
    if (kr != KERN_SUCCESS) return 0;
    if (out > (mach_vm_size_t)len) out = (mach_vm_size_t)len;
    return (size_t)out;
}

static inline uint32_t min_u32(uint32_t a, uint32_t b) { return a < b ? a : b; }

static uint32_t clamp_ool_bytes(uint64_t want, uint32_t elem_size, uint32_t *total_left_io) {
    uint32_t max_u32 = UINT32_MAX;
    uint32_t n = (want > (uint64_t)max_u32) ? max_u32 : (uint32_t)want;

    const xniff_hook_limits_t *lim = limits();
    if (lim->max_ool_per_desc != 0) n = min_u32(n, lim->max_ool_per_desc);

    if (total_left_io && *total_left_io != 0) n = min_u32(n, *total_left_io);

    if (elem_size != 0 && n >= elem_size) n -= (n % elem_size);
    if (total_left_io && *total_left_io != 0) *total_left_io -= n;
    return n;
}

static mach_msg_size_t safe_descriptor_count(const mach_msg_header_t *msg, uint32_t msg_bound, const uint8_t **out_base, const mach_msg_body_t **out_body, mach_msg_descriptor_t **out_desc) {
    if (!msg) return 0;
    if (!(msg->msgh_bits & MACH_MSGH_BITS_COMPLEX)) return 0;

    mach_msg_size_t total = msg->msgh_size;
    if (msg_bound != 0 && total > msg_bound) total = (mach_msg_size_t)msg_bound;
    if (total < sizeof(*msg) + sizeof(mach_msg_body_t)) return 0;

    const uint8_t *base = (const uint8_t *)msg;
    const mach_msg_body_t *body = (const mach_msg_body_t *)(base + sizeof(*msg));
    mach_msg_descriptor_t *desc = (mach_msg_descriptor_t *)((uint8_t *)body + sizeof(*body));

    mach_msg_size_t dcount = body->msgh_descriptor_count;
    mach_msg_size_t desc_bytes_avail = total - (mach_msg_size_t)(sizeof(*msg) + sizeof(*body));
    mach_msg_size_t max_by_size = desc_bytes_avail / (mach_msg_size_t)sizeof(mach_msg_descriptor_t);
    if (dcount > max_by_size) dcount = max_by_size;

    const xniff_hook_limits_t *lim = limits();
    if (lim->max_desc != 0 && dcount > (mach_msg_size_t)lim->max_desc) dcount = (mach_msg_size_t)lim->max_desc;

    if (out_base) *out_base = base;
    if (out_body) *out_body = body;
    if (out_desc) *out_desc = desc;
    return dcount;
}

static size_t attachments_size_for_msg_limited(const mach_msg_header_t *msg, uint32_t msg_bound) {
    if (!msg) return 0;

    mach_msg_descriptor_t *desc = NULL;
    mach_msg_size_t dcount = safe_descriptor_count(msg, msg_bound, NULL, NULL, &desc);
    if (dcount == 0) return 0;

    const xniff_hook_limits_t *lim = limits();
    uint32_t total_left = lim->max_ool_total ? lim->max_ool_total : 0; // 0 == unlimited

    size_t sum = 0;
    for (mach_msg_size_t i = 0; i < dcount; i++, desc++) {
        mach_msg_descriptor_type_t t = desc->type.type;
        if (t == MACH_MSG_OOL_DESCRIPTOR) {
            const mach_msg_ool_descriptor_t *ool = &desc->out_of_line;
            uint32_t n = clamp_ool_bytes((uint64_t)ool->size, 0, &total_left);
            if (n == 0) continue;
            size_t tlv = sizeof(xniff_ipc_tlv_t) + sizeof(xniff_ool_data_t) + (size_t)n;
            sum += tlv;
        } else if (t == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
            const mach_msg_ool_ports_descriptor_t *op = &desc->ool_ports;
            uint64_t ports_bytes64 = (uint64_t)op->count * (uint64_t)sizeof(mach_port_t);
            uint32_t n = clamp_ool_bytes(ports_bytes64, (uint32_t)sizeof(mach_port_t), &total_left);
            if (n == 0) continue;
            size_t tlv = sizeof(xniff_ipc_tlv_t) + sizeof(xniff_ool_ports_t) + (size_t)n;
            sum += tlv;
        }
    }
    return sum;
}

static void ipc_send_msg_full(int kind, const xniff_ipc_mach_payload_t *pl_in,
                              const mach_msg_header_t *msg,
                              uint32_t buf_size_hint) {
    if (!msg || !pl_in) return;
    uint8_t *msg_copy = NULL;
    uint8_t *scratch = NULL;
    size_t scratch_cap = 0;

    xniff_hooks_ipc_lock();

    const xniff_hook_limits_t *lim = limits();

    mach_msg_header_t hdr_copy;
    memset(&hdr_copy, 0, sizeof(hdr_copy));
    bool header_ok = xniff_safe_copy(msg, &hdr_copy, sizeof(hdr_copy)) == sizeof(hdr_copy);
    uint32_t raw_msgh_size = header_ok ? (uint32_t)hdr_copy.msgh_size : 0;

    // Treat msgh_size as "trusted" only when it is plausibly bounded by the caller's
    // receive buffer size and our configured maximum payload ceiling.
    bool msgh_size_ok = header_ok &&
                        (raw_msgh_size >= (uint32_t)sizeof(mach_msg_header_t)) &&
                        (buf_size_hint != 0 ? (raw_msgh_size <= buf_size_hint) : true) &&
                        (lim->max_payload == 0 || raw_msgh_size <= lim->max_payload);

    // Decide how many inline bytes to copy. If msgh_size is untrusted, fall back to
    // the caller-provided buffer size hint (if any).
    uint32_t copy_bound = 0;
    if (msgh_size_ok) {
        copy_bound = raw_msgh_size;

        // On successful receive, a trailer may be present after the rounded message size.
        // Capture enough bytes to include the requested trailer so the listener can extract
        // sender identity (audit token) without risking dereferencing invalid memory.
        mach_msg_option_t opt32 = (mach_msg_option_t)pl_in->option_lo;
        if ((opt32 & MACH_RCV_MSG) != 0 && buf_size_hint != 0 && buf_size_hint > raw_msgh_size) {
            mach_msg_trailer_size_t req = REQUESTED_TRAILER_SIZE(opt32);
            uint64_t want64 = (uint64_t)round_msg(raw_msgh_size) + (uint64_t)req;
            uint32_t want = (want64 > UINT32_MAX) ? UINT32_MAX : (uint32_t)want64;
            if (want > buf_size_hint) want = buf_size_hint;
            if (want > copy_bound) copy_bound = want;
        }
    } else if (buf_size_hint != 0) {
        copy_bound = buf_size_hint;
    }

    uint32_t copy_len = copy_bound;
    if (lim->max_msg_copy != 0 && copy_len > lim->max_msg_copy) copy_len = lim->max_msg_copy;
    if (!header_ok) copy_len = 0;

    // Safely copy message bytes out of the target's address space so we never dereference
    // a potentially-invalid pointer. If we can't read the header, don't attempt to copy.
    if (copy_len != 0 && header_ok) {
        msg_copy = (uint8_t *)calloc(1, (size_t)copy_len);
        if (msg_copy) {
            memcpy(msg_copy, &hdr_copy, (size_t)min_u32(copy_len, (uint32_t)sizeof(hdr_copy)));
            (void)xniff_safe_copy(msg, msg_copy, (size_t)copy_len);
        } else {
            copy_len = 0;
        }
    }

    // Compute attachment TLVs size from the safe message copy (bounded by what we copied).
    uint32_t msg_bound = 0;
    if (msgh_size_ok && copy_len != 0) {
        msg_bound = raw_msgh_size;
        if (buf_size_hint != 0 && msg_bound > buf_size_hint) msg_bound = buf_size_hint;
        if (msg_bound > copy_len) msg_bound = copy_len;
    }
    size_t att_sz = (msgh_size_ok && msg_bound != 0 && msg_copy != NULL)
                        ? attachments_size_for_msg_limited((const mach_msg_header_t *)msg_copy, msg_bound)
                        : 0;

    xniff_ipc_hdr_t hdr = {0};
    hdr.magic = XNIFF_IPC_MAGIC;
    hdr.version = XNIFF_IPC_VERSION;
    hdr.kind = (uint16_t)kind;
    hdr.pid = (uint32_t)getpid();
    hdr.tid_low = (uint32_t)(uintptr_t)pthread_self();

    uint64_t payload_len64 = (uint64_t)sizeof(xniff_ipc_mach_payload_t) + (uint64_t)copy_len + (uint64_t)att_sz;
    if (lim->max_payload != 0 && payload_len64 > lim->max_payload) {
        // Prefer truncating attachments first, then inline bytes.
        uint64_t over = payload_len64 - lim->max_payload;
        if (att_sz >= over) {
            att_sz -= (size_t)over;
        } else {
            over -= att_sz;
            att_sz = 0;
            if (over >= copy_len) copy_len = 0;
            else copy_len -= (uint32_t)over;
        }
        payload_len64 = (uint64_t)sizeof(xniff_ipc_mach_payload_t) + (uint64_t)copy_len + (uint64_t)att_sz;
    }
    if (payload_len64 > UINT32_MAX) {
        // Hard fail-safe: keep within the wire format.
        uint64_t max = UINT32_MAX;
        if (payload_len64 > max) {
            uint64_t keep = (uint64_t)sizeof(xniff_ipc_mach_payload_t);
            if (keep > max) { xniff_hooks_ipc_unlock(); return; }
            uint64_t left = max - keep;
            uint64_t keep_inline = (copy_len > left) ? left : copy_len;
            left -= keep_inline;
            uint64_t keep_att = ((uint64_t)att_sz > left) ? left : (uint64_t)att_sz;
            copy_len = (uint32_t)keep_inline;
            att_sz = (size_t)keep_att;
            payload_len64 = keep + keep_inline + keep_att;
        }
    }
    hdr.payload_len = (uint32_t)payload_len64;

    xniff_ipc_mach_payload_t pl = *pl_in;
    pl.msgh_size = header_ok ? raw_msgh_size : 0;
    pl.copy_len = copy_len;
    pl.msg_addr = (uint64_t)(uintptr_t)msg;

    // Send header, payload, and inline bytes (blocking to ensure ordering)
    if (xniff_hooks_ipc_write_locked(&hdr, sizeof(hdr)) != 0) goto out;
    if (xniff_hooks_ipc_write_locked(&pl, sizeof(pl)) != 0) goto out;
    if (copy_len && msg_copy && xniff_hooks_ipc_write_locked(msg_copy, copy_len) != 0) goto out;

    // Send attachments
    if (att_sz != 0 && msgh_size_ok && msg_copy) {
        mach_msg_descriptor_t *desc2 = NULL;
        mach_msg_size_t dcount = safe_descriptor_count((const mach_msg_header_t *)msg_copy, msg_bound, NULL, NULL, &desc2);
        uint32_t total_left = lim->max_ool_total ? lim->max_ool_total : 0;
        size_t att_left = att_sz;
        for (mach_msg_size_t i = 0; i < dcount; i++, desc2++) {
            if (att_left < sizeof(xniff_ipc_tlv_t)) break;
            mach_msg_descriptor_type_t t = desc2->type.type;
            if (t == MACH_MSG_OOL_DESCRIPTOR) {
                const mach_msg_ool_descriptor_t *ool = &desc2->out_of_line;
                uint32_t n = clamp_ool_bytes((uint64_t)ool->size, 0, &total_left);
                size_t overhead = sizeof(xniff_ipc_tlv_t) + sizeof(xniff_ool_data_t);
                if (att_left <= overhead) break;
                size_t max_data_sz = att_left - overhead;
                if (max_data_sz < n) n = (uint32_t)max_data_sz;
                if (n == 0) break;
                if ((uint64_t)sizeof(xniff_ool_data_t) + (uint64_t)n > UINT32_MAX) continue;
                xniff_ipc_tlv_t h = { .type = XNIFF_TLV_OOL_DATA, .length = (uint32_t)(sizeof(xniff_ool_data_t) + n) };
                xniff_ool_data_t md = {0};
                md.index = (uint32_t)i;
                md.flags = (ool->deallocate ? 1u : 0u) | (ool->copy ? 2u : 0u);
                md.address = (uint64_t)(uintptr_t)ool->address;
                md.size = n;
                if (xniff_hooks_ipc_write_locked(&h, sizeof(h)) != 0) goto out;
                if (xniff_hooks_ipc_write_locked(&md, sizeof(md)) != 0) goto out;
                if ((size_t)n > scratch_cap) {
                    uint8_t *ns = (uint8_t *)realloc(scratch, (size_t)n);
                    if (!ns) goto out;
                    scratch = ns;
                    scratch_cap = (size_t)n;
                }
                if (scratch && n) {
                    memset(scratch, 0, (size_t)n);
                    if (ool->address) (void)xniff_safe_copy(ool->address, scratch, (size_t)n);
                    if (xniff_hooks_ipc_write_locked(scratch, (size_t)n) != 0) goto out;
                }
                att_left -= (overhead + (size_t)n);
            } else if (t == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
                const mach_msg_ool_ports_descriptor_t *op = &desc2->ool_ports;
                uint64_t ports_bytes64 = (uint64_t)op->count * (uint64_t)sizeof(mach_port_t);
                uint32_t n = clamp_ool_bytes(ports_bytes64, (uint32_t)sizeof(mach_port_t), &total_left);
                size_t overhead = sizeof(xniff_ipc_tlv_t) + sizeof(xniff_ool_ports_t);
                if (att_left <= overhead) break;
                size_t max_data_sz = att_left - overhead;
                if (max_data_sz < n) n = (uint32_t)max_data_sz;
                n -= (n % (uint32_t)sizeof(mach_port_t));
                if (n == 0) break;
                uint32_t send_count = n / (uint32_t)sizeof(mach_port_t);
                if ((uint64_t)sizeof(xniff_ool_ports_t) + (uint64_t)n > UINT32_MAX) continue;
                xniff_ipc_tlv_t h = { .type = XNIFF_TLV_OOL_PORTS, .length = (uint32_t)(sizeof(xniff_ool_ports_t) + n) };
                xniff_ool_ports_t md = {0};
                md.index = (uint32_t)i;
                md.count = send_count;
                md.address = (uint64_t)(uintptr_t)op->address;
                md.elem_size = (uint32_t)sizeof(mach_port_t);
                if (xniff_hooks_ipc_write_locked(&h, sizeof(h)) != 0) goto out;
                if (xniff_hooks_ipc_write_locked(&md, sizeof(md)) != 0) goto out;
                if ((size_t)n > scratch_cap) {
                    uint8_t *ns = (uint8_t *)realloc(scratch, (size_t)n);
                    if (!ns) goto out;
                    scratch = ns;
                    scratch_cap = (size_t)n;
                }
                if (scratch && n) {
                    memset(scratch, 0, (size_t)n);
                    if (op->address) (void)xniff_safe_copy(op->address, scratch, (size_t)n);
                    if (xniff_hooks_ipc_write_locked(scratch, (size_t)n) != 0) goto out;
                }
                att_left -= (overhead + (size_t)n);
            }
        }
    }
out:
    if (scratch) free(scratch);
    if (msg_copy) free(msg_copy);
    xniff_hooks_ipc_unlock();
}

void xniff_emit_mach_msg_entry(const uint64_t args[8]) {
    if (!args) return;
    mach_msg_header_t *msg = (mach_msg_header_t *)(uintptr_t)args[0];
    mach_msg_option_t option = (mach_msg_option_t)args[1];
    uint32_t send_size = (uint32_t)args[2];
    uint32_t rcv_size  = (uint32_t)args[3];
    uint32_t buf_hint = 0;
    if (option & MACH_SEND_MSG) buf_hint = send_size;
    else if (option & MACH_RCV_MSG) buf_hint = rcv_size;
    xniff_ipc_mach_payload_t pl = {0};
    pl.api = XNIFF_API_MACH_MSG;
    pl.direction = XNIFF_DIR_ENTRY;
    pl.option_lo = (uint32_t)option;
    pl.option_hi = 0;
    pl.ret_value = 0;
    pl.desc_count = 0;
    pl.priority = 0;
    pl.timeout = args[5];
    for (int i = 0; i < 8; i++) pl.args[i] = args[i];
    ipc_send_msg_full(XNIFF_EVT_MACH_ENTRY, &pl, msg, buf_hint);
}

void xniff_emit_mach_msg_exit(uint64_t ret, const uint64_t args[8], int has_separate_rcv_msg) {
    if (!args) return;
    mach_msg_option_t option = (mach_msg_option_t)args[1];
    uint32_t send_size = (uint32_t)args[2];
    uint32_t rcv_size  = (uint32_t)args[3];

    bool have_rcv = (option & MACH_RCV_MSG) && (ret == MACH_MSG_SUCCESS);
    uint64_t rcv_ptr = (has_separate_rcv_msg && args[7]) ? args[7] : args[0];
    mach_msg_header_t* msg = (mach_msg_header_t *)(uintptr_t)(have_rcv ? rcv_ptr : args[0]);
    if (!msg) return;
    uint32_t buf_hint = have_rcv ? rcv_size : send_size;

    xniff_ipc_mach_payload_t pl = {0};
    pl.api = XNIFF_API_MACH_MSG;
    pl.direction = XNIFF_DIR_EXIT;
    pl.option_lo = (uint32_t)option;
    pl.ret_value = ret;
    for (int i = 0; i < 8; i++) pl.args[i] = args[i];
    pl.timeout = args[5];
    ipc_send_msg_full(XNIFF_EVT_MACH_EXIT, &pl, msg, buf_hint);
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

void xniff_emit_mach_msg2_entry(const uint64_t args[8]) {
    if (!args) return;

    void *data = (void *)(uintptr_t)args[0];
    mach_msg_option64_t option64 = (mach_msg_option64_t)args[1];
    uint64_t msgh_bits_and_send_size = args[2];
    uint64_t msgh_remote_and_local_port = args[3];
    uint64_t msgh_voucher_and_id = args[4];
    uint64_t desc_count_and_rcv_name = args[5];
    uint64_t rcv_size_and_priority = args[6];
    uint64_t timeout = args[7];

    xniff_msg2_parsed_t p;
    xniff_parse_msg2_args(
        data, option64,
        msgh_bits_and_send_size,
        msgh_remote_and_local_port,
        msgh_voucher_and_id,
        desc_count_and_rcv_name,
        rcv_size_and_priority,
        timeout, &p);

    if (!p.send_msg) return;
    uint32_t buf_hint = 0;
    if (p.option64 & MACH64_SEND_MSG) buf_hint = p.send_size;
    else if (p.option64 & MACH64_RCV_MSG) buf_hint = p.rcv_size;

    xniff_ipc_mach_payload_t pl = {0};
    pl.api = XNIFF_API_MACH_MSG2;
    pl.direction = XNIFF_DIR_ENTRY;
    pl.option_lo = (uint32_t)(option64 & 0xffffffffu);
    pl.option_hi = (uint32_t)(option64 >> 32);
    pl.timeout = p.timeout;
    pl.priority = p.priority;
    pl.desc_count = p.desc_count;
    pl.aux_addr = (uint64_t)(uintptr_t)p.aux;
    for (int i = 0; i < 8; i++) pl.args[i] = args[i];
    ipc_send_msg_full(XNIFF_EVT_MACH2_ENTRY, &pl, p.send_msg, buf_hint);
}

void xniff_emit_mach_msg2_exit(uint64_t ret, const uint64_t args[8]) {
    if (!args) return;

    void*               data     = (void *)(uintptr_t)args[0];
    mach_msg_option64_t option64 = (mach_msg_option64_t)args[1];
    uint64_t            bits_send= args[2];
    uint64_t            r_l      = args[3];
    uint64_t            v_id     = args[4];
    uint64_t            d_name   = args[5];
    uint64_t            r_p      = args[6];
    uint64_t            timeout  = args[7];

    xniff_msg2_parsed_t p;
    xniff_parse_msg2_args(
        data, option64, bits_send, r_l, v_id, d_name, r_p, timeout, &p);

    mach_msg_header_t *out_msg = NULL;
    uint32_t out_hint = 0;
    if ((p.option64 & MACH64_RCV_MSG) && p.rcv_msg && ret == MACH_MSG_SUCCESS) {
        out_msg = p.rcv_msg;
        out_hint = p.rcv_size;
    } else if (p.send_msg) {
        out_msg = p.send_msg;
        out_hint = p.send_size;
    } else if (p.rcv_msg) {
        out_msg = p.rcv_msg;
        out_hint = p.rcv_size;
    } else {
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
    for (int i = 0; i < 8; i++) pl.args[i] = args[i];
    ipc_send_msg_full(XNIFF_EVT_MACH2_EXIT, &pl, out_msg, out_hint);
}

// Legacy trampoline hook entrypoints removed (Frida Gum handles interception).
