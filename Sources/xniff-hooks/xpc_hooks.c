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
#include <pthread.h>

#include "../shared/xniff_ipc.h"

#include <mach/mach.h>
#include <mach/message.h>

// Context frame layout expected by the extended trampoline used by xniff.
// Keep in sync with tramp_ex_template.S ring frame layout (128 bytes).
typedef struct xniff_ctx_frame {
    // Saved at entry
    uint64_t lr_orig;      // +0x00: original LR (return target)
    uint64_t resume_pc;    // +0x08: resume PC (after entry patch window)

    // Register arguments snapshot at entry
    uint64_t x[8];         // +0x10..+0x48: x0..x7 (8 × 8 bytes)

    // Saved at exit
    uint64_t ret;          // +0x50: function return value (from x0 at exit)

    // Pad to fixed 128-byte frame size (one frame per 0x80)
    uint8_t  reserved[0x80 - 0x58]; // 0x28 bytes
} xniff_ctx_frame_t;

_Static_assert(sizeof(xniff_ctx_frame_t) == 0x80, "xniff_ctx_frame_t must be 128 bytes");

static const char *disp_to_str(mach_msg_bits_t disp) {
    switch (disp) {
    case MACH_MSG_TYPE_MOVE_SEND:      return "MOVE_SEND";
    case MACH_MSG_TYPE_COPY_SEND:      return "COPY_SEND";
    case MACH_MSG_TYPE_MAKE_SEND:      return "MAKE_SEND";
    case MACH_MSG_TYPE_MOVE_RECEIVE:   return "MOVE_RECEIVE";
    case MACH_MSG_TYPE_MOVE_SEND_ONCE: return "MOVE_SEND_ONCE";
    case MACH_MSG_TYPE_MAKE_SEND_ONCE: return "MAKE_SEND_ONCE";
    default:                           return "UNKNOWN";
    }
}

static void print_msg_bits(mach_msg_bits_t bits) {
    mach_msg_bits_t remote  = MACH_MSGH_BITS_REMOTE(bits);
    mach_msg_bits_t local   = MACH_MSGH_BITS_LOCAL(bits);
#if defined(MACH_MSGH_BITS_VOUCHER)
    mach_msg_bits_t voucher = MACH_MSGH_BITS_VOUCHER(bits);
#endif

    printf("  msgh_bits: 0x%08x\n", (unsigned)bits);
    printf("    remote disp : 0x%02x (%s)\n",
           (unsigned)remote, disp_to_str(remote));
    printf("    local  disp : 0x%02x (%s)\n",
           (unsigned)local, disp_to_str(local));
#if defined(MACH_MSGH_BITS_VOUCHER)
    printf("    voucher disp: 0x%02x (%s)\n",
           (unsigned)voucher, disp_to_str(voucher));
#endif

#ifdef MACH_MSGH_BITS_COMPLEX
    printf("    flags       :");
    if (bits & MACH_MSGH_BITS_COMPLEX)   printf(" COMPLEX");
#endif
#ifdef MACH_MSGH_BITS_CIRCULAR
    if (bits & MACH_MSGH_BITS_CIRCULAR)  printf(" CIRCULAR");
#endif
    if (!(bits & (MACH_MSGH_BITS_COMPLEX
#ifdef MACH_MSGH_BITS_CIRCULAR
                  | MACH_MSGH_BITS_CIRCULAR
#endif
                  ))) {
        printf(" (none)");
    }
    printf("\n");
}

static void print_msg_options(mach_msg_option_t option) {
    printf("  options : 0x%08x\n", (unsigned)option);
    printf("    flags :");

    int printed = 0;

#ifdef MACH_SEND_MSG
    if (option & MACH_SEND_MSG)        { printf(" SEND_MSG"); printed = 1; }
#endif
#ifdef MACH_RCV_MSG
    if (option & MACH_RCV_MSG)         { printf(" RCV_MSG"); printed = 1; }
#endif
#ifdef MACH_SEND_TIMEOUT
    if (option & MACH_SEND_TIMEOUT)    { printf(" SEND_TIMEOUT"); printed = 1; }
#endif
#ifdef MACH_RCV_TIMEOUT
    if (option & MACH_RCV_TIMEOUT)     { printf(" RCV_TIMEOUT"); printed = 1; }
#endif
#ifdef MACH_SEND_INTERRUPT
    if (option & MACH_SEND_INTERRUPT)  { printf(" SEND_INTERRUPT"); printed = 1; }
#endif
#ifdef MACH_RCV_INTERRUPT
    if (option & MACH_RCV_INTERRUPT)   { printf(" RCV_INTERRUPT"); printed = 1; }
#endif
#ifdef MACH_RCV_LARGE
    if (option & MACH_RCV_LARGE)       { printf(" RCV_LARGE"); printed = 1; }
#endif
#ifdef MACH_SEND_NOTIFY
    if (option & MACH_SEND_NOTIFY)     { printf(" SEND_NOTIFY"); printed = 1; }
#endif

    if (!printed)
        printf(" (none)");

    printf("\n");
}

static void hexdump_body(const mach_msg_header_t *msg) {
    const uint8_t *base = (const uint8_t *)msg;
    mach_msg_size_t total = msg->msgh_size;

    if (total <= sizeof(*msg)) {
        printf("  body   : <no body> (msgh_size <= sizeof(header))\n");
        return;
    }

    const uint8_t *body = base + sizeof(*msg);
    mach_msg_size_t body_len = total - (mach_msg_size_t)sizeof(*msg);

    const mach_msg_size_t max_dump = 128;
    if (body_len > max_dump)
        body_len = max_dump;

    printf("  body   : %u bytes (showing %u bytes)\n",
           (unsigned)(msg->msgh_size - (mach_msg_size_t)sizeof(*msg)),
           (unsigned)body_len);

    for (mach_msg_size_t i = 0; i < body_len; i += 16) {
        printf("    %04x : ", (unsigned)i);

        for (mach_msg_size_t j = 0; j < 16; ++j) {
            mach_msg_size_t idx = i + j;
            if (idx < body_len)
                printf("%02x ", body[idx]);
            else
                printf("   ");
        }

        printf(" |");

        for (mach_msg_size_t j = 0; j < 16 && (i + j) < body_len; ++j) {
            unsigned char c = body[i + j];
            printf("%c", isprint(c) ? c : '.');
        }

        printf("|\n");
    }
}

static void hexdump_ool(const void *addr, mach_msg_size_t size,
                        const char *label)
{
    if (!addr || size == 0) {
        printf("  %s: <empty>\n", label);
        return;
    }

    const uint8_t *p = (const uint8_t *)addr;
    mach_msg_size_t max_dump = 256; // keep this sane
    if (size > max_dump)
        size = max_dump;

    printf("  %s: %u bytes (showing %u bytes)\n",
           label, (unsigned)size, (unsigned)size);

    for (mach_msg_size_t i = 0; i < size; i += 16) {
        printf("    %04x : ", (unsigned)i);

        // hex
        for (mach_msg_size_t j = 0; j < 16; ++j) {
            mach_msg_size_t idx = i + j;
            if (idx < size)
                printf("%02x ", p[idx]);
            else
                printf("   ");
        }

        // ascii
        printf(" |");
        for (mach_msg_size_t j = 0; j < 16 && (i + j) < size; ++j) {
            unsigned char c = p[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("|\n");
    }
}

static void dump_complex_message(const mach_msg_header_t *msg)
{
    const uint8_t *base   = (const uint8_t *)msg;
    mach_msg_size_t total = msg->msgh_size;

    if (total < sizeof(*msg) + sizeof(mach_msg_body_t)) {
        printf("  body   : <invalid complex message: too small>\n");
        return;
    }

    const mach_msg_body_t *body =
        (const mach_msg_body_t *)(base + sizeof(*msg));
    mach_msg_descriptor_t *desc =
        (mach_msg_descriptor_t *)((uint8_t *)body + sizeof(*body));
    mach_msg_size_t dcount = body->msgh_descriptor_count;

    printf("  body   : COMPLEX message\n");
    printf("    descriptor_count: %u\n", (unsigned)dcount);

    for (mach_msg_size_t i = 0; i < dcount; i++, desc++) {
        mach_msg_descriptor_type_t t = desc->type.type;

        printf("    descriptor[%u]: ", (unsigned)i);

        switch (t) {
        case MACH_MSG_PORT_DESCRIPTOR: {
            mach_msg_port_descriptor_t *p = &desc->port;
            printf("PORT name=0x%08x disp=%u\n",
                   (unsigned)p->name, p->disposition);
            break;
        }

        case MACH_MSG_OOL_DESCRIPTOR: {
            mach_msg_ool_descriptor_t *ool = &desc->out_of_line;
            printf("OOL addr=%p size=%u deallocate=%u copy=%u\n",
                   ool->address,
                   (unsigned)ool->size,
                   (unsigned)ool->deallocate,
                   (unsigned)ool->copy);
            hexdump_ool(ool->address, ool->size, "    OOL data");
            break;
        }

        case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
            mach_msg_ool_ports_descriptor_t *op = &desc->ool_ports;
            printf("OOL_PORTS addr=%p count=%u disp=%u deallocate=%u copy=%u\n",
                   op->address,
                   (unsigned)op->count,
                   (unsigned)op->disposition,
                   (unsigned)op->deallocate,
                   (unsigned)op->copy);
            hexdump_ool(op->address,
                        op->count * sizeof(mach_port_t),
                        "    OOL ports array");
            break;
        }

#ifdef MACH_MSG_GUARDED_PORT_DESCRIPTOR
        case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
            mach_msg_guarded_port_descriptor_t *gp = &desc->guarded_port;
            printf("GUARDED_PORT name=0x%08x disp=%u guard=0x%llx flags=0x%x\n",
                   (unsigned)gp->name,
                   gp->disposition,
                   (unsigned long long)gp->context,
                   (unsigned)gp->flags);
            break;
        }
#endif

        default:
            printf("UNKNOWN descriptor type=%u\n", (unsigned)t);
            break;
        }
    }

    const uint8_t *after_desc = (const uint8_t *)desc;
    if (after_desc < base + total) {
        mach_msg_size_t inline_len = (mach_msg_size_t)(base + total - after_desc);
        printf("    inline payload after descriptors: %u bytes\n",
               (unsigned)inline_len);

        const uint8_t *p = after_desc;
        mach_msg_size_t max_dump = inline_len > 128 ? 128 : inline_len;
        for (mach_msg_size_t i = 0; i < max_dump; i += 16) {
            printf("      %04x : ", (unsigned)i);
            for (mach_msg_size_t j = 0; j < 16; ++j) {
                mach_msg_size_t idx = i + j;
                if (idx < max_dump)
                    printf("%02x ", p[idx]);
                else
                    printf("   ");
            }
            printf(" |");
            for (mach_msg_size_t j = 0; j < 16 && (i + j) < max_dump; ++j) {
                unsigned char c = p[i + j];
                printf("%c", isprint(c) ? c : '.');
            }
            printf("|\n");
        }
    }
}

static void dump_message_body(const mach_msg_header_t *msg)
{
    if (msg->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
        dump_complex_message(msg);
    } else {
        hexdump_body(msg);
    }
}

static int g_ipc_fd = -1; // lazily connect per-process

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
    if (g_ipc_fd == -1) {
        int fd = xniff_ipc_client_connect(getpid());
        if (fd >= 0) g_ipc_fd = fd;
    }
    if (g_ipc_fd < 0) return; // no server; silently drop

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
    if (xniff_ipc_send_all(g_ipc_fd, &hdr, sizeof(hdr)) != 0) return;
    if (xniff_ipc_send_all(g_ipc_fd, &pl, sizeof(pl)) != 0) return;
    if (xniff_ipc_send_all(g_ipc_fd, base, copy_len) != 0) return;

    // Send attachments
    if (msg->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
        if (copy_len >= sizeof(*msg) + sizeof(mach_msg_body_t)) {
            const mach_msg_body_t *body = (const mach_msg_body_t *)(base + sizeof(*msg));
            mach_msg_descriptor_t *desc = (mach_msg_descriptor_t *)((uint8_t *)body + sizeof(*body));
            mach_msg_size_t dcount = body->msgh_descriptor_count;
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
                    (void)xniff_ipc_send_all(g_ipc_fd, &h, sizeof(h));
                    (void)xniff_ipc_send_all(g_ipc_fd, &md, sizeof(md));
                    if (ool->address && ool->size)
                        (void)xniff_ipc_send_all(g_ipc_fd, ool->address, ool->size);
                } else if (t == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
                    const mach_msg_ool_ports_descriptor_t *op = &desc->ool_ports;
                    size_t ports_bytes = (size_t)op->count * sizeof(mach_port_t);
                    xniff_ipc_tlv_t h = { .type = XNIFF_TLV_OOL_PORTS, .length = (uint32_t)(sizeof(xniff_ool_ports_t) + ports_bytes) };
                    xniff_ool_ports_t md = {0};
                    md.index = (uint32_t)i;
                    md.count = (uint32_t)op->count;
                    md.address = (uint64_t)(uintptr_t)op->address;
                    md.elem_size = (uint32_t)sizeof(mach_port_t);
                    (void)xniff_ipc_send_all(g_ipc_fd, &h, sizeof(h));
                    (void)xniff_ipc_send_all(g_ipc_fd, &md, sizeof(md));
                    if (op->address && ports_bytes)
                        (void)xniff_ipc_send_all(g_ipc_fd, op->address, ports_bytes);
                }
            }
        }
    }
}

static void write_dump_files(const mach_msg_header_t *msg, const char *tag) {
    if (!msg) return;

    const char *dir_path = "/tmp/xpc";
    mkdir(dir_path, 0755);

    char identifier[32];
    snprintf(identifier, sizeof(identifier), "%p", (void *)msg);

    char meta_path[256];
    char body_path[256];
    snprintf(meta_path, sizeof(meta_path), "%s/%s_%d_%s.msg",
             dir_path, tag, getpid(), identifier);
    snprintf(body_path, sizeof(body_path), "%s/%s_%d_%s.bin",
             dir_path, tag, getpid(), identifier);

    FILE *meta = fopen(meta_path, "w");
    if (meta) {
        fprintf(meta, "PID: %d\n", getpid());
        fprintf(meta, "Tag: %s\n", tag);
        fprintf(meta, "Message address: %p\n", (void*)msg);
        fprintf(meta, "msgh_bits: 0x%08x\n", (unsigned)msg->msgh_bits);
        fprintf(meta, "msgh_size: %u\n", (unsigned)msg->msgh_size);
        fprintf(meta, "msgh_remote_port: 0x%08x\n", (unsigned)msg->msgh_remote_port);
        fprintf(meta, "msgh_local_port:  0x%08x\n", (unsigned)msg->msgh_local_port);
        fprintf(meta, "msgh_id: %d (0x%08x)\n", msg->msgh_id, (unsigned)msg->msgh_id);
        fclose(meta);
    } else {
        perror("fopen meta");
    }

    FILE *body = fopen(body_path, "wb");
    if (body) {
        fwrite(msg, 1, msg->msgh_size, body);
        fclose(body);
    } else {
        perror("fopen body");
    }

    if (!(msg->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
        return;
    }

    const uint8_t *base   = (const uint8_t *)msg;
    mach_msg_size_t total = msg->msgh_size;

    if (total < sizeof(*msg) + sizeof(mach_msg_body_t)) {
        return;
    }

    const mach_msg_body_t *body_hdr =
        (const mach_msg_body_t *)(base + sizeof(*msg));
    mach_msg_descriptor_t *desc =
        (mach_msg_descriptor_t *)((uint8_t *)body_hdr + sizeof(*body_hdr));
    mach_msg_size_t dcount = body_hdr->msgh_descriptor_count;

    for (mach_msg_size_t i = 0; i < dcount; i++, desc++) {
        mach_msg_descriptor_type_t t = desc->type.type;

        if (t == MACH_MSG_OOL_DESCRIPTOR) {
            mach_msg_ool_descriptor_t *ool = &desc->out_of_line;

            if (!ool->address || ool->size == 0) continue;

            char ool_path[256];
            snprintf(ool_path, sizeof(ool_path),
                     "%s/%s_%d_%s_ool%u.bin",
                     dir_path, tag, getpid(), identifier,
                     (unsigned)i);

            FILE *f = fopen(ool_path, "wb");
            if (f) {
                fwrite(ool->address, 1, ool->size, f);
                fclose(f);
            } else {
                perror("fopen ool");
            }
        } else if (t == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
            mach_msg_ool_ports_descriptor_t *op = &desc->ool_ports;

            if (!op->address || op->count == 0) continue;

            char ool_ports_path[256];
            snprintf(ool_ports_path, sizeof(ool_ports_path),
                     "%s/%s_%d_%s_ool_ports%u.bin",
                     dir_path, tag, getpid(), identifier,
                     (unsigned)i);

            FILE *f = fopen(ool_ports_path, "wb");
            if (f) {
                fwrite(op->address, sizeof(mach_port_t), op->count, f);
                fclose(f);
            } else {
                perror("fopen ool_ports");
            }
        }
    }
}

__attribute__((used, noinline, visibility("default")))
void xniff_remote_entry_hook(mach_msg_header_t *msg, mach_msg_option_t option) {
    printf("::: xniff_remote_entry_hook: intercepted call :::\n");
    // Build IPC payload (v1)
    xniff_ipc_mach_payload_t pl = {0};
    pl.api = XNIFF_API_MACH_MSG;
    pl.direction = XNIFF_DIR_ENTRY;
    pl.option_lo = (uint32_t)option;
    pl.option_hi = 0;
    pl.ret_value = 0;
    pl.desc_count = 0;
    pl.priority = 0;
    pl.timeout = 0; // unknown at entry for v1
    // args[0..1] available from this hook signature
    pl.args[0] = (uint64_t)(uintptr_t)msg;
    pl.args[1] = (uint64_t)option;
    ipc_send_msg_full(XNIFF_EVT_MACH_ENTRY, &pl, msg);
    write_dump_files(msg, "entry");

    if (!msg) {
        printf("  (null mach_msg_header_t *)\n");
        return;
    }

    printf("  address: %p\n", (void *)msg);

    print_msg_options(option);
    print_msg_bits(msg->msgh_bits);

    printf("  size   : %u bytes\n", (unsigned)msg->msgh_size);
    printf("  remote : 0x%08x\n", (unsigned)msg->msgh_remote_port);
    printf("  local  : 0x%08x\n", (unsigned)msg->msgh_local_port);
#if defined(__APPLE__) && __has_include(<mach/message.h>)
    printf("  voucher: 0x%08x\n", (unsigned)msg->msgh_voucher_port);
#else
    printf("  reserved/voucher: 0x%08x\n", (unsigned)msg->msgh_reserved);
#endif

    printf("  msgh_id: %d (0x%08x)\n",
           msg->msgh_id,
           (unsigned)msg->msgh_id);

    dump_message_body(msg);
}

__attribute__((used, noinline, visibility("default")))
void xniff_remote_exit_hook(uint64_t ret, const xniff_ctx_frame_t* ctx) {
    printf("::: xniff_remote_exit_hook: intercepted return :::\n");
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
            // capture args from ctx snapshot at entry
            for (int i = 0; i < 8; i++) pl.args[i] = ctx->x[i];
            // timeout is x5 for v1 signature
            pl.timeout = ctx->x[5];
            ipc_send_msg_full(XNIFF_EVT_MACH_EXIT, &pl, reply);
            write_dump_files(reply, "exit");
        }
    }

    printf("  return value: 0x%llx\n", (unsigned long long)ret);

    if (!ctx) { printf("  (null ctx)\n"); return; }

    const int did_recv = (option & MACH_RCV_MSG) != 0;

    if (!did_recv) {
        return;
    }

    mach_msg_header_t* reply = (mach_msg_header_t*)(ctx->x[7] ? ctx->x[7] : ctx->x[0]);

    printf("::: reply buffer: %p\n", (void*)reply);
    print_msg_options(option);

    if (!reply) { printf("  (null reply)\n"); return; }

    if (ret != MACH_MSG_SUCCESS) {
        printf("  receive not successful; ret=0x%llx — header may be invalid\n", (unsigned long long)ret);
        return;
    }

    print_msg_bits(reply->msgh_bits);
    printf("  size   : %u bytes\n", (unsigned)reply->msgh_size);
    printf("  remote : 0x%08x\n", (unsigned)reply->msgh_remote_port);
    printf("  local  : 0x%08x\n", (unsigned)reply->msgh_local_port);
#if defined(__APPLE__) && __has_include(<mach/message.h>)
    printf("  voucher: 0x%08x\n", (unsigned)reply->msgh_voucher_port);
#else
    printf("  reserved/voucher: 0x%08x\n", (unsigned)reply->msgh_reserved);
#endif
    printf("  msgh_id: %d (0x%08x)\n", reply->msgh_id, (unsigned)reply->msgh_id);

    dump_message_body(reply);
}

// ---- mach_msg2 helpers and hooks ----

#ifndef mach_msg_option64_t
typedef uint64_t mach_msg_option64_t;
#endif

#ifndef MACH64_SEND_MSG
#define MACH64_SEND_MSG 0x0000000000000001ull
#endif
#ifndef MACH64_RCV_MSG
#define MACH64_RCV_MSG  0x0000000000000002ull
#endif
#ifndef MACH64_MSG_VECTOR
#define MACH64_MSG_VECTOR 0x0000000100000000ull
#endif
#ifndef MACH64_SEND_KOBJECT_CALL
#define MACH64_SEND_KOBJECT_CALL 0x0000000200000000ull
#endif
#ifndef MACH64_SEND_MQ_CALL
#define MACH64_SEND_MQ_CALL 0x0000000400000000ull
#endif
#ifndef MACH64_SEND_ANY
#define MACH64_SEND_ANY 0x0000000800000000ull
#endif
#ifndef MACH64_SEND_DK_CALL
#define MACH64_SEND_DK_CALL 0x0000001000000000ull
#endif
#ifndef MACH64_RCV_TIMEOUT
#define MACH64_RCV_TIMEOUT 0x0000000000000010ull
#endif
#ifndef MACH64_SEND_TIMEOUT
#define MACH64_SEND_TIMEOUT 0x0000000000000004ull
#endif
#ifndef MACH64_RCV_LARGE
#define MACH64_RCV_LARGE 0x0000000000000100ull
#endif
#ifndef MACH64_RCV_VOUCHER
#define MACH64_RCV_VOUCHER 0x0000000000000200ull
#endif
#ifndef MACH64_RCV_SYNC_WAIT
#define MACH64_RCV_SYNC_WAIT 0x0000000000000800ull
#endif

#ifndef MACH_MSGV_MAX_COUNT
#define MACH_MSGV_IDX_MSG 0
#define MACH_MSGV_IDX_AUX 1
typedef struct {
    uint64_t        msgv_data;     /* mach_msg_header_t* or aux header */
    uint64_t        msgv_rcv_addr; /* optional distinct receive buffer */
    uint32_t        msgv_send_size;
    uint32_t        msgv_rcv_size;
} mach_msg_vector_t;
#endif

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

    mach_msg_option64_t option64;
    bool               is_vector;
} xniff_msg2_parsed_t;

static inline void xniff_unpack_u32x2(uint64_t v, uint32_t* lo, uint32_t* hi) {
    if (lo) *lo = (uint32_t)(v & 0xffffffffu);
    if (hi) *hi = (uint32_t)(v >> 32);
}

static inline void xniff_parse_msg2_args(
    void* data,
    mach_msg_option64_t option64,
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

static void print_msg_options64(mach_msg_option64_t opt)
{
    printf("  options64: 0x%016llx\n", (unsigned long long)opt);
    printf("    flags   :");

    int printed = 0;
    if (opt & MACH64_SEND_MSG)        { printf(" SEND_MSG"); printed = 1; }
    if (opt & MACH64_RCV_MSG)         { printf(" RCV_MSG"); printed = 1; }
    if (opt & MACH64_SEND_TIMEOUT)    { printf(" SEND_TIMEOUT"); printed = 1; }
    if (opt & MACH64_RCV_TIMEOUT)     { printf(" RCV_TIMEOUT"); printed = 1; }
    if (opt & MACH64_RCV_LARGE)       { printf(" RCV_LARGE"); printed = 1; }
    if (opt & MACH64_RCV_VOUCHER)     { printf(" RCV_VOUCHER"); printed = 1; }
    if (opt & MACH64_RCV_SYNC_WAIT)   { printf(" RCV_SYNC_WAIT"); printed = 1; }
    if (opt & MACH64_MSG_VECTOR)      { printf(" MSG_VECTOR"); printed = 1; }
    if (opt & MACH64_SEND_MQ_CALL)    { printf(" SEND_MQ_CALL"); printed = 1; }
    if (opt & MACH64_SEND_KOBJECT_CALL){ printf(" SEND_KOBJECT_CALL"); printed = 1; }
    if (opt & MACH64_SEND_DK_CALL)    { printf(" SEND_DK_CALL"); printed = 1; }
    if (opt & MACH64_SEND_ANY)        { printf(" SEND_ANY"); printed = 1; }

    if (!printed) printf(" (none)");
    printf("\n");
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

    printf("::: xniff_msg2_entry_hook: intercepted call :::\n");
    print_msg_options64(p.option64);

    if (!p.send_msg) {
        printf("  (null send buffer)\n");
        return;
    }

    xniff_ipc_mach_payload_t pl = {0};
    pl.api = XNIFF_API_MACH_MSG2;
    pl.direction = XNIFF_DIR_ENTRY;
    pl.option_lo = (uint32_t)(option64 & 0xffffffffu);
    pl.option_hi = (uint32_t)(option64 >> 32);
    pl.timeout = p.timeout;
    pl.priority = p.priority;
    pl.desc_count = p.desc_count;
    pl.aux_addr = (uint64_t)(uintptr_t)p.aux;
    // raw args available from function signature
    pl.args[0] = (uint64_t)(uintptr_t)data;
    pl.args[1] = (uint64_t)option64;
    pl.args[2] = msgh_bits_and_send_size;
    pl.args[3] = msgh_remote_and_local_port;
    pl.args[4] = msgh_voucher_and_id;
    pl.args[5] = desc_count_and_rcv_name;
    pl.args[6] = rcv_size_and_priority;
    pl.args[7] = timeout;
    ipc_send_msg_full(XNIFF_EVT_MACH2_ENTRY, &pl, p.send_msg);
    write_dump_files(p.send_msg, "entry2");

    printf("  data     : %p %s\n",
           p.send_msg, p.is_vector ? "(vector data)" : "(scalar data)");
    printf("  timeout  : %llu\n", (unsigned long long)p.timeout);
    printf("  priority : %u\n", p.priority);

    print_msg_bits(p.send_msg->msgh_bits);
    printf("  size   : %u bytes\n", (unsigned)p.send_msg->msgh_size);
    printf("  remote : 0x%08x\n", (unsigned)p.send_msg->msgh_remote_port);
    printf("  local  : 0x%08x\n", (unsigned)p.send_msg->msgh_local_port);
#if defined(__APPLE__) && __has_include(<mach/message.h>)
    printf("  voucher: 0x%08x\n", (unsigned)p.send_msg->msgh_voucher_port);
#else
    printf("  reserved/voucher: 0x%08x\n", (unsigned)p.send_msg->msgh_reserved);
#endif
    printf("  msgh_id: %d (0x%08x)\n",
           p.send_msg->msgh_id, (unsigned)p.send_msg->msgh_id);

    dump_message_body(p.send_msg);
}

__attribute__((used, noinline, visibility("default")))
void xniff_msg2_exit_hook(uint64_t ret, const xniff_ctx_frame_t* ctx)
{
    printf("::: xniff_msg2_exit_hook: intercepted return :::\n");
    printf("  return value: 0x%llx\n", (unsigned long long)ret);

    if (!ctx) { printf("  (null ctx)\n"); return; }

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
        printf("  (null rcv buffer)\n");
        return;
    }

    if (ret != MACH_MSG_SUCCESS) {
        printf("  receive not successful; ret=0x%llx — header may be invalid\n",
               (unsigned long long)ret);
        return;
    }

    // Build and send exit event with full context
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
    // raw args from ctx snapshot at entry
    for (int i = 0; i < 8; i++) pl.args[i] = ctx->x[i];
    ipc_send_msg_full(XNIFF_EVT_MACH2_EXIT, &pl, p.rcv_msg);
    write_dump_files(p.rcv_msg, "exit2");

    printf("::: reply buffer: %p %s\n",
           p.rcv_msg, p.is_vector ? "(vector data)" : "(scalar data)");
    print_msg_options64(p.option64);

    print_msg_bits(p.rcv_msg->msgh_bits);
    printf("  size   : %u bytes\n", (unsigned)p.rcv_msg->msgh_size);
    printf("  remote : 0x%08x\n", (unsigned)p.rcv_msg->msgh_remote_port);
    printf("  local  : 0x%08x\n", (unsigned)p.rcv_msg->msgh_local_port);
#if defined(__APPLE__) && __has_include(<mach/message.h>)
    printf("  voucher: 0x%08x\n", (unsigned)p.rcv_msg->msgh_voucher_port);
#else
    printf("  reserved/voucher: 0x%08x\n", (unsigned)p.rcv_msg->msgh_reserved);
#endif
    printf("  msgh_id: %d (0x%08x)\n",
           p.rcv_msg->msgh_id, (unsigned)p.rcv_msg->msgh_id);

    dump_message_body(p.rcv_msg);
}
