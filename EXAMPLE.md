
The following C code is an example of XPC sniffing using xniff:

<details>
    <summary>main.c</summary>

```c
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <xpc/xpc.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <ctype.h>

typedef struct xniff_ctx_frame {
    uint64_t lr_orig;
    uint64_t resume_pc;
    uint64_t x[8];
    uint64_t ret;
    uint8_t  reserved[0x80 - 0x58];
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
    mach_msg_bits_t voucher = MACH_MSGH_BITS_VOUCHER(bits);

    printf("  msgh_bits: 0x%08x\n", (unsigned)bits);
    printf("    remote disp : 0x%02x (%s)\n",
           (unsigned)remote, disp_to_str(remote));
    printf("    local  disp : 0x%02x (%s)\n",
           (unsigned)local, disp_to_str(local));
    printf("    voucher disp: 0x%02x (%s)\n",
           (unsigned)voucher, disp_to_str(voucher));

    printf("    flags       :");
    if (bits & MACH_MSGH_BITS_COMPLEX)   printf(" COMPLEX");
    if (bits & MACH_MSGH_BITS_CIRCULAR)  printf(" CIRCULAR");
    if (!(bits & (MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS_CIRCULAR)))
        printf(" (none)");
    printf("\n");
}

static void print_msg_options(mach_msg_option_t option) {
    printf("  options : 0x%08x\n", (unsigned)option);
    printf("    flags :");

    int printed = 0;

    if (option & MACH_SEND_MSG)        { printf(" SEND_MSG");        printed = 1; }
    if (option & MACH_RCV_MSG)         { printf(" RCV_MSG");         printed = 1; }
    if (option & MACH_SEND_TIMEOUT)    { printf(" SEND_TIMEOUT");    printed = 1; }
    if (option & MACH_RCV_TIMEOUT)     { printf(" RCV_TIMEOUT");     printed = 1; }
    if (option & MACH_SEND_INTERRUPT)  { printf(" SEND_INTERRUPT");  printed = 1; }
    if (option & MACH_RCV_INTERRUPT)   { printf(" RCV_INTERRUPT");   printed = 1; }
    if (option & MACH_RCV_LARGE)       { printf(" RCV_LARGE");       printed = 1; }
    if (option & MACH_SEND_NOTIFY)     { printf(" SEND_NOTIFY");     printed = 1; }

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
    mach_msg_size_t max_dump = 256;
    if (size > max_dump)
        size = max_dump;

    printf("  %s: %u bytes (showing %u bytes)\n",
           label, (unsigned)size, (unsigned)size);

    for (mach_msg_size_t i = 0; i < size; i += 16) {
        printf("    %04x : ", (unsigned)i);

        for (mach_msg_size_t j = 0; j < 16; ++j) {
            mach_msg_size_t idx = i + j;
            if (idx < size)
                printf("%02x ", p[idx]);
            else
                printf("   ");
        }

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

            case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
                mach_msg_guarded_port_descriptor_t *gp = &desc->guarded_port;
                printf("GUARDED_PORT name=0x%08x disp=%u guard=0x%llx flags=0x%x\n",
                       (unsigned)gp->name,
                       gp->disposition,
                       (unsigned long long)gp->context,
                       (unsigned)gp->flags);
                break;
            }

            default:
                printf("UNKNOWN descriptor type=%u\n", (unsigned)t);
                break;
        }
    }

    const uint8_t *after_desc = (const uint8_t *)desc;
    if (after_desc < base + total) {
        mach_msg_size_t inline_len =
            (mach_msg_size_t)(base + total - after_desc);
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

__attribute__((used, noinline, visibility("default")))
void xniff_remote_entry_hook(mach_msg_header_t *msg, mach_msg_option_t option) {
    printf("::: xniff_remote_entry_hook: intercepted call :::\n");

    if (!msg) {
        printf("  (null mach_msg_header_t *)\n");
        return;
    }

    printf("  address: %p\n", (void *)msg);

    print_msg_options(option);
    print_msg_bits(msg->msgh_bits);

    printf("  size   : %u bytes\n",   (unsigned)msg->msgh_size);
    printf("  remote : 0x%08x\n",     (unsigned)msg->msgh_remote_port);
    printf("  local  : 0x%08x\n",     (unsigned)msg->msgh_local_port);
    printf("  voucher: 0x%08x\n",     (unsigned)msg->msgh_voucher_port);
    printf("  msgh_id: %d (0x%08x)\n",
           msg->msgh_id,
           (unsigned)msg->msgh_id);

    dump_message_body(msg);
}

__attribute__((used, noinline, visibility("default")))
void xniff_remote_exit_hook(uint64_t ret, const xniff_ctx_frame_t* ctx) {
    printf("::: xniff_remote_exit_hook: intercepted return :::\n");
    printf("  return value: 0x%llx\n", ret);

    if (!ctx) {
        printf("  (null ctx)\n");
        return;
    }

    mach_msg_option_t option = (mach_msg_option_t)ctx->x[1];
    const int did_recv = (option & MACH_RCV_MSG) != 0;

    if (!did_recv)
        return;

    mach_msg_header_t* reply =
        (mach_msg_header_t*)(ctx->x[7] ? ctx->x[7] : ctx->x[0]);

    printf("::: reply buffer: %p\n", (void*)reply);
    print_msg_options(option);

    if (!reply) {
        printf("  (null reply)\n");
        return;
    }

    if (ret != MACH_MSG_SUCCESS) {
        printf("  receive not successful; ret=0x%llx — header may be invalid\n", ret);
        return;
    }

    print_msg_bits(reply->msgh_bits);
    printf("  size   : %u bytes\n",   (unsigned)reply->msgh_size);
    printf("  remote : 0x%08x\n",     (unsigned)reply->msgh_remote_port);
    printf("  local  : 0x%08x\n",     (unsigned)reply->msgh_local_port);
    printf("  voucher: 0x%08x\n",     (unsigned)reply->msgh_voucher_port);
    printf("  msgh_id: %d (0x%08x)\n",
           reply->msgh_id,
           (unsigned)reply->msgh_id);

    dump_message_body(reply);
}

typedef int (*os_eligibility_get_internal_state_t)(xpc_object_t *out_state);
typedef int (*os_eligibility_get_state_dump_t)(xpc_object_t *out_dump);

void print_xpc_object(xpc_object_t obj);

int main(void) {
    printf("Waiting for patch, our PID is %d\n", getpid());
    sleep(30);

    void *handle = NULL;
    os_eligibility_get_internal_state_t os_eligibility_get_internal_state = NULL;
    os_eligibility_get_state_dump_t     os_eligibility_get_state_dump     = NULL;
    xpc_object_t internal_state = NULL;
    xpc_object_t state_dump     = NULL;
    int result = 0;

    handle = dlopen("/usr/lib/system/libsystem_eligibility.dylib", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr,
                "Failed to open libsystem_eligibility.dylib: %s\n",
                dlerror());
        return 1;
    }

    dlerror();

    *(void **)(&os_eligibility_get_internal_state) =
        dlsym(handle, "os_eligibility_get_internal_state");
    char *error = dlerror();
    if (error != NULL) {
        fprintf(stderr,
                "Failed to find os_eligibility_get_internal_state: %s\n",
                error);
        dlclose(handle);
        return 1;
    }

    *(void **)(&os_eligibility_get_state_dump) =
        dlsym(handle, "os_eligibility_get_state_dump");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr,
                "Failed to find os_eligibility_get_state_dump: %s\n",
                error);
        dlclose(handle);
        return 1;
    }

    result = os_eligibility_get_internal_state(&internal_state);
    if (result != 0) {
        fprintf(stderr,
                "os_eligibility_get_internal_state failed with error: %d\n",
                result);
    } else {
        if (internal_state) {
            printf("internal state:\n");
            print_xpc_object(internal_state);
            xpc_release(internal_state);
        } else {
            printf("No internal state returned.\n");
        }
    }

    result = os_eligibility_get_state_dump(&state_dump);
    if (result != 0) {
        fprintf(stderr,
                "os_eligibility_get_state_dump failed with error: %d\n",
                result);
        dlclose(handle);
        return 1;
    }

    if (state_dump) {
        printf("state:\n");
        print_xpc_object(state_dump);
        xpc_release(state_dump);
    } else {
        printf("No state dump returned.\n");
    }

    dlclose(handle);
    return 0;
}

void print_xpc_object(xpc_object_t obj) {
    if (!obj) {
        printf("NULL XPC object.\n");
        return;
    }

    char *description = xpc_copy_description(obj);
    if (description) {
        printf("%s\n", description);
        free(description);
    } else {
        printf("Failed to get XPC object description.\n");
    }
}
```

</details>

It should be built with XCode, with libxpc.tbd linked, and the resulting binary injected into the target process.

Also, the following entitlements should be applied:

<details>
    <summary>entitlements.plist</summary>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.private.eligibilityd.setInput</key>
    <true/>
    <key>com.apple.private.eligibilityd.resetDomain</key>
    <true/>
    <key>com.apple.private.eligibilityd.forceDomain</key>
    <true/>
    <key>com.apple.private.eligibilityd.internalState</key>
    <true/>
    <key>com.apple.private.eligibilityd.resetAllDomains</key>
    <true/>
    <key>com.apple.private.eligibilityd.forceDomainSet</key>
    <true/>
    <key>com.apple.private.eligibilityd.stateDump</key>
    <true/>
    <key>com.apple.private.eligibilityd.dumpSysdiagnoseDataToDir</key>
    <true/>
    <key>com.apple.private.eligibilityd.setTestMode</key>
    <true/>
    <key>com.apple.private.eligibilityd.testMode</key>
    <true/>
</dict>
</plist>
```

</details>

After you run, you have a window of about 30 seconds to run xniff-cli on the target process to see the intercepted XPC messages.

```
sudo build/xniff-cli hook-exit <PID> _mach_msg_overwrite _xniff_remote_entry_hook _xniff_remote_exit_hook
```

This will output intercepted XPC messages to STDOUT of the victim process.

This is merely a proof of concept. Xniff will soon embed the sniffing logic directly, so xniff can be run on any process without needing access to source.
