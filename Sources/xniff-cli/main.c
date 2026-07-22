// xniff-cli: attach to a target process, inject xniff-hooks, and stream events.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <libproc.h>
#include <poll.h>

#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach/mach_vm.h>
#include <mach/message.h>
#include <time.h>
#include <sys/stat.h>

#include "../shared/xniff_ipc.h"
#include "../shared/xniff_ipc_v2.h"
#include "../shared/mach_private.h"

#include <xniff/macho.h>
#include <xniff/inject.h>

#include "cli_options.h"
#include "embedded_hooks.h"
#include "launch_environment.h"
#include "target_identity.h"
// XPC wire parser (shared library)
#include "../xpcdesert/xpcdesert.h"

extern char **environ;

enum {
    XNIFF_HOOK_MODE_MACH = XNIFF_CAPTURE_MODE_MACH,
    XNIFF_HOOK_MODE_XPC  = XNIFF_CAPTURE_MODE_XPC,
};

static listener_opts_t g_listener_opts;

static FILE *xniff_diag_stream(void) {
    return stderr;
}

#define XNIFF_DIAGF(...) fprintf(xniff_diag_stream(), __VA_ARGS__)

static int attach_and_get_task(pid_t pid, mach_port_t *out_task) {
    // Attempt to get the task port first; if allowed, we can avoid ptrace.
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr == KERN_SUCCESS) {
        XNIFF_DIAGF("got task port for pid %d without attach\n", pid);
        *out_task = task;
        return 0;
    }

    XNIFF_DIAGF("attaching to pid %d\n", pid);
    if (ptrace(PT_ATTACHEXC, pid, 0, 0) != 0) {
        perror("ptrace(PT_ATTACHEXC)");
        return -1;
    }

    // Retry task_for_pid after attach instead of relying on waitpid semantics.
    for (int i = 0; i < 40; i++) { // up to ~2s
        kr = task_for_pid(mach_task_self(), pid, &task);
        if (kr == KERN_SUCCESS) break;
        if (i == 5) (void)kill(pid, SIGSTOP);
        usleep(50 * 1000);
    }
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed after attach: %d\n", kr);
        (void)ptrace(PT_DETACH, pid, 0, 0);
        return -1;
    }
    XNIFF_DIAGF("getting task port for pid %d\n", pid);
    *out_task = task;
    return 0;
}

static int detach_process(pid_t pid) {
    if (ptrace(PT_DETACH, pid, 0, 0) != 0) {
        // If we never attached (e.g., obtained task port directly), PT_DETACH
        // can fail with EPERM/ESRCH. Treat as non-fatal.
        return -1;
    }
    return 0;
}

static int copy_file_all(const char *src_path, const char *dst_path, mode_t dst_mode) {
    int in_fd = open(src_path, O_RDONLY);
    if (in_fd < 0) return -1;

    int out_fd = open(dst_path, O_WRONLY | O_CREAT | O_EXCL, dst_mode);
    if (out_fd < 0) {
        close(in_fd);
        return -1;
    }

    uint8_t buf[64 * 1024];
    int rc = 0;
    while (1) {
        ssize_t rn = read(in_fd, buf, sizeof(buf));
        if (rn == 0) break;
        if (rn < 0) {
            if (errno == EINTR) continue;
            rc = -1;
            break;
        }

        size_t off = 0;
        while (off < (size_t)rn) {
            ssize_t wn = write(out_fd, buf + off, (size_t)rn - off);
            if (wn < 0) {
                if (errno == EINTR) continue;
                rc = -1;
                break;
            }
            off += (size_t)wn;
        }
        if (rc != 0) break;
    }

    if (rc == 0) {
        (void)fchmod(out_fd, dst_mode);
        (void)fsync(out_fd);
    }

    close(out_fd);
    close(in_fd);

    if (rc != 0) {
        (void)unlink(dst_path);
        return -1;
    }
    return 0;
}

static int stage_dylib_for_sandbox(const char *src_abs_path,
                                   char *out_path,
                                   size_t out_path_size) {
    if (!src_abs_path || !out_path || out_path_size == 0) return -1;

    const char *home = getenv("HOME");
    char home_trash_xniff[PATH_MAX] = {0};
    if (home && home[0]) {
        int n = snprintf(home_trash_xniff, sizeof(home_trash_xniff),
                         "%s/.Trash/.xniff", home);
        if (n > 0 && (size_t)n < sizeof(home_trash_xniff)) {
            (void)mkdir(home_trash_xniff, 0755);
        } else {
            home_trash_xniff[0] = '\0';
        }
    }

    const char *k_dirs[] = {
        home_trash_xniff[0] ? home_trash_xniff : NULL,
        "/tmp",
        "/private/tmp",
        "/private/var/tmp",
        "/Users/Shared",
    };

    for (size_t i = 0; i < sizeof(k_dirs) / sizeof(k_dirs[0]); i++) {
        const char *dir = k_dirs[i];
        if (!dir || !dir[0]) continue;
        char candidate[PATH_MAX];
        for (int attempt = 0; attempt < 16; attempt++) {
            unsigned int salt = (unsigned int)(arc4random() & 0xffff);
            int n = snprintf(candidate, sizeof(candidate),
                             "%s/xniff-hooks-%d-%u.dylib",
                             dir, (int)getpid(), salt);
            if (n <= 0 || (size_t)n >= sizeof(candidate)) continue;

            if (copy_file_all(src_abs_path, candidate, 0644) == 0) {
                (void)strncpy(out_path, candidate, out_path_size - 1);
                out_path[out_path_size - 1] = '\0';
                return 0;
            }
        }
    }
    return -1;
}

static int install_hooks(pid_t pid, const char *dylib_path, int mode);
static int cmd_attach(pid_t pid, const char *dylib_path, int mode);
static int cmd_launch(const char *dylib_path, int mode, const char *target_user,
                      char *const launch_argv[]);

int main(int argc, char **argv) {
    xniff_cli_options_t options;
    int parse_result = xniff_cli_parse(argc, argv, &options);
    if (parse_result != 0) {
        xniff_cli_usage(argv[0]);
        return parse_result > 0 ? 0 : 2;
    }
    g_listener_opts = options.listener;

    char embedded_hooks[PATH_MAX] = {0};
    const char *hooks_path = options.hooks_path;
    if (hooks_path == NULL) {
        if (xniff_extract_embedded_hooks(embedded_hooks, sizeof(embedded_hooks)) != 0) {
            fprintf(stderr, "failed to extract embedded hooks: %s\n", strerror(errno));
            return 1;
        }
        hooks_path = embedded_hooks;
    }

    int rc = -1;
    switch (options.command) {
        case XNIFF_CLI_ATTACH:
            rc = cmd_attach(options.pid, hooks_path, options.capture_mode);
            break;
        case XNIFF_CLI_LAUNCH:
            rc = cmd_launch(hooks_path, options.capture_mode, options.target_user,
                            (char *const *)options.launch_argv);
            break;
        default:
            break;
    }
    if (embedded_hooks[0] != '\0') unlink(embedded_hooks);
    return rc == 0 ? 0 : 1;
}

static bool entry_len_sane(uint32_t entry_len) {
    if (entry_len < sizeof(xniff_ipc_v2_entry_hdr_t) + sizeof(xniff_ipc_v2_fixed_hdr_t)) return false;
    if (entry_len > (64u * 1024u * 1024u)) return false;
    return true;
}

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

static const char* kind_to_tag(int kind) {
    switch (kind) {
        case XNIFF_EVT_MACH_ENTRY:  return "entry";
        case XNIFF_EVT_MACH_EXIT:   return "exit";
        case XNIFF_EVT_MACH2_ENTRY: return "entry2";
        case XNIFF_EVT_MACH2_EXIT:  return "exit2";
        case XNIFF_EVT_XPC_ENTRY:   return "xpc_entry";
        case XNIFF_EVT_XPC_EXIT:    return "xpc_exit";
        case XNIFF_EVT_DEBUG_LOG:   return "debug_log";
    }
    return "unknown";
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
    char *pretty;
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
    if (pl->func == XNIFF_XPC_FUNC_CONNECTION_CREATE) {
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

static xniff_conn_meta_t *conn_meta_find_or_create(uint32_t owner_pid, uint64_t conn_ptr, bool create) {
    if (conn_ptr == 0) return NULL;
    xniff_conn_meta_t *m = g_conn_meta;
    while (m) {
        if (m->owner_pid == owner_pid && m->conn_ptr == conn_ptr) return m;
        m = m->next;
    }
    if (!create) return NULL;
    m = (xniff_conn_meta_t *)calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->owner_pid = owner_pid;
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
    out->conn_ptr = xpc_conn_ptr_for_event(ihdr, pl);
    out->msg_ptr = xpc_msg_ptr_for_event(pl);

    xniff_conn_meta_t *m = conn_meta_find_or_create(ihdr->pid, out->conn_ptr, out->conn_ptr != 0);
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

static uint32_t u32le_at(const uint8_t *p) {
    if (!p) return 0;
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
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

static char *xpc_serial_pretty_from_blob(const uint8_t *bytes, size_t len, uint8_t format) {
    if (!bytes || len < 4) return NULL;

    const uint8_t *obj = bytes;
    size_t obj_len = len;
    bool parsed = false;

    if (format == XNIFF_XPC_SERIAL_FORMAT_LIBXPC_V5) {
        if (len >= 8 && u32le_at(bytes) == 0x42133742u && u32le_at(bytes + 4) == 5u) {
            obj = bytes + 8;
            obj_len = len - 8;
        }
    }

    xpcd_object_t *root = xpcd_parse(obj, obj_len);
    if (!root && format == XNIFF_XPC_SERIAL_FORMAT_LIBXPC_V5) {
        size_t off = 0;
        if (xpcd_find_payload(bytes, len, 512, &off) == 0 && off < len) {
            root = xpcd_parse(bytes + off, len - off);
            parsed = true;
        }
    }
    if (!root && !parsed) {
        size_t off = 0;
        if (xpcd_find_payload(obj, obj_len, 512, &off) == 0 && off < obj_len) {
            root = xpcd_parse(obj + off, obj_len - off);
        }
    }
    if (!root) return NULL;
    char *pretty = xpcd_format(root);
    xpcd_free(root);
    return pretty;
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
    if (xs->message.pretty) free(xs->message.pretty);
    if (xs->reply.pretty) free(xs->reply.pretty);
    if (xs->event.pretty) free(xs->event.pretty);
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
                              xniff_xpc_conn_meta_item_t *cm) {
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
        if (dst->pretty) { free(dst->pretty); dst->pretty = NULL; }
        if (g_listener_opts.parse_xpc) {
            dst->pretty = xpc_serial_pretty_from_blob(dst->bytes, stored, dst->format);
        }
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

typedef struct {
    uint16_t type;
    uint32_t index;
    uint64_t address;
    uint32_t size_bytes;
    uint32_t count;
    uint32_t elem_size;
    char path[600];
} xniff_att_meta_t;

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
            if (idx == 0) return "service_name_ptr";
            if (idx == 1) return "target_queue_ptr";
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
    if (it->pretty) {
        printf("  xpc.serialized.%s.pretty: %s\n",
               xpc_serial_slot_name(it->slot),
               it->pretty);
    }
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
    size_t dump_len = msg_len < g_listener_opts.hex_preview_len ? msg_len : g_listener_opts.hex_preview_len;
    if (hdr && dump_len) {
        const uint8_t *p = (const uint8_t *)hdr;
        printf("  mach.msg_preview_hex[%zu]: ", dump_len);
        for (size_t i = 0; i < dump_len; i++) printf("%02x", p[i]);
        printf("\n");
    }

    // Try to detect and pretty-print an inline XPC payload using shared lib
    if (g_listener_opts.parse_xpc && msg_bytes && msg_len >= 16) {
        size_t xoff = 0;
        if (xpcd_find_payload(msg_bytes, msg_len, 512, &xoff) == 0) {
            xpcd_object_t *root = xpcd_parse(msg_bytes + xoff, msg_len - xoff);
            if (root) {
                char *pretty = xpcd_format(root);
                if (pretty) {
                    printf("  xpc: offset=+%zu\n", xoff);
                    printf("%s\n", pretty);
                    free(pretty);
                }
                xpcd_free(root);
            }
        }
    }
}

static int task_read_exact(mach_port_t task, mach_vm_address_t address, void *buf, size_t len) {
    if (!buf && len != 0) return -1;
    mach_vm_size_t out_sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task,
                                              address,
                                              (mach_vm_size_t)len,
                                              (mach_vm_address_t)(uintptr_t)buf,
                                              &out_sz);
    if (kr != KERN_SUCCESS || out_sz != (mach_vm_size_t)len) return -1;
    return 0;
}

static int task_write_exact(mach_port_t task, mach_vm_address_t address, const void *buf, size_t len) {
    if (!buf && len != 0) return -1;
    kern_return_t kr = mach_vm_write(task,
                                     address,
                                     (vm_offset_t)(uintptr_t)buf,
                                     (mach_msg_type_number_t)len);
    return kr == KERN_SUCCESS ? 0 : -1;
}

static bool env_var_enabled(const char *name) {
    if (!name || !*name) return false;
    const char *v = getenv(name);
    return (v && *v && strcmp(v, "0") != 0);
}

static int write_bin_record(FILE *fp, const uint8_t *entry, size_t entry_len) {
    if (!fp || !entry || entry_len == 0) return -1;
    if (fwrite(entry, 1, entry_len, fp) != entry_len) return -1;
    if (fflush(fp) != 0) return -1;
    return 0;
}

static int resolve_remote_ring_addr(mach_port_t task, mach_vm_address_t *out_addr) {
    if (!out_addr) return -1;
    mach_vm_address_t addr = 0;
    if (xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "_xniff_ipc_ring", &addr) == 0 ||
        xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "xniff_ipc_ring", &addr) == 0) {
        *out_addr = addr;
        return 0;
    }
    return -1;
}

static int configure_remote_capture_mode(mach_port_t task, uint32_t mode) {
    mach_vm_address_t ring_addr = 0;
    for (int i = 0; i < 80; i++) {
        if (resolve_remote_ring_addr(task, &ring_addr) == 0) break;
        usleep(25 * 1000);
    }
    if (ring_addr == 0) return -1;

    mach_vm_address_t mode_addr =
        ring_addr + (mach_vm_address_t)offsetof(xniff_ipc_ring_t, hdr) +
        (mach_vm_address_t)offsetof(xniff_ipc_ring_hdr_t, capture_mode);
    return task_write_exact(task, mode_addr, &mode, sizeof(mode));
}

static bool target_process_alive(pid_t pid) {
    struct proc_bsdinfo info;
    int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    return n == (int)sizeof(info);
}

static int capture_ring(pid_t pid, int ready_fd) {
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "capture: task_for_pid failed for %d: %d (%s)\n",
                (int)pid, kr, mach_error_string(kr));
        return -1;
    }
    if (ready_fd >= 0) {
        const uint8_t ready = 1;
        (void)write(ready_fd, &ready, sizeof(ready));
        close(ready_fd);
    }
    const bool handle_hook_debug_logs = env_var_enabled("XNIFF_HOOKS_DEBUG");
    FILE *out_bin_fp = NULL;
    const bool bin_only = g_listener_opts.out_bin;
    if (bin_only) {
        if (strcmp(g_listener_opts.out_bin_path, "-") == 0) {
            out_bin_fp = stdout;
        } else {
            out_bin_fp = fopen(g_listener_opts.out_bin_path, "wb");
            if (!out_bin_fp) {
                fprintf(stderr, "capture: failed opening --out path '%s': %s\n",
                        g_listener_opts.out_bin_path, strerror(errno));
                return -1;
            }
        }
        xniff_bin_file_hdr_t fh = {0};
        fh.magic = XNIFF_BIN_FILE_MAGIC;
        fh.version = XNIFF_BIN_FILE_VERSION;
        if (fwrite(&fh, sizeof(fh), 1, out_bin_fp) != 1 || fflush(out_bin_fp) != 0) {
            fprintf(stderr, "capture: failed writing binary stream header\n");
            if (out_bin_fp != stdout) fclose(out_bin_fp);
            return -1;
        }
    }

    mach_vm_address_t ring_addr = 0;
    for (int i = 0; i < 4000; i++) { // up to ~20s while parent loads hooks
        if (resolve_remote_ring_addr(task, &ring_addr) == 0) break;
        usleep(5 * 1000);
    }
    if (ring_addr == 0) {
        fprintf(stderr, "capture: failed to resolve remote xniff ring symbol in pid %d\n", (int)pid);
        return -1;
    }

    mach_vm_address_t ring_hdr_addr = ring_addr + (mach_vm_address_t)offsetof(xniff_ipc_ring_t, hdr);
    mach_vm_address_t ring_data_addr = ring_addr + (mach_vm_address_t)offsetof(xniff_ipc_ring_t, data);
    mach_vm_address_t ring_read_idx_addr =
        ring_hdr_addr + (mach_vm_address_t)offsetof(xniff_ipc_ring_hdr_t, read_idx);

    XNIFF_DIAGF("capture: streaming target_pid=%d ring=0x%llx\n",
                (int)pid, (unsigned long long)ring_addr);

    // Prepare dump directory for this pid
    char base_dir[256];
    snprintf(base_dir, sizeof(base_dir), "/tmp/xniff/%d", (int)pid);
    if (g_listener_opts.dump_files) {
        mkdir("/tmp/xniff", 0755);
        mkdir(base_dir, 0755);
    }
    unsigned long long evt_idx = 0;
    uint64_t local_read_idx = UINT64_MAX;

    uint8_t *stream = NULL;
    size_t stream_len = 0;
    size_t stream_cap = 0;
    uint64_t last_dropped_events = 0;
    uint64_t last_dropped_bytes = 0;
    unsigned int consecutive_read_failures = 0;

    for (;;) {
        xniff_ipc_ring_hdr_t rmeta = {0};
        if (task_read_exact(task, ring_hdr_addr, &rmeta, sizeof(rmeta)) != 0) {
            consecutive_read_failures++;
            if (consecutive_read_failures >= 5 && !target_process_alive(pid)) {
                XNIFF_DIAGF("capture: target pid %d exited; capture complete\n", (int)pid);
                if (out_bin_fp && out_bin_fp != stdout) fclose(out_bin_fp);
                free(stream);
                return 0;
            }
            usleep(10 * 1000);
            continue;
        }
        consecutive_read_failures = 0;
        if (rmeta.magic != XNIFF_IPC_RING_MAGIC || rmeta.version != XNIFF_IPC_RING_VERSION ||
            rmeta.capacity == 0 || rmeta.capacity > XNIFF_IPC_RING_CAPACITY) {
            usleep(10 * 1000);
            continue;
        }
        if (rmeta.dropped_events != last_dropped_events || rmeta.dropped_bytes != last_dropped_bytes) {
            uint64_t event_delta = rmeta.dropped_events - last_dropped_events;
            uint64_t byte_delta = rmeta.dropped_bytes - last_dropped_bytes;
            XNIFF_DIAGF("capture: warning: target dropped %llu events (%llu bytes); totals=%llu/%llu\n",
                        (unsigned long long)event_delta,
                        (unsigned long long)byte_delta,
                        (unsigned long long)rmeta.dropped_events,
                        (unsigned long long)rmeta.dropped_bytes);
            last_dropped_events = rmeta.dropped_events;
            last_dropped_bytes = rmeta.dropped_bytes;
        }
        if (local_read_idx == UINT64_MAX) local_read_idx = rmeta.read_idx;

        if (rmeta.write_idx < local_read_idx || (rmeta.write_idx - local_read_idx) > (uint64_t)rmeta.capacity) {
            local_read_idx = rmeta.write_idx;
        }

        bool pulled = false;
        while (local_read_idx < rmeta.write_idx) {
            uint64_t cap = (uint64_t)rmeta.capacity;
            uint64_t off = local_read_idx % cap;
            uint64_t avail = rmeta.write_idx - local_read_idx;
            uint64_t contig = cap - off;
            uint64_t chunk64 = avail < contig ? avail : contig;
            if (chunk64 > 64u * 1024u) chunk64 = 64u * 1024u;
            size_t chunk = (size_t)chunk64;

            if (stream_cap - stream_len < chunk) {
                size_t need = stream_len + chunk;
                size_t new_cap = stream_cap ? stream_cap : 64u * 1024u;
                while (new_cap < need) new_cap *= 2;
                uint8_t *tmp = (uint8_t *)realloc(stream, new_cap);
                if (!tmp) {
                    fprintf(stderr, "capture: out of memory while growing stream buffer\n");
                    if (out_bin_fp && out_bin_fp != stdout) fclose(out_bin_fp);
                    free(stream);
                    return -1;
                }
                stream = tmp;
                stream_cap = new_cap;
            }

            if (task_read_exact(task,
                                ring_data_addr + (mach_vm_address_t)off,
                                stream + stream_len,
                                chunk) != 0) {
                break;
            }
            stream_len += chunk;
            local_read_idx += (uint64_t)chunk;
            pulled = true;
        }
        if (pulled) {
            (void)task_write_exact(task, ring_read_idx_addr, &local_read_idx, sizeof(local_read_idx));
        }

        while (stream_len >= sizeof(xniff_ipc_v2_entry_hdr_t)) {
            xniff_ipc_v2_entry_hdr_t eh = {0};
            memcpy(&eh, stream, sizeof(eh));
            if (eh.version != XNIFF_IPC_V2_VERSION || !entry_len_sane(eh.entry_len)) {
                memmove(stream, stream + 1, stream_len - 1);
                stream_len -= 1;
                continue;
            }
            size_t frame_len = (size_t)eh.entry_len;
            if (stream_len < frame_len) break;

            if (bin_only) {
                if (write_bin_record(out_bin_fp, stream, frame_len) != 0) {
                    fprintf(stderr, "capture: failed writing binary record\n");
                    if (out_bin_fp && out_bin_fp != stdout) fclose(out_bin_fp);
                    free(stream);
                    return -1;
                }
                evt_idx++;
                memmove(stream, stream + frame_len, stream_len - frame_len);
                stream_len -= frame_len;
                continue;
            }

            size_t body_len = frame_len - sizeof(eh);
            if (body_len < sizeof(xniff_ipc_v2_fixed_hdr_t)) {
                memmove(stream, stream + frame_len, stream_len - frame_len);
                stream_len -= frame_len;
                continue;
            }
            const uint8_t *body = stream + sizeof(eh);
            xniff_ipc_v2_fixed_hdr_t fh = {0};
            memcpy(&fh, body, sizeof(fh));
            uint16_t kind = v2_kind_from_fixed(&fh);

            size_t sec_off = sizeof(fh);
            if (handle_hook_debug_logs && kind == XNIFF_EVT_DEBUG_LOG) {
                while (sec_off + sizeof(xniff_ipc_v2_section_hdr_t) <= body_len) {
                    xniff_ipc_v2_section_hdr_t sh = {0};
                    memcpy(&sh, body + sec_off, sizeof(sh));
                    sec_off += sizeof(sh);
                    if (sec_off + sh.sec_len > body_len) break;
                    const uint8_t *val = body + sec_off;
                    if (sh.sec_type == XNIFF_V2_SEC_HOOK_DIAG && sh.sec_len >= sizeof(xniff_ipc_v2_diag_t)) {
                        xniff_ipc_v2_diag_t d = {0};
                        memcpy(&d, val, sizeof(d));
                        size_t avail = sh.sec_len - sizeof(d);
                        uint32_t msg_len = d.msg_len;
                        if (msg_len > avail) msg_len = (uint32_t)avail;
                        char *line = (char *)malloc((size_t)msg_len + 1);
                        if (line) {
                            memcpy(line, val + sizeof(d), msg_len);
                            line[msg_len] = '\0';
                            char tbuf[64];
                            double mono_s = 0.0;
                            format_time(tbuf, sizeof(tbuf), &mono_s);
                            append_hook_debug_log(fh.pid, fh.tid_low, tbuf, mono_s, line);
                            if (*line) printf("[hook-debug][pid=%u][tid=0x%x] %s\n", fh.pid, fh.tid_low, line);
                            free(line);
                        }
                    }
                    sec_off += sh.sec_len;
                }
                memmove(stream, stream + frame_len, stream_len - frame_len);
                stream_len -= frame_len;
                continue;
            }

            if (g_listener_opts.xpc_only && fh.api != XNIFF_API_XPC_HL) {
                memmove(stream, stream + frame_len, stream_len - frame_len);
                stream_len -= frame_len;
                continue;
            }

            unsigned long long cur_evt_id = evt_idx;
            if (fh.api == XNIFF_API_XPC_HL) {
                xniff_ipc_xpc_payload_t pl;
                memset(&pl, 0, sizeof(pl));
                pl.api = fh.api;
                pl.direction = fh.direction;
                pl.func = fh.function;

                char *s0 = NULL, *s1 = NULL, *s2 = NULL, *s3 = NULL;
                uint64_t call_id = 0;
                xniff_xpc_serialized_set_t xser;
                xniff_xpc_conn_meta_item_t xcm;
                xpc_serialized_init(&xser);
                xpc_conn_meta_init(&xcm);

                sec_off = sizeof(fh);
                while (sec_off + sizeof(xniff_ipc_v2_section_hdr_t) <= body_len) {
                    xniff_ipc_v2_section_hdr_t sh = {0};
                    memcpy(&sh, body + sec_off, sizeof(sh));
                    sec_off += sizeof(sh);
                    if (sec_off + sh.sec_len > body_len) break;
                    const uint8_t *val = body + sec_off;
                    if (sh.sec_type == XNIFF_V2_SEC_XPC_CALL_META &&
                        sh.sec_len >= sizeof(xniff_ipc_xpc_payload_t)) {
                        memcpy(&pl, val, sizeof(pl));
                        size_t voff = sizeof(pl);
                        s0 = wire_copy_str(val, sh.sec_len, &voff, pl.str0_len);
                        s1 = wire_copy_str(val, sh.sec_len, &voff, pl.str1_len);
                        s2 = wire_copy_str(val, sh.sec_len, &voff, pl.str2_len);
                        s3 = wire_copy_str(val, sh.sec_len, &voff, pl.str3_len);
                    } else if (sh.sec_type == XNIFF_V2_SEC_CALL_ID &&
                               sh.sec_len >= sizeof(call_id)) {
                        memcpy(&call_id, val, sizeof(call_id));
                    } else {
                        xpc_parse_section(sh.sec_type, val, sh.sec_len, &xser, &xcm);
                    }
                    sec_off += sh.sec_len;
                }

                xniff_ipc_hdr_t ihdr = {0};
                ihdr.kind = kind;
                ihdr.pid = fh.pid;
                ihdr.tid_low = fh.tid_low;

                char tbuf[64];
                double mono_s = 0.0;
                format_time(tbuf, sizeof(tbuf), &mono_s);

                xniff_xpc_analysis_t xa;
                analyze_xpc_event(cur_evt_id, &ihdr, &pl, s0, mono_s, &xa);
                xa.call_id = call_id;
                print_xpc_event(&ihdr, &pl, &xa, &xser, &xcm, s0, s1, s2, s3, tbuf, mono_s);

                xpc_serialized_free(&xser);
                xpc_conn_meta_free(&xcm);
                free(s0);
                free(s1);
                free(s2);
                free(s3);
                evt_idx++;

                memmove(stream, stream + frame_len, stream_len - frame_len);
                stream_len -= frame_len;
                continue;
            }

            if (fh.api == XNIFF_API_MACH_MSG || fh.api == XNIFF_API_MACH_MSG2) {
                xniff_ipc_mach_payload_t pl;
                memset(&pl, 0, sizeof(pl));
                pl.api = fh.api;
                pl.direction = fh.direction;

                const uint8_t *msg_bytes = NULL;
                size_t msg_len = 0;
                xniff_att_meta_t *atts = NULL;
                size_t att_count = 0, att_cap = 0;
                xniff_ipc_v2_desc_meta_t last_desc = {0};
                bool have_last_desc = false;

                sec_off = sizeof(fh);
                while (sec_off + sizeof(xniff_ipc_v2_section_hdr_t) <= body_len) {
                    xniff_ipc_v2_section_hdr_t sh = {0};
                    memcpy(&sh, body + sec_off, sizeof(sh));
                    sec_off += sizeof(sh);
                    if (sec_off + sh.sec_len > body_len) break;
                    const uint8_t *val = body + sec_off;

                    if (sh.sec_type == XNIFF_V2_SEC_MACH_HEADER_OPTIONS &&
                        sh.sec_len >= sizeof(xniff_ipc_mach_payload_t)) {
                        memcpy(&pl, val, sizeof(pl));
                    } else if (sh.sec_type == XNIFF_V2_SEC_MACH_INLINE_BYTES) {
                        msg_bytes = val;
                        msg_len = sh.sec_len;
                    } else if (sh.sec_type == XNIFF_V2_SEC_MACH_DESC_META &&
                               sh.sec_len >= sizeof(xniff_ipc_v2_desc_meta_t)) {
                        memcpy(&last_desc, val, sizeof(last_desc));
                        have_last_desc = true;
                    } else if ((sh.sec_type == XNIFF_V2_SEC_MACH_DESC_OOL_BYTES ||
                                sh.sec_type == XNIFF_V2_SEC_MACH_DESC_PORT_ARRAY) &&
                               have_last_desc) {
                        if (att_count == att_cap) {
                            size_t new_cap = att_cap ? att_cap * 2 : 8;
                            xniff_att_meta_t *tmp = (xniff_att_meta_t *)realloc(atts, new_cap * sizeof(*atts));
                            if (!tmp) break;
                            atts = tmp;
                            att_cap = new_cap;
                        }
                        xniff_att_meta_t *m = &atts[att_count++];
                        memset(m, 0, sizeof(*m));
                        m->type = (sh.sec_type == XNIFF_V2_SEC_MACH_DESC_PORT_ARRAY) ? XNIFF_TLV_OOL_PORTS : XNIFF_TLV_OOL_DATA;
                        m->index = last_desc.index;
                        m->address = last_desc.address;
                        m->size_bytes = (uint32_t)sh.sec_len;
                        m->count = last_desc.count;
                        m->elem_size = last_desc.elem_size;
                    }
                    sec_off += sh.sec_len;
                }

                char prefix[512] = {0};
                if (g_listener_opts.dump_files) {
                    snprintf(prefix, sizeof(prefix), "%s/%s_%06llu", base_dir, kind_to_tag(kind), evt_idx);
                    if (msg_bytes && msg_len != 0) {
                        char pmsg[600];
                        snprintf(pmsg, sizeof(pmsg), "%s_msg.bin", prefix);
                        FILE *fp = fopen(pmsg, "wb");
                        if (fp) {
                            fwrite(msg_bytes, 1, msg_len, fp);
                            fclose(fp);
                        }
                    }

                    sec_off = sizeof(fh);
                    xniff_ipc_v2_desc_meta_t dump_desc = {0};
                    bool have_dump_desc = false;
                    while (sec_off + sizeof(xniff_ipc_v2_section_hdr_t) <= body_len) {
                        xniff_ipc_v2_section_hdr_t sh = {0};
                        memcpy(&sh, body + sec_off, sizeof(sh));
                        sec_off += sizeof(sh);
                        if (sec_off + sh.sec_len > body_len) break;
                        const uint8_t *val = body + sec_off;
                        if (sh.sec_type == XNIFF_V2_SEC_MACH_DESC_META &&
                            sh.sec_len >= sizeof(xniff_ipc_v2_desc_meta_t)) {
                            memcpy(&dump_desc, val, sizeof(dump_desc));
                            have_dump_desc = true;
                        } else if (have_dump_desc && sh.sec_type == XNIFF_V2_SEC_MACH_DESC_OOL_BYTES) {
                            char path[600];
                            snprintf(path, sizeof(path), "%s_ool%u.bin", prefix, dump_desc.index);
                            FILE *fp = fopen(path, "wb");
                            if (fp) {
                                fwrite(val, 1, sh.sec_len, fp);
                                fclose(fp);
                            }
                        } else if (have_dump_desc && sh.sec_type == XNIFF_V2_SEC_MACH_DESC_PORT_ARRAY) {
                            char path[600];
                            snprintf(path, sizeof(path), "%s_ool_ports%u.bin", prefix, dump_desc.index);
                            FILE *fp = fopen(path, "wb");
                            if (fp) {
                                fwrite(val, 1, sh.sec_len, fp);
                                fclose(fp);
                            }
                        }
                        sec_off += sh.sec_len;
                    }
                }

                print_event(kind, &pl, msg_bytes, msg_len);
                if (atts) free(atts);
                evt_idx++;
            }

            memmove(stream, stream + frame_len, stream_len - frame_len);
            stream_len -= frame_len;
        }
        usleep(10 * 1000);
    }
    // unreachable
    return 0;
}

static int install_hooks(pid_t pid, const char *dylib_path, int mode) {
    mach_port_t task;
    if (attach_and_get_task(pid, &task) != 0) return -1;

    // Resolve absolute path so dlopen() in the remote process finds the library
    char abs_path[PATH_MAX] = {0};
    if (!realpath(dylib_path, abs_path)) {
        perror("realpath");
        detach_process(pid);
        return -1;
    }

    char inject_path[PATH_MAX] = {0};
    bool staged_copy =
        stage_dylib_for_sandbox(abs_path, inject_path, sizeof(inject_path)) == 0;
    if (staged_copy) {
        XNIFF_DIAGF("attach: staged hooks dylib at %s (from %s)\n", inject_path, abs_path);
    } else {
        (void)strncpy(inject_path, abs_path, sizeof(inject_path) - 1);
        inject_path[sizeof(inject_path) - 1] = '\0';
        XNIFF_DIAGF("attach: warning: failed to stage hooks dylib; using original path %s\n", abs_path);
    }

    // Inject hooks dylib (uses filtered dlopen/pthread_exit resolution)
    (void)xniff_dump_task_images(task);
    if (xniff_inject_dylib_task(task, inject_path, NULL) != 0) {
        fprintf(stderr, "failed to inject hooks dylib into pid %d\n", pid);
        detach_process(pid);
        if (staged_copy) (void)unlink(inject_path);
        return -1;
    }
    // Wait for dyld to finish loading the injected image; poll for up to ~2s
    for (int i = 0; i < 40; i++) {
        mach_vm_address_t tmp = 0;
        // Try to resolve our exported ABI marker to confirm load
        if (xniff_find_symbol_in_image_exact_path(task, inject_path, "_xniff_hooks_abi_version", &tmp) == 0 ||
            xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "_xniff_hooks_abi_version", &tmp) == 0 ||
            xniff_find_symbol_in_image_exact_path(task, inject_path, "xniff_hooks_abi_version", &tmp) == 0 ||
            xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "xniff_hooks_abi_version", &tmp) == 0) {
            break;
        }
        usleep(50 * 1000);
    }
    if (configure_remote_capture_mode(task, (uint32_t)mode) != 0) {
        fprintf(stderr, "attach: failed to configure capture mode in pid %d\n", pid);
        detach_process(pid);
        if (staged_copy) (void)unlink(inject_path);
        return -1;
    }
    detach_process(pid);
    XNIFF_DIAGF("attach: injected %s; capture mode=%s\n", inject_path,
                mode == XNIFF_HOOK_MODE_XPC ? "xpc" : "mach");
    if (staged_copy) (void)unlink(inject_path);
    return 0;
}

static int spawn_suspended_target(char *const launch_argv[], const char *hooks_path,
                                  int mode, const xniff_target_identity_t *identity,
                                  pid_t *out_pid) {
    if (!launch_argv || !launch_argv[0] || !hooks_path || !out_pid) {
        errno = EINVAL;
        return -1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        /*
         * START_SUSPENDED is too late for platform binaries: dyld can strip
         * DYLD_INSERT_LIBRARIES before the parent gets control.  TRACE_ME
         * marks the child debugged before exec and stops it at the exec trap,
         * so dyld accepts the injected hooks while main is still unreachable.
         */
        if (identity && xniff_target_identity_apply(identity) != 0) {
            fprintf(stderr, "launch: failed to become %s (%u:%u): %s\n",
                    identity->name, (unsigned int)identity->uid,
                    (unsigned int)identity->gid, strerror(errno));
            _exit(126);
        }
        xniff_launch_environment_t launch_environment;
        if (xniff_launch_environment_create(hooks_path, mode, &launch_environment) != 0) {
            _exit(126);
        }
        if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) _exit(126);
        environ = launch_environment.values;
        execvp(launch_argv[0], launch_argv);
        _exit(errno == ENOENT ? 127 : 126);
    }
    if (pid < 0) return -1;

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        return -1;
    }
    if (!WIFSTOPPED(status)) {
        errno = WIFEXITED(status) && WEXITSTATUS(status) == 127 ? ENOENT : ENOEXEC;
        return -1;
    }
    *out_pid = pid;
    return 0;
}

static int continue_traced_target(pid_t pid, int signal_number) {
    return ptrace(PT_CONTINUE, pid, (caddr_t)1, signal_number);
}

static int continue_after_trace_stop(pid_t pid, int status) {
    int signal_number = WSTOPSIG(status);
    /* Exec traps are debugger notifications, not target-visible signals. */
    if (signal_number == SIGTRAP) signal_number = 0;
    return continue_traced_target(pid, signal_number);
}

// Combined workflow: start listener, then inject hooks.
static int capture_attached_process(pid_t pid,
                                    const char *dylib_path,
                                    int mode,
                                    bool resume_target,
                                    bool target_is_child,
                                    bool hooks_preloaded) {
    const char *flow = resume_target ? "launch" : "attach";
    int ready_pipe[2] = {-1, -1};
    if (pipe(ready_pipe) != 0) {
        perror("pipe");
        return -1;
    }
    pid_t child = fork();
    if (child == 0) {
        close(ready_pipe[0]);
        int rc = capture_ring(pid, ready_pipe[1]);
        _exit(rc == 0 ? 0 : 1);
    }
    if (child < 0) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        perror("fork");
        return -1;
    }
    close(ready_pipe[1]);

    struct pollfd ready_poll = {.fd = ready_pipe[0], .events = POLLIN};
    int poll_result = poll(&ready_poll, 1, 5000);
    uint8_t ready_byte = 0;
    bool listener_ready = poll_result > 0 &&
                          read(ready_pipe[0], &ready_byte, sizeof(ready_byte)) == sizeof(ready_byte) &&
                          ready_byte == 1;
    close(ready_pipe[0]);
    if (!listener_ready) {
        fprintf(stderr, "%s: listener failed to start for pid %d\n", flow, (int)pid);
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        return -1;
    }

    if (!hooks_preloaded) {
        int rc = install_hooks(pid, dylib_path, mode);
        if (rc != 0) {
            fprintf(stderr, "%s: hook injection failed; terminating listener (pid %d)\n", flow, (int)child);
            kill(child, SIGTERM);
            (void)waitpid(child, NULL, 0);
            return -1;
        }
    }

    if (resume_target) {
        if (continue_traced_target(pid, 0) != 0) {
            fprintf(stderr, "%s: failed to resume target pid %d: %s\n", flow, (int)pid, strerror(errno));
            kill(child, SIGTERM);
            (void)waitpid(child, NULL, 0);
            return -1;
        }
        XNIFF_DIAGF("%s: resumed target pid %d\n", flow, (int)pid);
    }

    XNIFF_DIAGF("%s: hooks installed; streaming events (listener pid %d). Press Ctrl-C to stop.\n",
                flow, (int)child);
    int listener_status = 0;
    for (;;) {
        int status = 0;
        pid_t w = waitpid(-1, &status, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == child) {
            listener_status = status;
            break;
        }
        if (target_is_child && w == pid) {
            if (WIFSTOPPED(status)) {
                if (continue_after_trace_stop(pid, status) != 0) {
                    fprintf(stderr, "%s: failed to continue target pid %d: %s\n",
                            flow, (int)pid, strerror(errno));
                    (void)kill(child, SIGTERM);
                }
            } else if (WIFEXITED(status)) {
                XNIFF_DIAGF("%s: target pid %d exited with code %d\n",
                            flow, (int)pid, WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                XNIFF_DIAGF("%s: target pid %d exited due to signal %d\n",
                            flow, (int)pid, WTERMSIG(status));
            }
            continue;
        }
    }
    if (WIFEXITED(listener_status)) return WEXITSTATUS(listener_status) == 0 ? 0 : -1;
    return -1;
}

static int cmd_attach(pid_t pid, const char *dylib_path, int mode) {
    return capture_attached_process(pid, dylib_path, mode, false, false, false);
}

static int cmd_launch(const char *dylib_path, int mode, const char *target_user,
                      char *const launch_argv[]) {
    xniff_target_identity_t identity;
    xniff_target_identity_t *identity_ptr = NULL;
    if (target_user) {
        if (xniff_target_identity_resolve(target_user, &identity) != 0) {
            fprintf(stderr, "launch: failed to resolve target user '%s': %s\n",
                    target_user, strerror(errno));
            return -1;
        }
        identity_ptr = &identity;
        XNIFF_DIAGF("launch: target user %s (%u:%u)\n", identity.name,
                    (unsigned int)identity.uid, (unsigned int)identity.gid);
    }
    pid_t pid = 0;
    if (spawn_suspended_target(launch_argv, dylib_path, mode, identity_ptr, &pid) != 0) {
        fprintf(stderr, "launch: failed to spawn suspended target '%s': %s\n",
                launch_argv && launch_argv[0] ? launch_argv[0] : "(null)", strerror(errno));
        return -1;
    }

    XNIFF_DIAGF("launch: spawned suspended pid %d (%s)\n", (int)pid, launch_argv[0]);
    int rc = capture_attached_process(pid, dylib_path, mode, true, true, true);
    if (rc != 0) {
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
    }
    return rc;
}
