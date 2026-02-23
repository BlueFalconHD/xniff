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
#include <spawn.h>

#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach/mach_vm.h>
#include <mach/message.h>
#include <time.h>
#include <sys/stat.h>

#include "../shared/xniff_ipc.h"
#include "../shared/mach_private.h"

#include <xniff/macho.h>
#include <xniff/inject.h>

// New combined workflow command
#include "sniff_xpc_cmd.h"
// XPC wire parser (shared library)
#include "../xpcdesert/xpcdesert.h"

extern char **environ;

typedef struct {
    bool jsonl;
    bool dump_files;
    bool parse_xpc;
    bool xpc_only;
    size_t hex_preview_len;
} listener_opts_t;

enum {
    XNIFF_HOOK_MODE_MACH = 1,
    XNIFF_HOOK_MODE_XPC  = 2,
};

static listener_opts_t g_listener_opts = {
    .jsonl = false,
    .dump_files = true,
    .parse_xpc = true,
    .xpc_only = false,
    .hex_preview_len = 64,
};

static FILE *xniff_diag_stream(void) {
    return g_listener_opts.jsonl ? stderr : stdout;
}

#define XNIFF_DIAGF(...) fprintf(xniff_diag_stream(), __VA_ARGS__)

static int parse_listener_flags(listener_opts_t *opts, int argc, char **argv, int start_idx) {
    if (!opts) return -1;
    for (int i = start_idx; i < argc; i++) {
        const char *a = argv[i];
        if (!a) continue;
        // hook-xpc/sniff-xpc mode flags (not listener flags)
        if (strcmp(a, "--mach") == 0 || strcmp(a, "--xpc") == 0) {
            continue;
        }
        if (strcmp(a, "--jsonl") == 0 || strcmp(a, "--format=jsonl") == 0) {
            opts->jsonl = true;
        } else if (strcmp(a, "--text") == 0 || strcmp(a, "--format=text") == 0) {
            opts->jsonl = false;
        } else if (strcmp(a, "--no-dump") == 0) {
            opts->dump_files = false;
        } else if (strcmp(a, "--no-xpc") == 0) {
            opts->parse_xpc = false;
        } else if (strcmp(a, "--xpc-only") == 0 || strcmp(a, "--no-mach-output") == 0) {
            opts->xpc_only = true;
        } else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            return 1;
        } else {
            fprintf(stderr, "unknown listen flag: %s\n", a);
            return -1;
        }
    }
    return 0;
}

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

static void usage(const char *prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s hook-xpc <pid> <hooks.dylib> [--mach|--xpc]  Inject hooks and install either mach_msg* or libxpc XPC APIs.\n", prog);
    fprintf(stderr, "  %s listen <pid> [flags]          Listen for events from target via in-memory ring buffer.\n", prog);
    fprintf(stderr, "  %s sniff-xpc <pid> <hooks.dylib> [--mach|--xpc] [flags] Start listener, inject hooks, and install automatically.\n", prog);
    fprintf(stderr, "  %s sniff-xpc-launch <hooks.dylib> [--mach|--xpc] [flags] -- <program> [args...]\n", prog);
    fprintf(stderr, "                                   Launch suspended, install hooks before process starts, then resume.\n");
    fprintf(stderr, "  %s sniff-xpc-wait <process_name> <hooks.dylib> [--mach|--xpc] [flags]\n", prog);
    fprintf(stderr, "                                   Poll for process name, stop on first match, inject, then resume.\n");
    fprintf(stderr, "\nNotes:\n");
    fprintf(stderr, "- Hooks are installed in-process via frida-gum after injection.\n");
    fprintf(stderr, "\nListen flags:\n");
    fprintf(stderr, "  --jsonl           Emit JSON Lines (one event per line)\n");
    fprintf(stderr, "  --text            Human-readable output (default)\n");
    fprintf(stderr, "  --no-dump         Do not write /tmp/xniff/<pid>/* files\n");
    fprintf(stderr, "  --no-xpc          Disable XPC payload parsing/formatting\n");
    fprintf(stderr, "  --xpc-only        Suppress Mach API events; emit only high-level XPC hook events\n");
    fprintf(stderr, "  --no-mach-output  Alias for --xpc-only\n");
}

// Forward declare subcommand implementation
static int cmd_hook_xpc(pid_t pid, const char *dylib_path, int mode);
static int cmd_listen(pid_t pid);
static int cmd_sniff_xpc_launch(const char *dylib_path, int mode, char *const launch_argv[]);
static int cmd_sniff_xpc_wait(const char *process_name, const char *dylib_path, int mode);

static int find_double_dash(int argc, char **argv, int start_idx) {
    for (int i = start_idx; i < argc; i++) {
        if (argv[i] && strcmp(argv[i], "--") == 0) return i;
    }
    return -1;
}

static int parse_hook_mode_flags(int argc, char **argv, int start_idx, int end_idx, int *mode_out) {
    bool saw_mach = false, saw_xpc = false;
    if (end_idx < 0 || end_idx > argc) end_idx = argc;
    for (int i = start_idx; i < end_idx; i++) {
        const char *a = argv[i];
        if (!a) continue;
        if (strcmp(a, "--mach") == 0) saw_mach = true;
        else if (strcmp(a, "--xpc") == 0) saw_xpc = true;
    }
    if (saw_mach && saw_xpc) return -1;
    int mode = XNIFF_HOOK_MODE_MACH;
    if (saw_xpc) mode = XNIFF_HOOK_MODE_XPC;
    if (mode_out) *mode_out = mode;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 2; }

    // Subcommand: listen <pid>
    if (strcmp(argv[1], "listen") == 0) {
        if (argc < 3) { usage(argv[0]); return 2; }
        pid_t pid = (pid_t)strtol(argv[2], NULL, 10);
        if (pid <= 0) { usage(argv[0]); return 2; }
        int prc = parse_listener_flags(&g_listener_opts, argc, argv, 3);
        if (prc != 0) { usage(argv[0]); return prc > 0 ? 0 : 2; }
        int rc = cmd_listen(pid);
        return (rc == 0) ? 0 : 1;
    }

    // Subcommand: sniff-xpc <pid> <hooks.dylib>
    if (strcmp(argv[1], "sniff-xpc") == 0) {
        if (argc < 4) { usage(argv[0]); return 2; }
        pid_t pid = (pid_t)strtol(argv[2], NULL, 10);
        if (pid <= 0) { usage(argv[0]); return 2; }
        const char *path = argv[3];
        int mode = XNIFF_HOOK_MODE_MACH;
        if (parse_hook_mode_flags(argc, argv, 4, argc, &mode) != 0) {
            fprintf(stderr, "sniff-xpc: choose exactly one of --mach or --xpc\n");
            return 2;
        }
        int prc = parse_listener_flags(&g_listener_opts, argc, argv, 4);
        if (prc != 0) { usage(argv[0]); return prc > 0 ? 0 : 2; }
        int rc = cmd_sniff_xpc(pid, path, mode);
        return (rc == 0) ? 0 : 1;
    }

    // Subcommand: sniff-xpc-launch <hooks.dylib> [--mach|--xpc] [flags] -- <program> [args...]
    if (strcmp(argv[1], "sniff-xpc-launch") == 0) {
        if (argc < 5) { usage(argv[0]); return 2; }
        const char *path = argv[2];
        int sep = find_double_dash(argc, argv, 3);
        if (sep < 0 || (sep + 1) >= argc) {
            fprintf(stderr, "sniff-xpc-launch: missing target program; use -- <program> [args...]\n");
            usage(argv[0]);
            return 2;
        }
        int mode = XNIFF_HOOK_MODE_MACH;
        if (parse_hook_mode_flags(argc, argv, 3, sep, &mode) != 0) {
            fprintf(stderr, "sniff-xpc-launch: choose exactly one of --mach or --xpc\n");
            return 2;
        }
        int prc = parse_listener_flags(&g_listener_opts, sep, argv, 3);
        if (prc != 0) { usage(argv[0]); return prc > 0 ? 0 : 2; }
        int rc = cmd_sniff_xpc_launch(path, mode, &argv[sep + 1]);
        return (rc == 0) ? 0 : 1;
    }

    // Subcommand: sniff-xpc-wait <process_name> <hooks.dylib> [--mach|--xpc] [flags]
    if (strcmp(argv[1], "sniff-xpc-wait") == 0) {
        if (argc < 4) { usage(argv[0]); return 2; }
        const char *process_name = argv[2];
        const char *path = argv[3];
        int mode = XNIFF_HOOK_MODE_MACH;
        if (parse_hook_mode_flags(argc, argv, 4, argc, &mode) != 0) {
            fprintf(stderr, "sniff-xpc-wait: choose exactly one of --mach or --xpc\n");
            return 2;
        }
        int prc = parse_listener_flags(&g_listener_opts, argc, argv, 4);
        if (prc != 0) { usage(argv[0]); return prc > 0 ? 0 : 2; }
        int rc = cmd_sniff_xpc_wait(process_name, path, mode);
        return (rc == 0) ? 0 : 1;
    }

    // Subcommand: hook-xpc <pid> <hooks.dylib>
    if (strcmp(argv[1], "hook-xpc") == 0) {
        if (argc < 4) { usage(argv[0]); return 2; }
        pid_t pid = (pid_t)strtol(argv[2], NULL, 10);
        if (pid <= 0) { usage(argv[0]); return 2; }
        const char *path = argv[3];
        int mode = XNIFF_HOOK_MODE_MACH;
        if (parse_hook_mode_flags(argc, argv, 4, argc, &mode) != 0) {
            fprintf(stderr, "hook-xpc: choose exactly one of --mach or --xpc\n");
            return 2;
        }
        int rc = cmd_hook_xpc(pid, path, mode);
        return (rc == 0) ? 0 : 1;
    }

    usage(argv[0]);
    return 2;
}

static bool payload_len_sane(uint32_t payload_len) {
    if (payload_len < sizeof(uint32_t)) return false;
    if (payload_len > (64u * 1024u * 1024u)) return false;
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

typedef struct pending_call {
    uint32_t pid;
    uint32_t tid_low;
    uint32_t api;
    uint32_t sub;
    uint64_t call_id;
    unsigned long long entry_event_id;
    struct pending_call *next;
} pending_call_t;

static pending_call_t *g_pending_calls = NULL;
static uint64_t g_next_call_id = 1;

static void pending_calls_clear_pid(uint32_t pid) {
    pending_call_t **pp = &g_pending_calls;
    while (*pp) {
        pending_call_t *c = *pp;
        if (c->pid == pid) {
            *pp = c->next;
            free(c);
            continue;
        }
        pp = &c->next;
    }
}

static void pending_calls_drop_one(uint32_t pid, uint32_t tid_low, uint32_t api, uint32_t sub) {
    pending_call_t **pp = &g_pending_calls;
    while (*pp) {
        pending_call_t *c = *pp;
        if (c->pid == pid && c->tid_low == tid_low && c->api == api && c->sub == sub) {
            *pp = c->next;
            free(c);
            return;
        }
        pp = &c->next;
    }
}

static uint64_t pending_calls_push(uint32_t pid, uint32_t tid_low, uint32_t api, uint32_t sub, unsigned long long entry_event_id) {
    pending_calls_drop_one(pid, tid_low, api, sub); // avoid unbounded growth if an exit event is dropped
    pending_call_t *c = (pending_call_t *)calloc(1, sizeof(*c));
    if (!c) return 0;
    c->pid = pid;
    c->tid_low = tid_low;
    c->api = api;
    c->sub = sub;
    c->call_id = g_next_call_id++;
    if (c->call_id == 0) c->call_id = g_next_call_id++;
    c->entry_event_id = entry_event_id;
    c->next = g_pending_calls;
    g_pending_calls = c;
    return c->call_id;
}

static bool pending_calls_pop(uint32_t pid, uint32_t tid_low, uint32_t api, uint32_t sub, uint64_t *call_id_out, unsigned long long *entry_event_id_out) {
    pending_call_t **pp = &g_pending_calls;
    while (*pp) {
        pending_call_t *c = *pp;
        if (c->pid == pid && c->tid_low == tid_low && c->api == api && c->sub == sub) {
            *pp = c->next;
            if (call_id_out) *call_id_out = c->call_id;
            if (entry_event_id_out) *entry_event_id_out = c->entry_event_id;
            free(c);
            return true;
        }
        pp = &c->next;
    }
    return false;
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
    const char *peer_role;        // sender / recipient / unknown
    uint64_t conn_ptr;
    uint64_t msg_ptr;
    uint64_t conn_seq;
    unsigned long long response_to_event_id;
    const char *service_name;
    uint32_t peer_pid;
    const char *peer_name;
} xniff_xpc_analysis_t;

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
        pl->func == XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER) {
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
            return "send";
        case XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER:
            return "recv";
        case XNIFF_XPC_FUNC_PIPE_ROUTINE:
            return "rpc";
        case XNIFF_XPC_FUNC_CONNECTION_CREATE:
            return "meta";
    }
    return "unknown";
}

static const char *xpc_peer_role_for_flow(const char *flow) {
    if (!flow) return "unknown";
    if (strcmp(flow, "send") == 0) return "recipient";
    if (strcmp(flow, "recv") == 0) return "sender";
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

        if (ihdr->kind == XNIFF_EVT_XPC_ENTRY && strcmp(out->flow, "recv") == 0) {
            m->last_recv_event_id = event_id;
            m->last_recv_tid_low = ihdr->tid_low;
            m->last_recv_mono_s = mono_s;
        } else if (ihdr->kind == XNIFF_EVT_XPC_ENTRY && strcmp(out->flow, "send") == 0) {
            if (m->last_recv_event_id != 0 &&
                ihdr->tid_low == m->last_recv_tid_low &&
                mono_s >= m->last_recv_mono_s &&
                (mono_s - m->last_recv_mono_s) <= 2.0) {
                out->response_to_event_id = m->last_recv_event_id;
                m->last_recv_event_id = 0;
            }
        }

        out->peer_pid = (m->peer_pid != 0) ? m->peer_pid : pl->conn_pid;
        out->service_name = str_nonempty(m->service) ? m->service : NULL;
    } else {
        out->peer_pid = pl->conn_pid;
        out->service_name = str_nonempty(s0) ? s0 : NULL;
    }

    out->peer_name = (out->peer_pid != 0) ? proc_name_cached((pid_t)out->peer_pid) : NULL;
}

static void json_write_escaped(FILE *out, const char *s) {
    fputc('"', out);
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            unsigned char c = *p;
            switch (c) {
                case '"':  fputs("\\\"", out); break;
                case '\\': fputs("\\\\", out); break;
                case '\b': fputs("\\b", out); break;
                case '\f': fputs("\\f", out); break;
                case '\n': fputs("\\n", out); break;
                case '\r': fputs("\\r", out); break;
                case '\t': fputs("\\t", out); break;
                default:
                    if (c < 0x20) fprintf(out, "\\u%04x", (unsigned)c);
                    else fputc((int)c, out);
                    break;
            }
        }
    }
    fputc('"', out);
}

static void json_write_hex(FILE *out, const uint8_t *p, size_t len) {
    fputc('"', out);
    for (size_t i = 0; i < len; i++) fprintf(out, "%02x", p[i]);
    fputc('"', out);
}

static void json_write_hex_u64(FILE *out, uint64_t v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
    json_write_escaped(out, buf);
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

static void jsonl_print_event(
    unsigned long long event_id,
    uint64_t call_id,
    unsigned long long entry_event_id,
    const xniff_ipc_hdr_t *ihdr,
    const xniff_ipc_mach_payload_t *pl,
    const uint8_t *msg_bytes,
    size_t msg_len,
    const char *tbuf,
    double mono_s,
    const char *msg_path,
    const xniff_att_meta_t *atts,
    size_t att_count)
{
    const mach_msg_header_t *mh = NULL;
    if (msg_bytes && msg_len >= sizeof(mach_msg_header_t)) mh = (const mach_msg_header_t *)msg_bytes;

    uint64_t option64 = ((uint64_t)pl->option_hi << 32) | (uint64_t)pl->option_lo;
    bool is_send = false, is_recv = false;
    if (pl->api == XNIFF_API_MACH_MSG) {
        is_send = (pl->option_lo & MACH_SEND_MSG) != 0;
        is_recv = (pl->option_lo & MACH_RCV_MSG) != 0;
    } else {
        is_send = (option64 & MACH64_SEND_MSG) != 0;
        is_recv = (option64 & MACH64_RCV_MSG) != 0;
    }

    size_t xpc_offset = 0;
    char *xpc_pretty = NULL;
    if (g_listener_opts.parse_xpc && msg_bytes && msg_len >= 16) {
        if (xpcd_find_payload(msg_bytes, msg_len, 512, &xpc_offset) == 0) {
            xpcd_object_t *root = xpcd_parse(msg_bytes + xpc_offset, msg_len - xpc_offset);
            if (root) {
                xpc_pretty = xpcd_format(root);
                xpcd_free(root);
            }
        }
    }

    fputc('{', stdout);
    fputs("\"schema\":\"xniff.event.v1\",", stdout);
    fputs("\"event_id\":", stdout); fprintf(stdout, "%llu,", event_id);
    fputs("\"call_id\":", stdout); fprintf(stdout, "%llu,", (unsigned long long)call_id);
    fputs("\"entry_event_id\":", stdout); fprintf(stdout, "%llu,", entry_event_id);
    fputs("\"kind\":", stdout); json_write_escaped(stdout, kind_to_tag((int)ihdr->kind)); fputc(',', stdout);
    fputs("\"pid\":", stdout); fprintf(stdout, "%u,", ihdr->pid);
    const char *proc_name = proc_name_cached((pid_t)ihdr->pid);
    fputs("\"proc_name\":", stdout); if (proc_name) json_write_escaped(stdout, proc_name); else fputs("null", stdout); fputc(',', stdout);
    fputs("\"tid_low\":", stdout); fprintf(stdout, "%u,", ihdr->tid_low);
    fputs("\"ts_real\":", stdout); json_write_escaped(stdout, tbuf); fputc(',', stdout);
    fputs("\"ts_mono_s\":", stdout); fprintf(stdout, "%.9f,", mono_s);

    fputs("\"mach\":{", stdout);
    fputs("\"api\":", stdout); fprintf(stdout, "%u,", pl->api);
    fputs("\"direction\":", stdout); fprintf(stdout, "%u,", pl->direction);
    fputs("\"is_send\":", stdout); fputs(is_send ? "true," : "false,", stdout);
    fputs("\"is_recv\":", stdout); fputs(is_recv ? "true," : "false,", stdout);
    fputs("\"msgh_id\":", stdout); fprintf(stdout, "%d,", mh ? mh->msgh_id : -1);
    fputs("\"msgh_bits\":", stdout); fprintf(stdout, "%u,", mh ? (unsigned)mh->msgh_bits : 0u);
    fputs("\"remote\":", stdout); fprintf(stdout, "%u,", mh ? (unsigned)mh->msgh_remote_port : 0u);
    fputs("\"local\":", stdout); fprintf(stdout, "%u,", mh ? (unsigned)mh->msgh_local_port : 0u);

    uint32_t peer_pid = 0;
    const char *peer_role = "unknown";
    if (pl->direction == XNIFF_DIR_EXIT && is_recv && pl->ret_value == 0) {
        peer_role = "sender";
        uint32_t sz = pl->msgh_size;
        if (sz == 0 && mh) sz = (uint32_t)mh->msgh_size;
        if (sz != 0) (void)mach_extract_sender_pid_from_trailer(msg_bytes, msg_len, sz, &peer_pid);
    } else if (is_send) {
        peer_role = "recipient";
    }
    const char *peer_name = (peer_pid != 0) ? proc_name_cached((pid_t)peer_pid) : NULL;
    fputs("\"peer_role\":", stdout); json_write_escaped(stdout, peer_role); fputc(',', stdout);
    fputs("\"peer_pid\":", stdout); if (peer_pid) fprintf(stdout, "%u,", peer_pid); else fputs("null,", stdout);
    fputs("\"peer_name\":", stdout); if (peer_name) json_write_escaped(stdout, peer_name); else fputs("null", stdout);
    fputc(',', stdout);

    fputs("\"msg_addr\":", stdout); json_write_hex_u64(stdout, pl->msg_addr); fputc(',', stdout);
    fputs("\"aux_addr\":", stdout); json_write_hex_u64(stdout, pl->aux_addr); fputc(',', stdout);
    fputs("\"option64\":", stdout); json_write_hex_u64(stdout, option64); fputc(',', stdout);
    fputs("\"ret\":", stdout); fprintf(stdout, "%llu,", (unsigned long long)pl->ret_value);
    fputs("\"priority\":", stdout); fprintf(stdout, "%u,", pl->priority);
    fputs("\"timeout\":", stdout); fprintf(stdout, "%llu,", (unsigned long long)pl->timeout);
    fputs("\"msgh_size\":", stdout); fprintf(stdout, "%u,", pl->msgh_size);
    fputs("\"copy_len\":", stdout); fprintf(stdout, "%u,", pl->copy_len);
    fputs("\"msg_len\":", stdout); fprintf(stdout, "%zu", msg_len);
    fputs("},", stdout);

    fputs("\"dump\":{", stdout);
    fputs("\"msg_path\":", stdout); if (msg_path) json_write_escaped(stdout, msg_path); else fputs("null", stdout);
    fputs(",\"msg_hex\":", stdout);
    size_t preview = g_listener_opts.hex_preview_len;
    if (preview > msg_len) preview = msg_len;
    if (msg_bytes && preview) json_write_hex(stdout, msg_bytes, preview);
    else fputs("\"\"", stdout);
    fputs(",\"attachments\":[", stdout);
    for (size_t i = 0; i < att_count; i++) {
        if (i) fputc(',', stdout);
        fputc('{', stdout);
        fputs("\"type\":", stdout);
        if (atts[i].type == XNIFF_TLV_OOL_DATA) json_write_escaped(stdout, "ool_data");
        else if (atts[i].type == XNIFF_TLV_OOL_PORTS) json_write_escaped(stdout, "ool_ports");
        else json_write_escaped(stdout, "unknown");
        fputs(",\"index\":", stdout); fprintf(stdout, "%u", atts[i].index);
        fputs(",\"address\":", stdout); json_write_hex_u64(stdout, atts[i].address);
        if (atts[i].type == XNIFF_TLV_OOL_DATA) {
            fputs(",\"size\":", stdout); fprintf(stdout, "%u", atts[i].size_bytes);
        } else if (atts[i].type == XNIFF_TLV_OOL_PORTS) {
            fputs(",\"count\":", stdout); fprintf(stdout, "%u", atts[i].count);
            fputs(",\"elem_size\":", stdout); fprintf(stdout, "%u", atts[i].elem_size);
            fputs(",\"size\":", stdout); fprintf(stdout, "%u", atts[i].size_bytes);
        }
        fputs(",\"path\":", stdout); json_write_escaped(stdout, atts[i].path);
        fputc('}', stdout);
    }
    fputs("]}", stdout);

    if (xpc_pretty) {
        fputs(",\"xpc\":{", stdout);
        fputs("\"offset\":", stdout); fprintf(stdout, "%zu,", xpc_offset);
        fputs("\"pretty\":", stdout); json_write_escaped(stdout, xpc_pretty);
        fputc('}', stdout);
    }

    fputs("}\n", stdout);
    fflush(stdout);
    if (xpc_pretty) free(xpc_pretty);
}

static void json_write_escaped(FILE *out, const char *s);
static void json_write_hex_u64(FILE *out, uint64_t v);

static const char *xpc_func_to_name(uint32_t func) {
    switch (func) {
        case XNIFF_XPC_FUNC_CONNECTION_CREATE: return "xpc_connection_create";
        case XNIFF_XPC_FUNC_PIPE_ROUTINE: return "xpc_pipe_routine";
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE: return "xpc_connection_send_message";
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY: return "xpc_connection_send_message_with_reply";
        case XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC: return "xpc_connection_send_message_with_reply_sync";
        case XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER: return "_xpc_connection_call_event_handler";
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

static void jsonl_write_xpc_string_fields(uint16_t kind, uint32_t func,
                                          const char *s0, const char *s1,
                                          const char *s2, const char *s3) {
    const char *vals[4] = {s0, s1, s2, s3};
    xpc_string_schema_t sc = xpc_string_schema_for_event(kind, func);
    bool first = true;
    fputc('{', stdout);
    for (size_t i = 0; i < 4; i++) {
        const char *name = sc.slot_name[i];
        const char *val = vals[i];
        if (!name || !val) continue;
        if (!first) fputc(',', stdout);
        json_write_escaped(stdout, name);
        fputc(':', stdout);
        json_write_escaped(stdout, val);
        first = false;
    }
    fputc('}', stdout);
}

static void jsonl_write_xpc_named_args(uint32_t func, const uint64_t args[8]) {
    bool first = true;
    fputc('{', stdout);
    for (size_t i = 0; i < 8; i++) {
        const char *name = xpc_arg_name(func, i);
        if (!name) continue;
        if (!first) fputc(',', stdout);
        json_write_escaped(stdout, name);
        fputc(':', stdout);
        json_write_hex_u64(stdout, args[i]);
        first = false;
    }
    fputc('}', stdout);
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

static void jsonl_print_xpc_event(
    unsigned long long event_id,
    uint64_t call_id,
    unsigned long long entry_event_id,
    const xniff_ipc_hdr_t *ihdr,
    const xniff_ipc_xpc_payload_t *pl,
    const xniff_xpc_analysis_t *xa,
    const char *s0,
    const char *s1,
    const char *s2,
    const char *s3,
    const char *tbuf,
    double mono_s)
{
    fputc('{', stdout);
    fputs("\"schema\":\"xniff.event.v1\",", stdout);
    fputs("\"event_id\":", stdout); fprintf(stdout, "%llu,", event_id);
    fputs("\"call_id\":", stdout); fprintf(stdout, "%llu,", (unsigned long long)call_id);
    fputs("\"entry_event_id\":", stdout); fprintf(stdout, "%llu,", entry_event_id);
    fputs("\"kind\":", stdout); json_write_escaped(stdout, kind_to_tag((int)ihdr->kind)); fputc(',', stdout);
    fputs("\"pid\":", stdout); fprintf(stdout, "%u,", ihdr->pid);
    const char *proc_name = proc_name_cached((pid_t)ihdr->pid);
    fputs("\"proc_name\":", stdout); if (proc_name) json_write_escaped(stdout, proc_name); else fputs("null", stdout); fputc(',', stdout);
    fputs("\"tid_low\":", stdout); fprintf(stdout, "%u,", ihdr->tid_low);
    fputs("\"ts_real\":", stdout); json_write_escaped(stdout, tbuf); fputc(',', stdout);
    fputs("\"ts_mono_s\":", stdout); fprintf(stdout, "%.9f,", mono_s);

    fputs("\"xpc\":{", stdout);
    fputs("\"direction\":", stdout); fprintf(stdout, "%u,", pl->direction);
    fputs("\"func\":", stdout); fprintf(stdout, "%u,", pl->func);
    fputs("\"func_name\":", stdout); json_write_escaped(stdout, xpc_func_to_name(pl->func)); fputc(',', stdout);
    const char *flow = (xa && xa->flow) ? xa->flow : "unknown";
    const char *peer_role = (xa && xa->peer_role) ? xa->peer_role : "unknown";
    uint64_t conn_ptr = xa ? xa->conn_ptr : 0;
    uint64_t msg_ptr = xa ? xa->msg_ptr : 0;
    uint64_t conn_seq = xa ? xa->conn_seq : 0;
    unsigned long long response_to_event_id = xa ? xa->response_to_event_id : 0;
    uint32_t conn_pid = xa ? xa->peer_pid : pl->conn_pid;
    const char *conn_name = (xa && xa->peer_name) ? xa->peer_name : ((conn_pid != 0) ? proc_name_cached((pid_t)conn_pid) : NULL);
    const char *service_name = (xa && xa->service_name) ? xa->service_name : (str_nonempty(s0) ? s0 : NULL);

    fputs("\"flow\":", stdout); json_write_escaped(stdout, flow); fputc(',', stdout);
    fputs("\"peer_role\":", stdout); json_write_escaped(stdout, peer_role); fputc(',', stdout);
    fputs("\"conn_ptr\":", stdout); json_write_hex_u64(stdout, conn_ptr); fputc(',', stdout);
    fputs("\"msg_ptr\":", stdout); json_write_hex_u64(stdout, msg_ptr); fputc(',', stdout);
    fputs("\"conn_seq\":", stdout); if (conn_seq != 0) fprintf(stdout, "%llu,", (unsigned long long)conn_seq); else fputs("null,", stdout);
    fputs("\"response_to_event_id\":", stdout); if (response_to_event_id != 0) fprintf(stdout, "%llu,", response_to_event_id); else fputs("null,", stdout);
    fputs("\"service_name\":", stdout); if (service_name) json_write_escaped(stdout, service_name); else fputs("null", stdout); fputc(',', stdout);
    fputs("\"conn_pid\":", stdout); fprintf(stdout, "%u,", conn_pid);
    fputs("\"conn_name\":", stdout); if (conn_name) json_write_escaped(stdout, conn_name); else fputs("null", stdout); fputc(',', stdout);
    fputs("\"ret\":", stdout); json_write_hex_u64(stdout, pl->ret_value); fputc(',', stdout);
    fputs("\"args\":[", stdout);
    for (int i = 0; i < 8; i++) {
        if (i) fputc(',', stdout);
        json_write_hex_u64(stdout, pl->args[i]);
    }
    fputs("],", stdout);
    fputs("\"args_named\":", stdout); jsonl_write_xpc_named_args(pl->func, pl->args); fputc(',', stdout);
    fputs("\"string_fields\":", stdout); jsonl_write_xpc_string_fields(ihdr->kind, pl->func, s0, s1, s2, s3); fputc(',', stdout);
    fputs("\"str0\":", stdout); if (s0) json_write_escaped(stdout, s0); else fputs("null", stdout);
    fputs(",\"str1\":", stdout); if (s1) json_write_escaped(stdout, s1); else fputs("null", stdout);
    fputs(",\"str2\":", stdout); if (s2) json_write_escaped(stdout, s2); else fputs("null", stdout);
    fputs(",\"str3\":", stdout); if (s3) json_write_escaped(stdout, s3); else fputs("null", stdout);
    fputc('}', stdout);

    fputs("}\n", stdout);
    fflush(stdout);
}

static void print_xpc_event(
    const xniff_ipc_hdr_t *ihdr,
    const xniff_ipc_xpc_payload_t *pl,
    const xniff_xpc_analysis_t *xa,
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
    const char *service_name = (xa && xa->service_name) ? xa->service_name : (str_nonempty(s0) ? s0 : NULL);
    uint64_t conn_ptr = xa ? xa->conn_ptr : 0;
    uint64_t msg_ptr = xa ? xa->msg_ptr : 0;

    printf("[%s][+%0.6fs] %s\n", tbuf, mono_s, kstr);
    printf("  xpc.func: %s (%u)\n", xpc_func_to_name(pl->func), pl->func);
    printf("  xpc.flow: %s\n", flow);
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

static int cmd_listen(pid_t pid) {
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "listen: task_for_pid failed for %d: %d (%s)\n",
                (int)pid, kr, mach_error_string(kr));
        return -1;
    }
    const bool handle_hook_debug_logs = env_var_enabled("XNIFF_HOOKS_DEBUG");

    mach_vm_address_t ring_addr = 0;
    for (int i = 0; i < 400; i++) { // up to ~20s while parent injects hooks
        if (resolve_remote_ring_addr(task, &ring_addr) == 0) break;
        usleep(50 * 1000);
    }
    if (ring_addr == 0) {
        fprintf(stderr, "listen: failed to resolve remote xniff ring symbol in pid %d\n", (int)pid);
        return -1;
    }

    mach_vm_address_t ring_hdr_addr = ring_addr + (mach_vm_address_t)offsetof(xniff_ipc_ring_t, hdr);
    mach_vm_address_t ring_data_addr = ring_addr + (mach_vm_address_t)offsetof(xniff_ipc_ring_t, data);
    mach_vm_address_t ring_read_idx_addr =
        ring_hdr_addr + (mach_vm_address_t)offsetof(xniff_ipc_ring_hdr_t, read_idx);

    XNIFF_DIAGF("listening on ring buffer: target_pid=%d ring=0x%llx\n",
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

    for (;;) {
        xniff_ipc_ring_hdr_t rmeta = {0};
        if (task_read_exact(task, ring_hdr_addr, &rmeta, sizeof(rmeta)) != 0) {
            usleep(10 * 1000);
            continue;
        }
        if (rmeta.magic != XNIFF_IPC_RING_MAGIC || rmeta.version != XNIFF_IPC_RING_VERSION ||
            rmeta.capacity == 0 || rmeta.capacity > XNIFF_IPC_RING_CAPACITY) {
            usleep(10 * 1000);
            continue;
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
                    fprintf(stderr, "listen: oom while growing stream buffer\n");
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

        while (stream_len >= sizeof(xniff_ipc_hdr_t)) {
            xniff_ipc_hdr_t hdr;
            memcpy(&hdr, stream, sizeof(hdr));
            if (hdr.magic != XNIFF_IPC_MAGIC || hdr.version != XNIFF_IPC_VERSION ||
                !payload_len_sane(hdr.payload_len)) {
                memmove(stream, stream + 1, stream_len - 1);
                stream_len -= 1;
                continue;
            }
            size_t frame_len = sizeof(hdr) + (size_t)hdr.payload_len;
            if (stream_len < frame_len) break;

            uint8_t *buf = NULL;
            if (hdr.payload_len != 0) {
                buf = (uint8_t *)malloc(hdr.payload_len);
                if (!buf) {
                    fprintf(stderr, "oom %u\n", hdr.payload_len);
                    free(stream);
                    return -1;
                }
                memcpy(buf, stream + sizeof(hdr), hdr.payload_len);
            }

            if (hdr.kind == XNIFF_EVT_DEBUG_LOG) {
                if (handle_hook_debug_logs && hdr.payload_len >= sizeof(xniff_ipc_debug_payload_t)) {
                    xniff_ipc_debug_payload_t *dpl = (xniff_ipc_debug_payload_t *)buf;
                    size_t off = sizeof(*dpl);
                    uint32_t msg_len = dpl->msg_len;
                    if (msg_len > hdr.payload_len - off) msg_len = (uint32_t)(hdr.payload_len - off);
                    char *line = wire_copy_str(buf, hdr.payload_len, &off, msg_len);
                    char tbuf[64];
                    double mono_s = 0.0;
                    format_time(tbuf, sizeof(tbuf), &mono_s);
                    append_hook_debug_log(hdr.pid, hdr.tid_low, tbuf, mono_s, line ? line : "");
                    if (!g_listener_opts.jsonl && line && *line) {
                        printf("[hook-debug][pid=%u][tid=0x%x] %s\n", hdr.pid, hdr.tid_low, line);
                    }
                    if (line) free(line);
                }
                if (buf) free(buf);
                memmove(stream, stream + frame_len, stream_len - frame_len);
                stream_len -= frame_len;
                continue;
            }

            uint32_t api = 0;
            if (hdr.payload_len >= sizeof(api)) memcpy(&api, buf, sizeof(api));

            if (g_listener_opts.xpc_only && api != XNIFF_API_XPC_HL) {
                if (buf) free(buf);
                memmove(stream, stream + frame_len, stream_len - frame_len);
                stream_len -= frame_len;
                continue;
            }

            unsigned long long cur_evt_id = evt_idx;
            uint64_t call_id = 0;
            unsigned long long entry_evt_id = 0;

            if (api == XNIFF_API_XPC_HL) {
                if (hdr.payload_len >= sizeof(xniff_ipc_xpc_payload_t)) {
                    xniff_ipc_xpc_payload_t *pl = (xniff_ipc_xpc_payload_t *)buf;
                    size_t off = sizeof(*pl);
                    char *s0 = wire_copy_str(buf, hdr.payload_len, &off, pl->str0_len);
                    char *s1 = wire_copy_str(buf, hdr.payload_len, &off, pl->str1_len);
                    char *s2 = wire_copy_str(buf, hdr.payload_len, &off, pl->str2_len);
                    char *s3 = wire_copy_str(buf, hdr.payload_len, &off, pl->str3_len);

                    bool is_entry = (hdr.kind == XNIFF_EVT_XPC_ENTRY);
                    bool is_exit = (hdr.kind == XNIFF_EVT_XPC_EXIT);
                    if (is_entry) {
                        call_id = pending_calls_push(hdr.pid, hdr.tid_low, pl->api, pl->func, cur_evt_id);
                    } else if (is_exit) {
                        (void)pending_calls_pop(hdr.pid, hdr.tid_low, pl->api, pl->func,
                                                &call_id, &entry_evt_id);
                    }

                    char tbuf[64];
                    double mono_s = 0.0;
                    format_time(tbuf, sizeof(tbuf), &mono_s);

                    xniff_xpc_analysis_t xa;
                    analyze_xpc_event(cur_evt_id, &hdr, pl, s0, mono_s, &xa);

                    if (g_listener_opts.jsonl) {
                        jsonl_print_xpc_event(cur_evt_id, call_id, entry_evt_id, &hdr, pl,
                                              &xa, s0, s1, s2, s3, tbuf, mono_s);
                    } else {
                        print_xpc_event(&hdr, pl, &xa, s0, s1, s2, s3, tbuf, mono_s);
                    }
                    free(s0);
                    free(s1);
                    free(s2);
                    free(s3);
                    evt_idx++;
                }
                if (buf) free(buf);
                memmove(stream, stream + frame_len, stream_len - frame_len);
                stream_len -= frame_len;
                continue;
            }

            if (hdr.payload_len >= sizeof(xniff_ipc_mach_payload_t)) {
                xniff_ipc_mach_payload_t *pl = (xniff_ipc_mach_payload_t *)buf;
                uint8_t *msg_bytes = buf + sizeof(*pl);
                size_t msg_avail = 0;
                if (hdr.payload_len > sizeof(*pl)) msg_avail = (size_t)hdr.payload_len - sizeof(*pl);
                size_t msg_len = pl->copy_len;
                if (msg_len > msg_avail) msg_len = msg_avail;

                bool is_entry = (hdr.kind == XNIFF_EVT_MACH_ENTRY || hdr.kind == XNIFF_EVT_MACH2_ENTRY);
                bool is_exit = (hdr.kind == XNIFF_EVT_MACH_EXIT || hdr.kind == XNIFF_EVT_MACH2_EXIT);
                if (is_entry) {
                    call_id = pending_calls_push(hdr.pid, hdr.tid_low, pl->api, 0, cur_evt_id);
                } else if (is_exit) {
                    (void)pending_calls_pop(hdr.pid, hdr.tid_low, pl->api, 0, &call_id, &entry_evt_id);
                }

                // Dump inline message bytes + attachments to files (optional), and collect metadata for JSONL.
                char prefix[512] = {0};
                char pmsg[600] = {0};
                const char *msg_path = NULL;
                xniff_att_meta_t *atts = NULL;
                size_t att_count = 0, att_cap = 0;

                if (g_listener_opts.dump_files) {
                    snprintf(prefix, sizeof(prefix), "%s/%s_%06llu", base_dir, kind_to_tag(hdr.kind), evt_idx);
                    if (msg_len) {
                        snprintf(pmsg, sizeof(pmsg), "%s_msg.bin", prefix);
                        FILE *fp = fopen(pmsg, "wb");
                        if (fp) {
                            fwrite(msg_bytes, 1, msg_len, fp);
                            fclose(fp);
                            msg_path = pmsg;
                        }
                    }
                }

                // Parse TLVs already contained in payload and dump them
                size_t offset = sizeof(*pl) + msg_len;
                while (offset + sizeof(xniff_ipc_tlv_t) <= hdr.payload_len) {
                    xniff_ipc_tlv_t *tlv = (xniff_ipc_tlv_t *)(buf + offset);
                    offset += sizeof(*tlv);
                    if (offset + tlv->length > hdr.payload_len) break; // malformed
                    uint8_t *val = buf + offset;

                    if ((tlv->type == XNIFF_TLV_OOL_DATA && tlv->length >= sizeof(xniff_ool_data_t)) ||
                        (tlv->type == XNIFF_TLV_OOL_PORTS && tlv->length >= sizeof(xniff_ool_ports_t))) {
                        if (att_count == att_cap) {
                            size_t new_cap = att_cap ? att_cap * 2 : 8;
                            xniff_att_meta_t *tmp = (xniff_att_meta_t *)realloc(atts, new_cap * sizeof(*atts));
                            if (!tmp) break;
                            atts = tmp;
                            att_cap = new_cap;
                        }
                        xniff_att_meta_t *m = &atts[att_count++];
                        memset(m, 0, sizeof(*m));
                        m->type = tlv->type;
                        if (tlv->type == XNIFF_TLV_OOL_DATA) {
                            xniff_ool_data_t *md = (xniff_ool_data_t *)val;
                            m->index = md->index;
                            m->address = md->address;
                            m->size_bytes = md->size;
                            if (g_listener_opts.dump_files) {
                                snprintf(m->path, sizeof(m->path), "%s_ool%u.bin", prefix, md->index);
                                const uint8_t *bytes = val + sizeof(*md);
                                FILE *fp = fopen(m->path, "wb");
                                if (fp) {
                                    fwrite(bytes, 1, md->size, fp);
                                    fclose(fp);
                                }
                            } else {
                                m->path[0] = '\0';
                            }
                        } else if (tlv->type == XNIFF_TLV_OOL_PORTS) {
                            xniff_ool_ports_t *md = (xniff_ool_ports_t *)val;
                            m->index = md->index;
                            m->address = md->address;
                            m->count = md->count;
                            m->elem_size = md->elem_size;
                            size_t bytes_len = (size_t)md->count * (size_t)md->elem_size;
                            m->size_bytes = (uint32_t)bytes_len;
                            if (g_listener_opts.dump_files) {
                                snprintf(m->path, sizeof(m->path), "%s_ool_ports%u.bin", prefix, md->index);
                                const uint8_t *bytes = val + sizeof(*md);
                                FILE *fp = fopen(m->path, "wb");
                                if (fp) {
                                    fwrite(bytes, 1, bytes_len, fp);
                                    fclose(fp);
                                }
                            } else {
                                m->path[0] = '\0';
                            }
                        }
                    }
                    offset += tlv->length;
                }

                if (g_listener_opts.jsonl) {
                    char tbuf[64];
                    double mono_s = 0.0;
                    format_time(tbuf, sizeof(tbuf), &mono_s);
                    jsonl_print_event(cur_evt_id, call_id, entry_evt_id, &hdr, pl, msg_bytes, msg_len,
                                      tbuf, mono_s, msg_path, atts, att_count);
                } else {
                    print_event(hdr.kind, pl, msg_bytes, msg_len);
                }

                if (atts) free(atts);
                evt_idx++;
            }
            if (buf) free(buf);
            memmove(stream, stream + frame_len, stream_len - frame_len);
            stream_len -= frame_len;
        }
        usleep(10 * 1000);
    }
    // unreachable
    return 0;
}

static int cmd_hook_xpc(pid_t pid, const char *dylib_path, int mode) {
    mach_port_t task;
    if (attach_and_get_task(pid, &task) != 0) return -1;
    (void)mode;

    // Resolve absolute path so dlopen() in the remote process finds the library
    char abs_path[PATH_MAX] = {0};
    if (!realpath(dylib_path, abs_path)) {
        perror("realpath");
        detach_process(pid);
        return -1;
    }

    char inject_path[PATH_MAX] = {0};
    if (stage_dylib_for_sandbox(abs_path, inject_path, sizeof(inject_path)) == 0) {
        XNIFF_DIAGF("hook-xpc: staged hooks dylib at %s (from %s)\n", inject_path, abs_path);
    } else {
        (void)strncpy(inject_path, abs_path, sizeof(inject_path) - 1);
        inject_path[sizeof(inject_path) - 1] = '\0';
        XNIFF_DIAGF("hook-xpc: warning: failed to stage hooks dylib; using original path %s\n", abs_path);
    }

    // Inject hooks dylib (uses filtered dlopen/pthread_exit resolution)
    (void)xniff_dump_task_images(task);
    if (xniff_inject_dylib_task(task, inject_path, NULL) != 0) {
        fprintf(stderr, "failed to inject hooks dylib into pid %d\n", pid);
        detach_process(pid);
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
    detach_process(pid);
    XNIFF_DIAGF("hook-xpc: injected %s; xniff-hooks installs interceptors via frida-gum\n", inject_path);
    return 0;
}

static int spawn_suspended_target(char *const launch_argv[], pid_t *out_pid) {
    if (!launch_argv || !launch_argv[0] || !out_pid) {
        errno = EINVAL;
        return -1;
    }
#ifdef POSIX_SPAWN_START_SUSPENDED
    posix_spawnattr_t attr;
    int src = posix_spawnattr_init(&attr);
    if (src != 0) {
        errno = src;
        return -1;
    }
    short flags = POSIX_SPAWN_START_SUSPENDED;
    src = posix_spawnattr_setflags(&attr, flags);
    if (src != 0) {
        errno = src;
        (void)posix_spawnattr_destroy(&attr);
        return -1;
    }

    pid_t pid = 0;
    src = posix_spawnp(&pid, launch_argv[0], NULL, &attr, launch_argv, environ);
    (void)posix_spawnattr_destroy(&attr);
    if (src != 0) {
        errno = src;
        return -1;
    }
    *out_pid = pid;
    return 0;
#else
    (void)launch_argv;
    (void)out_pid;
    errno = ENOTSUP;
    return -1;
#endif
}

static const char *xniff_basename(const char *path) {
    if (!path) return NULL;
    const char *slash = strrchr(path, '/');
    return slash ? (slash + 1) : path;
}

static int find_process_by_name_once(const char *target_name, pid_t *out_pid) {
    if (!target_name || !*target_name || !out_pid) return -1;

    int bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (bytes <= 0) return -1;
    size_t count = (size_t)bytes / sizeof(pid_t);
    pid_t *pids = (pid_t *)calloc(count ? count : 1, sizeof(pid_t));
    if (!pids) return -1;

    int got = proc_listpids(PROC_ALL_PIDS, 0, pids, (int)(count * sizeof(pid_t)));
    if (got <= 0) {
        free(pids);
        return -1;
    }
    size_t got_count = (size_t)got / sizeof(pid_t);

    pid_t self = getpid();
    pid_t best_pid = 0;
    for (size_t i = 0; i < got_count; i++) {
        pid_t pid = pids[i];
        if (pid <= 0 || pid == self) continue;

        bool matched = false;

        char name_buf[PROC_PIDPATHINFO_MAXSIZE];
        int n = proc_name(pid, name_buf, sizeof(name_buf));
        if (n > 0) {
            size_t nn = (size_t)n;
            if (nn >= sizeof(name_buf)) nn = sizeof(name_buf) - 1;
            name_buf[nn] = '\0';
            if (strcmp(name_buf, target_name) == 0) matched = true;
        }

        char path_buf[PROC_PIDPATHINFO_MAXSIZE];
        if (!matched) {
            int pn = proc_pidpath(pid, path_buf, sizeof(path_buf));
            if (pn > 0) {
                size_t pnn = (size_t)pn;
                if (pnn >= sizeof(path_buf)) pnn = sizeof(path_buf) - 1;
                path_buf[pnn] = '\0';
                if (strcmp(path_buf, target_name) == 0) {
                    matched = true;
                } else {
                    const char *base = xniff_basename(path_buf);
                    if (base && strcmp(base, target_name) == 0) matched = true;
                }
            }
        }

        if (matched && pid > best_pid) {
            // Prefer the newest matching pid.
            best_pid = pid;
        }
    }

    free(pids);
    if (best_pid > 0) {
        *out_pid = best_pid;
        return 0;
    }
    return 1;
}

static int wait_for_process_name(const char *target_name, pid_t *out_pid) {
    if (!target_name || !*target_name || !out_pid) return -1;
    for (;;) {
        pid_t pid = 0;
        int rc = find_process_by_name_once(target_name, &pid);
        if (rc == 0) {
            *out_pid = pid;
            return 0;
        }
        usleep(50 * 1000);
    }
}

// Combined workflow: start listener, then inject hooks.
static int cmd_sniff_xpc_impl(pid_t pid,
                              const char *dylib_path,
                              int mode,
                              bool resume_target,
                              bool target_is_child) {
    const char *flow = resume_target ? "sniff-xpc-launch" : "sniff-xpc";
    pid_t child = fork();
    if (child == 0) {
        int rc = cmd_listen(pid);
        _exit(rc == 0 ? 0 : 1);
    }
    if (child < 0) {
        perror("fork");
        return -1;
    }
    if (g_listener_opts.jsonl) {
        // Keep JSONL on stdout clean: route parent stdout to stderr.
        (void)dup2(STDERR_FILENO, STDOUT_FILENO);
    }

    // Wait for listener process startup. If it exits early, do not inject.
    bool listener_ready = false;
    for (int i = 0; i < 20; i++) { // ~1s
        if (kill(child, 0) != 0 && errno == ESRCH) {
            break;
        }
        listener_ready = true;
        usleep(50 * 1000);
    }
    if (!listener_ready) {
        fprintf(stderr, "%s: listener failed to start for pid %d\n", flow, (int)pid);
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        return -1;
    }

    int rc = cmd_hook_xpc(pid, dylib_path, mode);
    if (rc != 0) {
        fprintf(stderr, "%s: hook-xpc failed; terminating listener (pid %d)\n", flow, (int)child);
        kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        return -1;
    }

    if (resume_target) {
        if (kill(pid, SIGCONT) != 0) {
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
            if (WIFEXITED(status)) {
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

int cmd_sniff_xpc(pid_t pid, const char *dylib_path, int mode) {
    return cmd_sniff_xpc_impl(pid, dylib_path, mode, false, false);
}

static int cmd_sniff_xpc_launch(const char *dylib_path, int mode, char *const launch_argv[]) {
    pid_t pid = 0;
    if (spawn_suspended_target(launch_argv, &pid) != 0) {
        fprintf(stderr, "sniff-xpc-launch: failed to spawn suspended target '%s': %s\n",
                launch_argv && launch_argv[0] ? launch_argv[0] : "(null)", strerror(errno));
        return -1;
    }

    XNIFF_DIAGF("sniff-xpc-launch: spawned suspended pid %d (%s)\n", (int)pid, launch_argv[0]);
    int rc = cmd_sniff_xpc_impl(pid, dylib_path, mode, true, true);
    if (rc != 0) {
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
    }
    return rc;
}

static int cmd_sniff_xpc_wait(const char *process_name, const char *dylib_path, int mode) {
    pid_t pid = 0;
    XNIFF_DIAGF("sniff-xpc-wait: waiting for process '%s'\n", process_name);
    if (wait_for_process_name(process_name, &pid) != 0) {
        fprintf(stderr, "sniff-xpc-wait: failed waiting for process '%s'\n", process_name);
        return -1;
    }

    XNIFF_DIAGF("sniff-xpc-wait: found pid %d for '%s'; stopping target\n", (int)pid, process_name);
    if (kill(pid, SIGSTOP) != 0) {
        fprintf(stderr, "sniff-xpc-wait: failed to stop pid %d: %s\n", (int)pid, strerror(errno));
        return -1;
    }

    int rc = cmd_sniff_xpc_impl(pid, dylib_path, mode, true, false);
    if (rc != 0) {
        // Avoid leaving a process suspended on failure paths.
        (void)kill(pid, SIGCONT);
    }
    return rc;
}
