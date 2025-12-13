// xniff-cli: attach to a target process, find symbols, and patch
// a function with a trampoline that calls our hook.

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
#include <unistd.h>
#include <limits.h>

#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach/mach_vm.h>
#include <mach/message.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "../shared/xniff_ipc.h"
#include "../shared/mach_private.h"

#include <xniff/patch.h>
#include <xniff/macho.h>
#include <xniff/inject.h>

// New combined workflow command
#include "sniff_xpc_cmd.h"
// XPC wire parser (shared library)
#include "../xpcdesert/xpcdesert.h"

typedef struct {
    bool jsonl;
    bool dump_files;
    bool parse_xpc;
    size_t hex_preview_len;
} listener_opts_t;

static listener_opts_t g_listener_opts = {
    .jsonl = false,
    .dump_files = true,
    .parse_xpc = true,
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
        if (strcmp(a, "--jsonl") == 0 || strcmp(a, "--format=jsonl") == 0) {
            opts->jsonl = true;
        } else if (strcmp(a, "--text") == 0 || strcmp(a, "--format=text") == 0) {
            opts->jsonl = false;
        } else if (strcmp(a, "--no-dump") == 0) {
            opts->dump_files = false;
        } else if (strcmp(a, "--no-xpc") == 0) {
            opts->parse_xpc = false;
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

static int patch_symbol_in_task(pid_t pid, const char *symbol_name) {
    mach_port_t task;
    if (attach_and_get_task(pid, &task) != 0) return -1;

    bool did_suspend = false;
    kern_return_t kr_suspend = task_suspend(task);
    if (kr_suspend == KERN_SUCCESS) {
        did_suspend = true;
    } else {
        fprintf(stderr, "warning: task_suspend failed (%d); proceeding without suspend\n", kr_suspend);
    }

    // Find our hook symbol via library helper (main image only to avoid global scans).
    mach_vm_address_t hook_addr = 0;
    if (xniff_find_symbol_in_main_image(task, "_xniff_remote_hook", &hook_addr) != 0 &&
        xniff_find_symbol_in_main_image(task, "xniff_remote_hook", &hook_addr) != 0) {
        fprintf(stderr, "hook symbol _xniff_remote_hook not found in main image; inject hooks or provide a different hook.\n");
        if (did_suspend) task_resume(task);
        detach_process(pid);
        return -1;
    }

    // Find target symbol in libsystem_kernel to avoid global scan
    mach_vm_address_t target_addr = 0;
    if (xniff_find_symbol_in_image_path_contains(task, "libsystem_kernel", symbol_name, &target_addr) != 0) {
        fprintf(stderr, "could not locate %s in target\n", symbol_name);
        if (did_suspend) task_resume(task);
        detach_process(pid);
        return -1;
    }

    XNIFF_DIAGF("found hook at 0x%llx, target %s at 0x%llx\n",
           (unsigned long long)hook_addr, symbol_name, (unsigned long long)target_addr);

    trampoline_bank_t bank;
    // Extended (entry+exit) trampoline is larger; request a bigger per-slot size.
    // 512 bytes comfortably covers copied prologue + extended tail.
    if (trampoline_bank_init_task(&bank, task, 8, 512) != 0) {
        fprintf(stderr, "failed to init remote trampoline bank\n");
        if (did_suspend) task_resume(task); detach_process(pid); return -1;
    }

    size_t idx = 0;
    if (trampoline_bank_install_task(&bank, target_addr, hook_addr, &idx) != 0) {
        fprintf(stderr, "failed to install remote trampoline\n");
    // Keep remote trampoline memory alive after installation so the patched
    // function can continue to branch to it without crashing.
    if (bank.is_remote) {
        if (bank.infos) free(bank.infos);
        memset(&bank, 0, sizeof(bank));
    } else {
        trampoline_bank_deinit(&bank);
    }
        if (did_suspend) task_resume(task); detach_process(pid); return -1;
    }
    XNIFF_DIAGF("installed remote trampoline at slot %zu\n", idx);
    // Provide helpful addresses for debugging in LLDB
    if (idx < bank.capacity) {
        trampoline_info_t *info = &bank.infos[idx];
        uint64_t resume_addr = (uint64_t)target_addr + (uint64_t)info->prologue_bytes;
        uint64_t tramp_base = (uint64_t)(uintptr_t)info->trampoline;
        uint64_t stub_entry = tramp_base + (uint64_t)XNIFF_TRAMPOLINE_PRELUDE_BYTES + (uint64_t)info->prologue_bytes;
        uint64_t after_restore_off = (uint64_t)(uintptr_t)(TRAMPOLINE_AFTER_RESTORE - TRAMPOLINE_START_AFTER_PROLOGUE);
        uint64_t stub_after_restore = stub_entry + after_restore_off;
        XNIFF_DIAGF("  trampoline slot @ 0x%llx, resume @ 0x%llx, hook @ 0x%llx\n",
               (unsigned long long)tramp_base,
               (unsigned long long)resume_addr,
               (unsigned long long)hook_addr);
        XNIFF_DIAGF("  stub entry(after stolen) @ 0x%llx, stub after_restore @ 0x%llx\n",
               (unsigned long long)stub_entry,
               (unsigned long long)stub_after_restore);
        XNIFF_DIAGF("  lldb: command script import lldb/xniff_regcheck.py ; xniff-regcheck --entry 0x%llx --exit 0x%llx --once --stop-on-mismatch\n",
               (unsigned long long)stub_entry,
               (unsigned long long)stub_after_restore);
        XNIFF_DIAGF("  debug: set XNIFF_TRAMP_BRK=1 when running xniff-cli to write a BRK at stub entry\n");
    }

    // Keep remote trampoline mapping alive; free local bookkeeping only.
    if (bank.is_remote) {
        if (bank.infos) free(bank.infos);
        memset(&bank, 0, sizeof(bank));
    } else {
        trampoline_bank_deinit(&bank);
    }
    // Detach and let process run
    if (did_suspend) task_resume(task);
    detach_process(pid);
    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s <pid> [symbol]              Patch a function entry with trampoline.\n", prog);
    fprintf(stderr, "  %s hook-exit <pid> [symbol] [entry_hook] [exit_hook]\n", prog);
    fprintf(stderr, "  %s hook-xpc <pid> <hooks.dylib>  Inject hooks and patch mach_msg_overwrite + mach_msg2_internal.\n", prog);
    fprintf(stderr, "  %s listen <pid> [flags]          Listen for events from target via Unix socket.\n", prog);
    fprintf(stderr, "  %s sniff-xpc <pid> <hooks.dylib> [flags] Start listener, inject hooks, and patch automatically.\n", prog);
    fprintf(stderr, "\nNotes:\n");
    fprintf(stderr, "- For patching: if [symbol] is omitted, defaults to _mach_msg_overwrite.\n");
    fprintf(stderr, "- Provide Mach-O symbol (with or without leading underscore).\n");
    fprintf(stderr, "\nListen flags:\n");
    fprintf(stderr, "  --jsonl           Emit JSON Lines (one event per line)\n");
    fprintf(stderr, "  --text            Human-readable output (default)\n");
    fprintf(stderr, "  --no-dump         Do not write /tmp/xniff/<pid>/* files\n");
    fprintf(stderr, "  --no-xpc          Disable XPC payload parsing/formatting\n");
}

// Forward declare subcommand implementation
static int cmd_hook_exit(pid_t pid, const char *symbol_name, const char *entry_sym, const char *exit_sym);
static int cmd_hook_xpc(pid_t pid, const char *dylib_path);
static int cmd_listen(pid_t pid);

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
        int prc = parse_listener_flags(&g_listener_opts, argc, argv, 4);
        if (prc != 0) { usage(argv[0]); return prc > 0 ? 0 : 2; }
        int rc = cmd_sniff_xpc(pid, path);
        return (rc == 0) ? 0 : 1;
    }

    // Subcommand: hook-exit <pid> [symbol] [entry_hook] [exit_hook]
    if (strcmp(argv[1], "hook-exit") == 0) {
        if (argc < 3 || argc > 6) { usage(argv[0]); return 2; }
        pid_t pid = (pid_t)strtol(argv[2], NULL, 10);
        if (pid <= 0) { usage(argv[0]); return 2; }
        char symbuf[256] = {0};
        const char *user_sym = (argc >= 4) ? argv[3] : "_mach_msg_overwrite";
        if (user_sym[0] == '_') strncpy(symbuf, user_sym, sizeof(symbuf)-1);
        else { symbuf[0] = '_'; strncat(symbuf, user_sym, sizeof(symbuf)-2); }
        const char *entry_sym = (argc >= 5) ? argv[4] : NULL;
        const char *exit_sym  = (argc >= 6) ? argv[5] : NULL;
        int rc = cmd_hook_exit(pid, symbuf, entry_sym, exit_sym);
        return (rc == 0) ? 0 : 1;
    }

    // Subcommand: hook-xpc <pid> <hooks.dylib>
    if (strcmp(argv[1], "hook-xpc") == 0) {
        if (argc != 4) { usage(argv[0]); return 2; }
        pid_t pid = (pid_t)strtol(argv[2], NULL, 10);
        if (pid <= 0) { usage(argv[0]); return 2; }
        const char *path = argv[3];
        int rc = cmd_hook_xpc(pid, path);
        return (rc == 0) ? 0 : 1;
    }

    // Default mode: patch a symbol
    if (argc < 2 || argc > 3) { usage(argv[0]); return 2; }
    pid_t pid = (pid_t)strtol(argv[1], NULL, 10);
    if (pid <= 0) { usage(argv[0]); return 2; }

    char symbuf[256] = {0};
    const char *user_sym = (argc == 3) ? argv[2] : "_mach_msg_overwrite";
    if (user_sym[0] == '_') {
        strncpy(symbuf, user_sym, sizeof(symbuf) - 1);
    } else {
        symbuf[0] = '_';
        strncat(symbuf, user_sym, sizeof(symbuf) - 2);
    }

    int rc = patch_symbol_in_task(pid, symbuf);
    return (rc == 0) ? 0 : 1;
}
static int cmd_hook_exit(pid_t pid, const char *symbol_name, const char *entry_sym, const char *exit_sym) {
    mach_port_t task;
    if (attach_and_get_task(pid, &task) != 0) return -1;

    bool did_suspend = false;
    kern_return_t kr_suspend = task_suspend(task);
    if (kr_suspend == KERN_SUCCESS) did_suspend = true;

    mach_vm_address_t entry_hook = 0;
    mach_vm_address_t exit_hook  = 0;
    char entry_name[256] = {0};
    char exit_name[256]  = {0};
    const char *default_entry = "_xniff_remote_entry_hook";
    const char *default_exit  = "_xniff_remote_exit_hook";
    const char *en = entry_sym ? entry_sym : default_entry;
    const char *ex = exit_sym  ? exit_sym  : default_exit;
    if (en[0] == '_') strncpy(entry_name, en, sizeof(entry_name)-1);
    else { entry_name[0] = '_'; strncat(entry_name, en, sizeof(entry_name)-2); }
    if (ex[0] == '_') strncpy(exit_name, ex, sizeof(exit_name)-1);
    else { exit_name[0] = '_'; strncat(exit_name, ex, sizeof(exit_name)-2); }
    if (xniff_find_symbol_in_main_image(task, entry_name, &entry_hook) != 0 &&
        xniff_find_symbol_in_main_image(task, "_xniff_remote_hook", &entry_hook) != 0 &&
        xniff_find_symbol_in_main_image(task, "xniff_remote_hook", &entry_hook) != 0) {
        fprintf(stderr, "error: entry hook %s not found in main image; avoid global scan by injecting a dylib first.\n", entry_name);
        if (did_suspend) task_resume(task);
        detach_process(pid);
        return -1;
    }
    if (xniff_find_symbol_in_main_image(task, exit_name, &exit_hook) != 0) {
        fprintf(stderr, "warning: exit hook %s not found in main image; proceeding with no-op exit hook\n", exit_name);
        exit_hook = 0;
    }

    // Locate target symbol
    mach_vm_address_t target_addr = 0;
    if (xniff_find_symbol_in_image_path_contains(task, "libsystem_kernel", symbol_name, &target_addr) != 0) {
        fprintf(stderr, "could not locate %s in target\n", symbol_name);
        if (did_suspend) task_resume(task);
        detach_process(pid);
        return -1;
    }

    XNIFF_DIAGF("found target %s at 0x%llx, entry_hook 0x%llx, exit_hook 0x%llx\n",
           symbol_name, (unsigned long long)target_addr,
           (unsigned long long)entry_hook, (unsigned long long)exit_hook);

    trampoline_bank_t bank;
    // Extended trampoline requires a larger per-slot size; use 512 bytes per trampoline slot.
    if (trampoline_bank_init_task(&bank, task, 8, 512) != 0) {
        fprintf(stderr, "failed to init remote trampoline bank\n");
        if (did_suspend) task_resume(task); detach_process(pid); return -1;
    }

    size_t idx = 0;
    // exit_hook_function = 0 => no-op
    if (trampoline_bank_install_task_with_exit(&bank, target_addr, entry_hook, exit_hook, &idx) != 0) {
        fprintf(stderr, "failed to install entry+exit trampoline\n");
        if (bank.is_remote) { if (bank.infos) free(bank.infos); memset(&bank, 0, sizeof(bank)); }
        if (did_suspend) task_resume(task); detach_process(pid); return -1;
    }
    XNIFF_DIAGF("installed entry+exit trampoline at slot %zu\n", idx);
    if (idx < bank.capacity) {
        trampoline_info_t *info = &bank.infos[idx];
        uint64_t resume_addr = (uint64_t)target_addr + (uint64_t)info->prologue_bytes;
        // Compute exit stub address to help set LLDB breakpoints
        size_t ex_off = (size_t)(XTRAMP_EXIT_STUB - XTRAMP_START_AFTER_PROLOGUE);
        uint64_t exit_stub_addr = (uint64_t)(uintptr_t)info->trampoline + (uint64_t)info->prologue_bytes + (uint64_t)ex_off;
        XNIFF_DIAGF("  trampoline slot @ 0x%llx, resume @ 0x%llx, exit_stub @ 0x%llx\n",
               (unsigned long long)(uintptr_t)info->trampoline,
               (unsigned long long)resume_addr,
               (unsigned long long)exit_stub_addr);
        if (info->ctx_base) {
            XNIFF_DIAGF("  ctx_base @ 0x%llx size %zu bytes\n",
                   (unsigned long long)(uintptr_t)info->ctx_base, info->ctx_size);
        }
    }

    if (bank.is_remote) { if (bank.infos) free(bank.infos); memset(&bank, 0, sizeof(bank)); }
    else { trampoline_bank_deinit(&bank); }

    if (did_suspend) task_resume(task);
    detach_process(pid);
    return 0;
}

static ssize_t read_fully(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = recv(fd, p, left, 0);
        if (n == 0) { errno = 0; return -1; } // EOF
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)n;
        left -= (size_t)n;
    }
    return (ssize_t)len;
}

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t kind;
    uint32_t pid;
    uint64_t tid;
    uint32_t payload_len;
} xniff_ipc_hdr_legacy24_t;

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(xniff_ipc_hdr_legacy24_t) == 24, "legacy header must be 24 bytes");
#endif

typedef enum {
    XNIFF_HDR_WIRE_V1_20 = 20,
    XNIFF_HDR_WIRE_LEGACY_24 = 24,
} xniff_hdr_wire_kind_t;

static bool payload_len_sane(uint32_t payload_len) {
    if (payload_len < sizeof(xniff_ipc_mach_payload_t)) return false;
    if (payload_len > (64u * 1024u * 1024u)) return false;
    return true;
}

static bool peek_u32(const uint8_t *buf, size_t len, size_t off, uint32_t *out) {
    if (!out) return false;
    if (off + sizeof(uint32_t) > len) return false;
    uint32_t v = 0;
    memcpy(&v, buf + off, sizeof(v));
    *out = v;
    return true;
}

static int read_ipc_header_compat(int fd, xniff_ipc_hdr_t *out_hdr, xniff_hdr_wire_kind_t *wire_kind_out) {
    if (!out_hdr) return -1;

    // Peek enough bytes to discriminate between the current 20-byte header and a legacy 24-byte header.
    // Also validate the first u32 of the payload (api) to reduce false positives.
    uint8_t peek[64];
    ssize_t pn = -1;
    for (;;) {
        pn = recv(fd, peek, sizeof(peek), MSG_PEEK);
        if (pn < 0 && errno == EINTR) continue;
        break;
    }
    if (pn == 0) { errno = 0; return -1; } // EOF
    if (pn < 0) return -1;

    size_t avail = (size_t)pn;
    if (avail < sizeof(xniff_ipc_hdr_t)) {
        if (read_fully(fd, out_hdr, sizeof(*out_hdr)) != (ssize_t)sizeof(*out_hdr)) return -1;
        if (wire_kind_out) *wire_kind_out = XNIFF_HDR_WIRE_V1_20;
        return 0;
    }

    xniff_ipc_hdr_t h1;
    memcpy(&h1, peek, sizeof(h1));

    bool h1_ok = (h1.magic == XNIFF_IPC_MAGIC) &&
                 (h1.version == XNIFF_IPC_VERSION) &&
                 payload_len_sane(h1.payload_len);
    if (h1_ok && avail >= sizeof(xniff_ipc_hdr_t) + sizeof(uint32_t)) {
        uint32_t api = 0;
        if (peek_u32(peek, avail, sizeof(xniff_ipc_hdr_t), &api)) {
            if (api != XNIFF_API_MACH_MSG && api != XNIFF_API_MACH_MSG2) h1_ok = false;
        }
    }

    bool h0_ok = false;
    xniff_ipc_hdr_legacy24_t h0;
    if (avail >= sizeof(h0) + sizeof(uint32_t)) {
        memcpy(&h0, peek, sizeof(h0));
        h0_ok = (h0.magic == XNIFF_IPC_MAGIC) &&
                (h0.version == XNIFF_IPC_VERSION) &&
                payload_len_sane(h0.payload_len);
        if (h0_ok) {
            uint32_t api = 0;
            if (peek_u32(peek, avail, sizeof(h0), &api)) {
                if (api != XNIFF_API_MACH_MSG && api != XNIFF_API_MACH_MSG2) h0_ok = false;
            }
        }
    }

    // Prefer the current header when both validate; otherwise accept legacy if it validates.
    if (h1_ok) {
        if (read_fully(fd, out_hdr, sizeof(*out_hdr)) != (ssize_t)sizeof(*out_hdr)) return -1;
        if (wire_kind_out) *wire_kind_out = XNIFF_HDR_WIRE_V1_20;
        return 0;
    }
    if (h0_ok) {
        uint8_t tmp[sizeof(h0)];
        if (read_fully(fd, tmp, sizeof(tmp)) != (ssize_t)sizeof(tmp)) return -1;
        memcpy(&h0, tmp, sizeof(h0));
        out_hdr->magic = h0.magic;
        out_hdr->version = h0.version;
        out_hdr->kind = h0.kind;
        out_hdr->pid = h0.pid;
        out_hdr->tid_low = (uint32_t)h0.tid;
        out_hdr->payload_len = h0.payload_len;
        if (wire_kind_out) *wire_kind_out = XNIFF_HDR_WIRE_LEGACY_24;
        return 0;
    }

    // Unknown framing; fall back to consuming the v1-sized header so the caller can emit diagnostics.
    if (read_fully(fd, out_hdr, sizeof(*out_hdr)) != (ssize_t)sizeof(*out_hdr)) return -1;
    if (wire_kind_out) *wire_kind_out = XNIFF_HDR_WIRE_V1_20;
    return 0;
}

static void diag_dump_header(const char *why, const xniff_ipc_hdr_t *hdr) {
    if (!hdr) return;
    const uint8_t *b = (const uint8_t *)hdr;
    char hex[sizeof(*hdr) * 2 + 1];
    for (size_t i = 0; i < sizeof(*hdr); i++) snprintf(&hex[i * 2], 3, "%02x", b[i]);
    XNIFF_DIAGF("%s: raw_hdr=%s\n", why ? why : "header", hex);
    XNIFF_DIAGF("%s: magic=0x%08x (want 0x%08x) ver=%u (want %u) kind=%u pid=%u tid_low=%u payload_len=%u\n",
                why ? why : "header",
                hdr->magic, XNIFF_IPC_MAGIC,
                (unsigned)hdr->version, (unsigned)XNIFF_IPC_VERSION,
                (unsigned)hdr->kind, hdr->pid, hdr->tid_low, hdr->payload_len);
}

static void diag_disconnect(const char *where) {
    int e = errno;
    if (e == 0) {
        XNIFF_DIAGF("%s: client disconnected (EOF)\n", where ? where : "listen");
    } else {
        XNIFF_DIAGF("%s: client disconnected (errno=%d: %s)\n", where ? where : "listen", e, strerror(e));
    }
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
    }
    return "unknown";
}

typedef struct pending_call {
    uint32_t pid;
    uint32_t tid_low;
    uint32_t api;
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

static void pending_calls_drop_one(uint32_t pid, uint32_t tid_low, uint32_t api) {
    pending_call_t **pp = &g_pending_calls;
    while (*pp) {
        pending_call_t *c = *pp;
        if (c->pid == pid && c->tid_low == tid_low && c->api == api) {
            *pp = c->next;
            free(c);
            return;
        }
        pp = &c->next;
    }
}

static uint64_t pending_calls_push(uint32_t pid, uint32_t tid_low, uint32_t api, unsigned long long entry_event_id) {
    pending_calls_drop_one(pid, tid_low, api); // avoid unbounded growth if an exit event is dropped
    pending_call_t *c = (pending_call_t *)calloc(1, sizeof(*c));
    if (!c) return 0;
    c->pid = pid;
    c->tid_low = tid_low;
    c->api = api;
    c->call_id = g_next_call_id++;
    if (c->call_id == 0) c->call_id = g_next_call_id++;
    c->entry_event_id = entry_event_id;
    c->next = g_pending_calls;
    g_pending_calls = c;
    return c->call_id;
}

static bool pending_calls_pop(uint32_t pid, uint32_t tid_low, uint32_t api, uint64_t *call_id_out, unsigned long long *entry_event_id_out) {
    pending_call_t **pp = &g_pending_calls;
    while (*pp) {
        pending_call_t *c = *pp;
        if (c->pid == pid && c->tid_low == tid_low && c->api == api) {
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
    unsigned opt32 = pl->option_lo;
    unsigned opt_hi = pl->option_hi;
    unsigned bits = hdr ? (unsigned)hdr->msgh_bits : 0;
    mach_port_t remote = hdr ? hdr->msgh_remote_port : MACH_PORT_NULL;
    mach_port_t local  = hdr ? hdr->msgh_local_port  : MACH_PORT_NULL;
    printf("[%s][+%0.6fs] %s: api=%u dir=%u id=%d size=%u copy=%u bits=0x%08x addr=0x%llx opt=0x%08x%08x ret=0x%llx desc=%u prio=%u timeout=%llu remote=0x%08x local=0x%08x\n",
           tbuf, mono_s, kstr,
           pl->api, pl->direction,
           hdr ? hdr->msgh_id : -1,
           pl->msgh_size, pl->copy_len,
           bits,
           (unsigned long long)pl->msg_addr,
           opt_hi, opt32,
           (unsigned long long)pl->ret_value,
           pl->desc_count, pl->priority, (unsigned long long)pl->timeout,
           remote, local);

    // Optionally, print a short hexdump of the first 64 bytes of the message
    size_t dump_len = msg_len < g_listener_opts.hex_preview_len ? msg_len : g_listener_opts.hex_preview_len;
    if (hdr && dump_len) {
        const uint8_t *p = (const uint8_t *)hdr;
        printf("  msg[%zu]: ", dump_len);
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

static int cmd_listen(pid_t pid) {
    int sfd = xniff_ipc_server_listen(pid);
    if (sfd < 0) { perror("listen"); return -1; }
    char path[108]; xniff_ipc_path_for_pid(pid, path, sizeof(path));
    XNIFF_DIAGF("listening on %s...\n", path);

    // Prepare dump directory for this pid
    char base_dir[256];
    snprintf(base_dir, sizeof(base_dir), "/tmp/xniff/%d", (int)pid);
    if (g_listener_opts.dump_files) {
        mkdir("/tmp/xniff", 0755);
        mkdir(base_dir, 0755);
    }
    unsigned long long evt_idx = 0;

    for (;;) {
        int cfd = xniff_ipc_accept(sfd);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); return -1; }
        XNIFF_DIAGF("client connected\n");
        bool warned_legacy_hdr = false;
        for (;;) {
            xniff_ipc_hdr_t hdr;
            xniff_hdr_wire_kind_t wire_kind = XNIFF_HDR_WIRE_V1_20;
            if (read_ipc_header_compat(cfd, &hdr, &wire_kind) != 0) {
                diag_disconnect("read header");
                close(cfd);
                pending_calls_clear_pid((uint32_t)pid);
                break;
            }
            if (wire_kind == XNIFF_HDR_WIRE_LEGACY_24 && !warned_legacy_hdr) {
                warned_legacy_hdr = true;
                XNIFF_DIAGF("note: detected legacy 24-byte IPC header (tid64). Your injected xniff-hooks is older/different; rebuild and reinject to use the current 20-byte header.\n");
            }
            if (hdr.magic != XNIFF_IPC_MAGIC || hdr.version != XNIFF_IPC_VERSION) {
                diag_dump_header("bad header/magic", &hdr);
                XNIFF_DIAGF("bad header/magic: this is often caused by interleaved writes from multiple hook threads; ensure you’re using the updated xniff-hooks.\n");
                close(cfd);
                pending_calls_clear_pid((uint32_t)pid);
                break;
            }
            if (hdr.payload_len < sizeof(xniff_ipc_mach_payload_t)) { fprintf(stderr, "short payload len %u\n", hdr.payload_len); close(cfd); break; }
            if (hdr.payload_len > (64u * 1024u * 1024u)) {
                // Compatibility: some older/mismatched hook builds appear to scribble the upper 16 bits of
                // payload_len (often 0xAAAAxxxx). If the low 16 bits look sane and the payload begins with
                // a valid api field, salvage the length instead of hard-failing.
                uint32_t hi = hdr.payload_len & 0xFFFF0000u;
                uint32_t lo = hdr.payload_len & 0x0000FFFFu;
                bool salvaged = false;
                if ((hi == 0xAAAA0000u || hi == 0x55550000u) && payload_len_sane(lo)) {
                    uint32_t api = 0;
                    ssize_t pk;
                    do {
                        pk = recv(cfd, &api, sizeof(api), MSG_PEEK | MSG_WAITALL);
                    } while (pk < 0 && errno == EINTR);
                    if (pk == (ssize_t)sizeof(api) && (api == XNIFF_API_MACH_MSG || api == XNIFF_API_MACH_MSG2)) {
                        XNIFF_DIAGF("warning: salvaging scribbled payload_len 0x%08x -> %u (likely old/mismatched xniff-hooks)\n",
                                    hdr.payload_len, lo);
                        hdr.payload_len = lo;
                        salvaged = true;
                    }
                }
                if (!salvaged) {
                    diag_dump_header("insane payload_len", &hdr);
                    close(cfd);
                    pending_calls_clear_pid((uint32_t)pid);
                    break;
                }
            }

            uint8_t *buf = (uint8_t *)malloc(hdr.payload_len);
            if (!buf) { fprintf(stderr, "oom %u\n", hdr.payload_len); close(cfd); break; }
            if (read_fully(cfd, buf, hdr.payload_len) != (ssize_t)hdr.payload_len) {
                diag_disconnect("read payload");
                free(buf);
                close(cfd);
                pending_calls_clear_pid((uint32_t)pid);
                break;
            }

            xniff_ipc_mach_payload_t *pl = (xniff_ipc_mach_payload_t *)buf;
            uint8_t *msg_bytes = buf + sizeof(*pl);
            size_t msg_avail = 0;
            if (hdr.payload_len > sizeof(*pl)) msg_avail = (size_t)hdr.payload_len - sizeof(*pl);
            size_t msg_len = pl->copy_len;
            if (msg_len > msg_avail) msg_len = msg_avail;

            unsigned long long cur_evt_id = evt_idx;
            uint64_t call_id = 0;
            unsigned long long entry_evt_id = 0;
            bool is_entry = (hdr.kind == XNIFF_EVT_MACH_ENTRY || hdr.kind == XNIFF_EVT_MACH2_ENTRY);
            bool is_exit  = (hdr.kind == XNIFF_EVT_MACH_EXIT  || hdr.kind == XNIFF_EVT_MACH2_EXIT);
            if (is_entry) {
                call_id = pending_calls_push(hdr.pid, hdr.tid_low, pl->api, cur_evt_id);
            } else if (is_exit) {
                (void)pending_calls_pop(hdr.pid, hdr.tid_low, pl->api, &call_id, &entry_evt_id);
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
                    if (fp) { fwrite(msg_bytes, 1, msg_len, fp); fclose(fp); msg_path = pmsg; }
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
                            if (fp) { fwrite(bytes, 1, md->size, fp); fclose(fp); }
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
                            if (fp) { fwrite(bytes, 1, bytes_len, fp); fclose(fp); }
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
                jsonl_print_event(cur_evt_id, call_id, entry_evt_id, &hdr, pl, msg_bytes, msg_len, tbuf, mono_s, msg_path, atts, att_count);
            } else {
                print_event(hdr.kind, pl, msg_bytes, msg_len);
            }

            if (atts) free(atts);

            evt_idx++;
            free(buf);
        }
    }
    return 0;
}

static int cmd_hook_xpc(pid_t pid, const char *dylib_path) {
    mach_port_t task;
    if (attach_and_get_task(pid, &task) != 0) return -1;

    bool did_suspend = false; // will suspend only around patching

    // Resolve absolute path so dlopen() in the remote process finds the library
    char abs_path[PATH_MAX] = {0};
    if (!realpath(dylib_path, abs_path)) {
        perror("realpath");
        if (did_suspend) task_resume(task);
        detach_process(pid);
        return -1;
    }

    // Inject hooks dylib (uses filtered dlopen/pthread_exit resolution)
    (void)xniff_dump_task_images(task);
    if (xniff_inject_dylib_task(task, abs_path, NULL) != 0) {
        fprintf(stderr, "failed to inject hooks dylib into pid %d\n", pid);
        if (did_suspend) task_resume(task);
        detach_process(pid);
        return -1;
    }
    // Wait for dyld to finish loading the injected image; poll for up to ~2s
    for (int i = 0; i < 40; i++) {
        mach_vm_address_t tmp = 0;
        // Try to resolve any one of our exported symbols to confirm load
        if (xniff_find_symbol_in_image_exact_path(task, abs_path, "_xniff_remote_entry_hook", &tmp) == 0 ||
            xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "_xniff_remote_entry_hook", &tmp) == 0 ||
            xniff_find_symbol_in_image_exact_path(task, abs_path, "xniff_remote_entry_hook", &tmp) == 0 ||
            xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "xniff_remote_entry_hook", &tmp) == 0) {
            break;
        }
        usleep(50 * 1000);
    }

    // Resolve hooks; prefer image-scoped lookups; print images again to show any changes.
    (void)xniff_dump_task_images(task);
    mach_vm_address_t entry_hook_v1 = 0, exit_hook_v1 = 0;
    mach_vm_address_t entry_hook_v2 = 0, exit_hook_v2 = 0;
    // Image-scoped only
    (void)xniff_find_symbol_in_image_exact_path(task, abs_path, "_xniff_remote_entry_hook", &entry_hook_v1);
    if (!entry_hook_v1) (void)xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "_xniff_remote_entry_hook", &entry_hook_v1);
    if (!entry_hook_v1) (void)xniff_find_symbol_in_image_exact_path(task, abs_path, "xniff_remote_entry_hook", &entry_hook_v1);
    if (!entry_hook_v1) (void)xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "xniff_remote_entry_hook", &entry_hook_v1);
    if (!entry_hook_v1) fprintf(stderr, "warning: can’t find xniff_remote_entry_hook; mach_msg* entry logs will be disabled\n");
    (void)xniff_find_symbol_in_image_exact_path(task, abs_path, "_xniff_remote_exit_hook", &exit_hook_v1);
    if (!exit_hook_v1) (void)xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "_xniff_remote_exit_hook", &exit_hook_v1);
    if (!exit_hook_v1) (void)xniff_find_symbol_in_image_exact_path(task, abs_path, "xniff_remote_exit_hook", &exit_hook_v1);
    if (!exit_hook_v1) (void)xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "xniff_remote_exit_hook", &exit_hook_v1);
    if (!exit_hook_v1) fprintf(stderr, "warning: can’t find xniff_remote_exit_hook; mach_msg* exit logs will be disabled\n");
    (void)xniff_find_symbol_in_image_exact_path(task, abs_path, "_xniff_msg2_entry_hook", &entry_hook_v2);
    if (!entry_hook_v2) (void)xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "_xniff_msg2_entry_hook", &entry_hook_v2);
    if (!entry_hook_v2) (void)xniff_find_symbol_in_image_exact_path(task, abs_path, "xniff_msg2_entry_hook", &entry_hook_v2);
    if (!entry_hook_v2) (void)xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "xniff_msg2_entry_hook", &entry_hook_v2);
    if (!entry_hook_v2) fprintf(stderr, "warning: can’t find xniff_msg2_entry_hook; mach_msg2 entry logs will be disabled\n");
    (void)xniff_find_symbol_in_image_exact_path(task, abs_path, "_xniff_msg2_exit_hook", &exit_hook_v2);
    if (!exit_hook_v2) (void)xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "_xniff_msg2_exit_hook", &exit_hook_v2);
    if (!exit_hook_v2) (void)xniff_find_symbol_in_image_exact_path(task, abs_path, "xniff_msg2_exit_hook", &exit_hook_v2);
    if (!exit_hook_v2) (void)xniff_find_symbol_in_image_path_contains(task, "xniff-hooks", "xniff_msg2_exit_hook", &exit_hook_v2);
    if (!exit_hook_v2) fprintf(stderr, "warning: can’t find xniff_msg2_exit_hook; mach_msg2 exit logs will be disabled\n");

    // Suspend before patching to avoid racing with live calls
    if (!did_suspend) {
        if (task_suspend(task) == KERN_SUCCESS) did_suspend = true;
        else fprintf(stderr, "warning: task_suspend failed; proceeding anyway\n");
    }

    trampoline_bank_t bank;
    if (trampoline_bank_init_task(&bank, task, 8, 512) != 0) {
        fprintf(stderr, "failed to init remote trampoline bank\n");
        if (did_suspend) task_resume(task);
        detach_process(pid);
        return -1;
    }

    // Candidate symbols to patch (resolve in libsystem_kernel only to reduce scanning)
    // Policy: hook mach_msg_overwrite for non-vector messages and mach_msg2_internal for vector.
    // No fallback to legacy _mach_msg or _mach_msg2.
    const char *candidates[] = { "_mach_msg_overwrite", "_mach_msg2_internal" };
    const int n = (int)(sizeof(candidates)/sizeof(candidates[0]));
    int patched = 0;
    for (int i = 0; i < n; i++) {
        mach_vm_address_t target = 0;
        if (xniff_find_symbol_in_image_path_contains(task, "libsystem_kernel", candidates[i], &target) != 0) continue;

        // Choose appropriate hook pair for each symbol
        mach_vm_address_t eh = entry_hook_v1;
        mach_vm_address_t xh = exit_hook_v1;
        if (strcmp(candidates[i], "_mach_msg2_internal") == 0) { eh = entry_hook_v2; xh = exit_hook_v2; }
        // If we cannot resolve the entry hook for this symbol, skip patching to avoid branching to 0
        if (eh == 0) {
            fprintf(stderr, "warning: skipping patch for %s because entry hook not resolved\n", candidates[i]);
            continue;
        }
        size_t idx = 0;
        int rc = trampoline_bank_install_task_with_exit(&bank, target, eh, xh, &idx);
        if (rc == 0) {
            patched++;
            if (idx < bank.capacity) {
                trampoline_info_t *info = &bank.infos[idx];
                uint64_t resume_addr = (uint64_t)target + (uint64_t)info->prologue_bytes;
                size_t ex_off = (size_t)(XTRAMP_EXIT_STUB - XTRAMP_START_AFTER_PROLOGUE);
                uint64_t exit_stub_addr = (uint64_t)(uintptr_t)info->trampoline + (uint64_t)info->prologue_bytes + (uint64_t)ex_off;
                XNIFF_DIAGF("patched %s: slot @ 0x%llx, resume @ 0x%llx, exit_stub @ 0x%llx\n",
                       candidates[i],
                       (unsigned long long)(uintptr_t)info->trampoline,
                       (unsigned long long)resume_addr,
                       (unsigned long long)exit_stub_addr);
            } else {
                XNIFF_DIAGF("patched %s\n", candidates[i]);
            }
        } else {
            fprintf(stderr, "failed to patch %s\n", candidates[i]);
        }
    }

    if (bank.is_remote) { if (bank.infos) free(bank.infos); memset(&bank, 0, sizeof(bank)); }
    else { trampoline_bank_deinit(&bank); }

    if (did_suspend) task_resume(task);
    detach_process(pid);
    XNIFF_DIAGF("patched %d symbols\n", patched);
    return patched > 0 ? 0 : -1;
}

// Combined workflow: start listener, then inject hooks and patch mach_msg*.
int cmd_sniff_xpc(pid_t pid, const char *dylib_path) {
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

    // Wait for listener socket to exist to minimize dropped early events
    char sock_path[108];
    if (xniff_ipc_path_for_pid(pid, sock_path, sizeof(sock_path)) == 0) {
        for (int i = 0; i < 50; i++) { // ~2.5s
            struct stat st;
            if (stat(sock_path, &st) == 0) break;
            usleep(50 * 1000);
        }
    }

    int rc = cmd_hook_xpc(pid, dylib_path);
    if (rc != 0) {
        fprintf(stderr, "sniff-xpc: hook-xpc failed; terminating listener (pid %d)\n", (int)child);
        kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        return -1;
    }

    XNIFF_DIAGF("sniff-xpc: hooks installed; streaming events (listener pid %d). Press Ctrl-C to stop.\n", (int)child);
    int status = 0;
    (void)waitpid(child, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status) == 0 ? 0 : -1;
    return -1;
}
