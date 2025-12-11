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

#include <xniff/patch.h>
#include <xniff/macho.h>
#include <xniff/inject.h>


static int attach_and_get_task(pid_t pid, mach_port_t *out_task) {
    // Attempt to get the task port first; if allowed, we can avoid ptrace.
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr == KERN_SUCCESS) {
        printf("got task port for pid %d without attach\n", pid);
        *out_task = task;
        return 0;
    }

    printf("attaching to pid %d\n", pid);
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
    printf("getting task port for pid %d\n", pid);
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

    printf("found hook at 0x%llx, target %s at 0x%llx\n",
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
    printf("installed remote trampoline at slot %zu\n", idx);
    // Provide helpful addresses for debugging in LLDB
    if (idx < bank.capacity) {
        trampoline_info_t *info = &bank.infos[idx];
        uint64_t resume_addr = (uint64_t)target_addr + (uint64_t)info->prologue_bytes;
        printf("  trampoline slot @ 0x%llx, resume @ 0x%llx, hook @ 0x%llx\n",
               (unsigned long long)(uintptr_t)info->trampoline,
               (unsigned long long)resume_addr,
               (unsigned long long)hook_addr);
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
    fprintf(stderr, "  %s load-rt <pid> <path>        Inject xniff-rt dylib via remote dlopen.\n", prog);
    fprintf(stderr, "  %s hook-exit <pid> [symbol] [entry_hook] [exit_hook]\n", prog);
    fprintf(stderr, "  %s hook-xpc <pid> <hooks.dylib>  Inject hooks and patch mach_msg[_overwrite|2].\n", prog);
    fprintf(stderr, "  %s listen <pid>                 Listen for events from target via Unix socket.\n", prog);
    fprintf(stderr, "\nNotes:\n");
    fprintf(stderr, "- For patching: if [symbol] is omitted, defaults to _mach_msg_overwrite.\n");
    fprintf(stderr, "- Provide Mach-O symbol (with or without leading underscore).\n");
    fprintf(stderr, "- For load-rt: <path> must be an absolute path to xniff-rt dylib.\n");
}

// Forward declare subcommand implementation
static int cmd_hook_exit(pid_t pid, const char *symbol_name, const char *entry_sym, const char *exit_sym);
static int cmd_hook_xpc(pid_t pid, const char *dylib_path);
static int cmd_listen(pid_t pid);

static int cmd_load_rt(pid_t pid, const char *dylib_path) {
    mach_port_t task;
    if (attach_and_get_task(pid, &task) != 0) return -1;
    bool did_suspend = false;
    // Resolve absolute path to the runtime dylib to ensure dlopen in the target can locate it
    char abs_path[PATH_MAX] = {0};
    if (!realpath(dylib_path, abs_path)) {
        perror("realpath");
        if (did_suspend) task_resume(task);
        detach_process(pid);
        return -1;
    }

    mach_vm_address_t addr_enter = 0, addr_exit = 0, addr_exit_hook = 0;
    // Do not suspend before injection; allow dlopen to run
    int rc = xniff_load_runtime_task(task, abs_path, &addr_enter, &addr_exit, &addr_exit_hook);
    if (rc == 0) {
        printf("xniff-rt injected. ctx_enter=0x%llx ctx_exit=0x%llx exit_hook=0x%llx\n",
               (unsigned long long)addr_enter,
               (unsigned long long)addr_exit,
               (unsigned long long)addr_exit_hook);
    } else {
        fprintf(stderr, "failed to inject runtime into pid %d\n", pid);
    }

    if (did_suspend) task_resume(task);
    detach_process(pid);
    return rc;
}


int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 2; }

    // Subcommand: load-rt <pid> <path>
    if (strcmp(argv[1], "load-rt") == 0) {
        if (argc != 4) { usage(argv[0]); return 2; }
        pid_t pid = (pid_t)strtol(argv[2], NULL, 10);
        if (pid <= 0) { usage(argv[0]); return 2; }
        const char *path = argv[3];
        int rc = cmd_load_rt(pid, path);
        return (rc == 0) ? 0 : 1;
    }

    // Subcommand: listen <pid>
    if (strcmp(argv[1], "listen") == 0) {
        if (argc != 3) { usage(argv[0]); return 2; }
        pid_t pid = (pid_t)strtol(argv[2], NULL, 10);
        if (pid <= 0) { usage(argv[0]); return 2; }
        int rc = cmd_listen(pid);
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

    printf("found target %s at 0x%llx, entry_hook 0x%llx, exit_hook 0x%llx\n",
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
    printf("installed entry+exit trampoline at slot %zu\n", idx);
    if (idx < bank.capacity) {
        trampoline_info_t *info = &bank.infos[idx];
        uint64_t resume_addr = (uint64_t)target_addr + (uint64_t)info->prologue_bytes;
        // Compute exit stub address to help set LLDB breakpoints
        size_t ex_off = (size_t)(XTRAMP_EXIT_STUB - XTRAMP_START_AFTER_PROLOGUE);
        uint64_t exit_stub_addr = (uint64_t)(uintptr_t)info->trampoline + (uint64_t)info->prologue_bytes + (uint64_t)ex_off;
        printf("  trampoline slot @ 0x%llx, resume @ 0x%llx, exit_stub @ 0x%llx\n",
               (unsigned long long)(uintptr_t)info->trampoline,
               (unsigned long long)resume_addr,
               (unsigned long long)exit_stub_addr);
        if (info->ctx_base) {
            printf("  ctx_base @ 0x%llx size %zu bytes\n",
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
        if (n == 0) return -1; // EOF
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)n;
        left -= (size_t)n;
    }
    return (ssize_t)len;
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
    printf("[%s][+%0.6fs] %s: api=%u dir=%u id=%d size=%u copy=%u bits=0x%08x addr=0x%llx opt=0x%08x%08x ret=0x%llx desc=%u prio=%u timeout=%llu\n",
           tbuf, mono_s, kstr,
           pl->api, pl->direction,
           hdr ? hdr->msgh_id : -1,
           pl->msgh_size, pl->copy_len,
           bits,
           (unsigned long long)pl->msg_addr,
           opt_hi, opt32,
           (unsigned long long)pl->ret_value,
           pl->desc_count, pl->priority, (unsigned long long)pl->timeout);

    // Optionally, print a short hexdump of the first 64 bytes of the message
    size_t dump_len = msg_len < 64 ? msg_len : 64;
    if (hdr && dump_len) {
        const uint8_t *p = (const uint8_t *)hdr;
        printf("  msg[%zu]: ", dump_len);
        for (size_t i = 0; i < dump_len; i++) printf("%02x", p[i]);
        printf("\n");
    }
}

static int cmd_listen(pid_t pid) {
    int sfd = xniff_ipc_server_listen(pid);
    if (sfd < 0) { perror("listen"); return -1; }
    char path[108]; xniff_ipc_path_for_pid(pid, path, sizeof(path));
    printf("listening on %s...\n", path);

    // Prepare dump directory for this pid
    char base_dir[256];
    snprintf(base_dir, sizeof(base_dir), "/tmp/xniff/%d", (int)pid);
    mkdir("/tmp/xniff", 0755);
    mkdir(base_dir, 0755);
    unsigned long long evt_idx = 0;

    for (;;) {
        int cfd = xniff_ipc_accept(sfd);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); return -1; }
        printf("client connected\n");
        for (;;) {
            xniff_ipc_hdr_t hdr;
            if (read_fully(cfd, &hdr, sizeof(hdr)) != sizeof(hdr)) { close(cfd); printf("client disconnected\n"); break; }
            if (hdr.magic != XNIFF_IPC_MAGIC || hdr.version != XNIFF_IPC_VERSION) { fprintf(stderr, "bad header/magic\n"); close(cfd); break; }
            if (hdr.payload_len < sizeof(xniff_ipc_mach_payload_t)) { fprintf(stderr, "short payload len %u\n", hdr.payload_len); close(cfd); break; }

            uint8_t *buf = (uint8_t *)malloc(hdr.payload_len);
            if (!buf) { fprintf(stderr, "oom %u\n", hdr.payload_len); close(cfd); break; }
            if (read_fully(cfd, buf, hdr.payload_len) != (ssize_t)hdr.payload_len) { free(buf); close(cfd); printf("client disconnected\n"); break; }

            xniff_ipc_mach_payload_t *pl = (xniff_ipc_mach_payload_t *)buf;
            uint8_t *msg_bytes = buf + sizeof(*pl);
            print_event(hdr.kind, pl, msg_bytes, pl->copy_len);

            // Dump inline message bytes to file
            char prefix[512];
            snprintf(prefix, sizeof(prefix), "%s/%s_%06llu", base_dir, kind_to_tag(hdr.kind), evt_idx);
            if (pl->copy_len && pl->copy_len <= hdr.payload_len - sizeof(*pl)) {
                char pmsg[600]; snprintf(pmsg, sizeof(pmsg), "%s_msg.bin", prefix);
                FILE *fp = fopen(pmsg, "wb"); if (fp) { fwrite(msg_bytes, 1, pl->copy_len, fp); fclose(fp); }
            }

            // Parse TLVs already contained in payload and dump them
            size_t offset = sizeof(*pl) + pl->copy_len;
            while (offset + sizeof(xniff_ipc_tlv_t) <= hdr.payload_len) {
                xniff_ipc_tlv_t *tlv = (xniff_ipc_tlv_t *)(buf + offset);
                offset += sizeof(*tlv);
                if (offset + tlv->length > hdr.payload_len) break; // malformed
                uint8_t *val = buf + offset;
                if (tlv->type == XNIFF_TLV_OOL_DATA) {
                    xniff_ool_data_t *md = (xniff_ool_data_t *)val;
                    const uint8_t *bytes = val + sizeof(*md);
                    char ppath[600]; snprintf(ppath, sizeof(ppath), "%s_ool%u.bin", prefix, md->index);
                    FILE *fp = fopen(ppath, "wb"); if (fp) { fwrite(bytes, 1, md->size, fp); fclose(fp); }
                } else if (tlv->type == XNIFF_TLV_OOL_PORTS) {
                    xniff_ool_ports_t *md = (xniff_ool_ports_t *)val;
                    const uint8_t *bytes = val + sizeof(*md);
                    char ppath[600]; snprintf(ppath, sizeof(ppath), "%s_ool_ports%u.bin", prefix, md->index);
                    size_t bytes_len = (size_t)md->count * md->elem_size;
                    FILE *fp = fopen(ppath, "wb"); if (fp) { fwrite(bytes, 1, bytes_len, fp); fclose(fp); }
                }
                offset += tlv->length;
            }

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
    const char *candidates[] = { "_mach_msg_overwrite", "_mach_msg", "_mach_msg2" };
    const int n = (int)(sizeof(candidates)/sizeof(candidates[0]));
    int patched = 0;
    for (int i = 0; i < n; i++) {
        mach_vm_address_t target = 0;
        if (xniff_find_symbol_in_image_path_contains(task, "libsystem_kernel", candidates[i], &target) != 0) continue;

        // Choose appropriate hook pair for each symbol
        mach_vm_address_t eh = entry_hook_v1;
        mach_vm_address_t xh = exit_hook_v1;
        if (strcmp(candidates[i], "_mach_msg2") == 0) { eh = entry_hook_v2; xh = exit_hook_v2; }
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
                printf("patched %s: slot @ 0x%llx, resume @ 0x%llx, exit_stub @ 0x%llx\n",
                       candidates[i],
                       (unsigned long long)(uintptr_t)info->trampoline,
                       (unsigned long long)resume_addr,
                       (unsigned long long)exit_stub_addr);
            } else {
                printf("patched %s\n", candidates[i]);
            }
        } else {
            fprintf(stderr, "failed to patch %s\n", candidates[i]);
        }
    }

    if (bank.is_remote) { if (bank.infos) free(bank.infos); memset(&bank, 0, sizeof(bank)); }
    else { trampoline_bank_deinit(&bank); }

    if (did_suspend) task_resume(task);
    detach_process(pid);
    printf("patched %d symbols\n", patched);
    return patched > 0 ? 0 : -1;
}
