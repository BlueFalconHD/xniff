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

#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach/mach_vm.h>

#include <xniff/patch.h>
#include <xniff/macho.h>


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

    // Find our hook symbol via library helper (prefer main image, then all).
    mach_vm_address_t hook_addr = 0;
    if (xniff_find_symbol_in_main_image(task, "_xniff_remote_hook", &hook_addr) != 0) {
        if (xniff_find_symbol_in_task(task, "_xniff_remote_hook", &hook_addr) != 0) {
            // Try without underscore as a fallback.
            if (xniff_find_symbol_in_main_image(task, "xniff_remote_hook", &hook_addr) != 0 &&
                xniff_find_symbol_in_task(task, "xniff_remote_hook", &hook_addr) != 0) {
                fprintf(stderr, "hook symbol _xniff_remote_hook not found in target\n");
                if (did_suspend) task_resume(task);
                detach_process(pid);
                return -1;
            }
        }
    }

    // Find target symbol across all images
    mach_vm_address_t target_addr = 0;
    if (xniff_find_symbol_in_task(task, symbol_name, &target_addr) != 0) {
        fprintf(stderr, "could not locate %s in target\n", symbol_name);
        if (did_suspend) task_resume(task);
        detach_process(pid);
        return -1;
    }

    printf("found hook at 0x%llx, target %s at 0x%llx\n",
           (unsigned long long)hook_addr, symbol_name, (unsigned long long)target_addr);

    trampoline_bank_t bank;
    if (trampoline_bank_init_task(&bank, task, 8, 0) != 0) {
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
    fprintf(stderr, "Usage: %s <pid> [symbol]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "- If [symbol] is omitted, defaults to _mach_msg_overwrite.\n");
    fprintf(stderr, "- Provide Mach-O symbol (with or without leading underscore).\n");
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) { usage(argv[0]); return 2; }
    pid_t pid = (pid_t)strtol(argv[1], NULL, 10);
    if (pid <= 0) { usage(argv[0]); return 2; }

    // Determine the target symbol. Default to _mach_msg_overwrite for backward compatibility.
    char symbuf[256] = {0};
    const char *user_sym = (argc == 3) ? argv[2] : "_mach_msg_overwrite";
    // Accept names with or without leading underscore; Mach-O externs typically have one.
    if (user_sym[0] == '_') {
        strncpy(symbuf, user_sym, sizeof(symbuf) - 1);
    } else {
        // Prefix underscore if missing
        symbuf[0] = '_';
        strncat(symbuf, user_sym, sizeof(symbuf) - 2);
    }

    int rc = patch_symbol_in_task(pid, symbuf);
    return (rc == 0) ? 0 : 1;
}
