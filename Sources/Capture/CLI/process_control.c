#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <xniff/inject.h>
#include <xniff/macho.h>

#include "capture.h"
#include "cli_output.h"
#include "dylib_staging.h"
#include "launch_environment.h"
#include "process_control.h"
#include "shared_transport.h"
#include "target_identity.h"

extern char **environ;

enum {
    XNIFF_HOOK_MODE_MACH = XNIFF_CAPTURE_MODE_MACH,
    XNIFF_HOOK_MODE_XPC = XNIFF_CAPTURE_MODE_XPC,
};

static const char *capture_mode_name(int mode) {
    return mode == XNIFF_HOOK_MODE_XPC ? "XPC" : "Mach";
}

static const char *command_name(const char *path) {
    if (!path) return "target";
    const char *separator = strrchr(path, '/');
    return separator && separator[1] ? separator + 1 : path;
}

static int attach_and_get_task(pid_t pid, mach_port_t *out_task) {
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t result = task_for_pid(mach_task_self(), pid, &task);
    if (result == KERN_SUCCESS) {
        xniff_output_detail("task", "obtained port for pid %d", pid);
        *out_task = task;
        return 0;
    }

    xniff_output_detail("task", "attaching to pid %d", pid);
    if (ptrace(PT_ATTACHEXC, pid, 0, 0) != 0) {
        xniff_output_error("cannot attach to pid %d: %s", pid, strerror(errno));
        return -1;
    }
    for (int attempt = 0; attempt < 40; attempt++) {
        result = task_for_pid(mach_task_self(), pid, &task);
        if (result == KERN_SUCCESS) break;
        if (attempt == 5) (void)kill(pid, SIGSTOP);
        usleep(50 * 1000);
    }
    if (result != KERN_SUCCESS) {
        xniff_output_error("cannot obtain the task port for pid %d: %d", pid, result);
        (void)ptrace(PT_DETACH, pid, 0, 0);
        return -1;
    }
    *out_task = task;
    return 0;
}

static int detach_process(pid_t pid) {
    return ptrace(PT_DETACH, pid, 0, 0) == 0 ? 0 : -1;
}

static void release_task(pid_t pid, mach_port_t task) {
    (void)detach_process(pid);
    xniff_release_task_cache(task);
    (void)mach_port_deallocate(mach_task_self(), task);
}

static int install_hooks(pid_t pid, const char *dylib_path, int mode,
                         xniff_shared_transport_t *transport) {
    mach_port_t task;
    if (attach_and_get_task(pid, &task) != 0) return -1;

    // Resolve absolute path so dlopen() in the remote process finds the library
    char abs_path[PATH_MAX] = {0};
    if (!realpath(dylib_path, abs_path)) {
        xniff_output_error("cannot resolve hooks path %s: %s",
                           dylib_path, strerror(errno));
        release_task(pid, task);
        return -1;
    }

    char inject_path[PATH_MAX] = {0};
    bool staged_copy =
        xniff_stage_dylib_for_process(pid, abs_path, inject_path,
                                      sizeof(inject_path)) == 0;
    if (staged_copy) {
        xniff_output_detail("hooks", "staged %s", inject_path);
    } else {
        (void)strncpy(inject_path, abs_path, sizeof(inject_path) - 1);
        inject_path[sizeof(inject_path) - 1] = '\0';
        xniff_output_warning("could not stage hooks, using %s", abs_path);
    }

    // Inject hooks dylib (uses filtered dlopen/pthread_exit resolution)
    if (xniff_inject_dylib_task(task, inject_path, NULL) != 0) {
        xniff_output_error("cannot inject hooks into pid %d", pid);
        release_task(pid, task);
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
    int transport_result = -1;
    for (int i = 0; i < 40; i++) {
        if (xniff_shared_transport_configure_target(transport, task,
                                                     (uint32_t)mode) == 0) {
            transport_result = 0;
            break;
        }
        usleep(50 * 1000);
    }
    if (transport_result != 0) {
        xniff_output_error("cannot configure capture transport in pid %d", pid);
        release_task(pid, task);
        if (staged_copy) (void)unlink(inject_path);
        return -1;
    }
    release_task(pid, task);
    xniff_output_detail("hooks", "injected into pid %d", pid);
    if (staged_copy) (void)unlink(inject_path);
    return 0;
}

static int spawn_suspended_target(char *const launch_argv[], const char *hooks_path,
                                  int mode, const xniff_target_identity_t *identity,
                                  xniff_shared_transport_t *transport,
                                  pid_t *out_pid) {
    if (!launch_argv || !launch_argv[0] || !hooks_path || !transport || !out_pid) {
        errno = EINVAL;
        return -1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        xniff_shared_transport_prepare_target_child(transport);
        /*
         * START_SUSPENDED is too late for platform binaries: dyld can strip
         * DYLD_INSERT_LIBRARIES before the parent gets control. TRACE_ME
         * marks the child debugged before exec and stops it at the exec trap,
         * so dyld accepts the injected hooks while main is still unreachable.
         */
        if (identity && xniff_target_identity_apply(identity) != 0) {
            xniff_output_error("cannot become %s (%u:%u): %s",
                               identity->name, (unsigned int)identity->uid,
                               (unsigned int)identity->gid, strerror(errno));
            _exit(126);
        }
        xniff_launch_environment_t launch_environment;
        if (xniff_launch_environment_create(hooks_path, mode,
                                            transport->ring_fd,
                                            transport->wake_write_fd,
                                            &launch_environment) != 0) {
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
                                    const char *target_name,
                                    bool resume_target,
                                    bool target_is_child,
                                    bool hooks_preloaded,
                                    xniff_shared_transport_t *transport,
                                    const listener_opts_t *listener_options) {
    int ready_pipe[2] = {-1, -1};
    if (pipe(ready_pipe) != 0) {
        xniff_output_error("cannot create listener pipe: %s", strerror(errno));
        return -1;
    }
    pid_t child = fork();
    if (child == 0) {
        close(ready_pipe[0]);
        xniff_shared_transport_prepare_listener_child(transport);
        int rc = xniff_capture_ring(pid, ready_pipe[1], transport,
                                    listener_options);
        _exit(rc == 0 ? 0 : 1);
    }
    if (child < 0) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        xniff_output_error("cannot start the capture listener: %s", strerror(errno));
        return -1;
    }
    close(ready_pipe[1]);
    xniff_shared_transport_release_controller_reader(transport);

    struct pollfd ready_poll = {.fd = ready_pipe[0], .events = POLLIN};
    int poll_result = poll(&ready_poll, 1, 5000);
    uint8_t ready_byte = 0;
    bool listener_ready = poll_result > 0 &&
                          read(ready_pipe[0], &ready_byte, sizeof(ready_byte)) == sizeof(ready_byte) &&
                          ready_byte == 1;
    close(ready_pipe[0]);
    if (!listener_ready) {
        if (poll_result <= 0) {
            xniff_output_error("capture listener timed out for pid %d", (int)pid);
        }
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        return -1;
    }

    if (!hooks_preloaded) {
        if (install_hooks(pid, dylib_path, mode, transport) != 0) {
            xniff_shared_transport_release_controller_producer(transport);
            kill(child, SIGTERM);
            (void)waitpid(child, NULL, 0);
            return -1;
        }
    }
    xniff_shared_transport_release_controller_producer(transport);

    if (resume_target) {
        if (continue_traced_target(pid, 0) != 0) {
            xniff_output_error("cannot resume target pid %d: %s",
                               (int)pid, strerror(errno));
            kill(child, SIGTERM);
            (void)waitpid(child, NULL, 0);
            return -1;
        }
        xniff_output_detail("target", "resumed pid %d", (int)pid);
    }

    const char *destination = listener_options->out_bin
        ? listener_options->out_bin_path
        : "standard output";
    xniff_output_status("capture", "writing %s events to %s",
                        capture_mode_name(mode), destination);
    xniff_output_success("ready", "listening to pid %d, press Ctrl-C to stop",
                         (int)pid);
    xniff_output_detail("listener", "pid %d", (int)child);

    int listener_status = 0;
    int target_status = 0;
    bool target_finished = false;
    for (;;) {
        int status = 0;
        pid_t w = waitpid(-1, &status, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            xniff_output_error("cannot wait for capture processes: %s", strerror(errno));
            return -1;
        }
        if (w == child) {
            listener_status = status;
            break;
        }
        if (target_is_child && w == pid) {
            if (WIFSTOPPED(status)) {
                if (continue_after_trace_stop(pid, status) != 0) {
                    xniff_output_error("cannot continue target pid %d: %s",
                                       (int)pid, strerror(errno));
                    (void)kill(child, SIGTERM);
                }
            } else {
                target_status = status;
                target_finished = true;
            }
            continue;
        }
    }
    if (target_is_child && !target_finished) {
        pid_t waited = -1;
        while ((waited = waitpid(pid, &target_status, 0)) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        target_finished = waited == pid;
    }

    bool listener_succeeded = WIFEXITED(listener_status) &&
                              WEXITSTATUS(listener_status) == 0;
    if (!listener_succeeded) return -1;

    if (!target_is_child) {
        xniff_output_success("done", "capture finished for pid %d", (int)pid);
    } else if (target_finished && WIFEXITED(target_status) &&
               WEXITSTATUS(target_status) == 0) {
        xniff_output_success("done", "%s exited successfully", target_name);
    } else if (target_finished && WIFEXITED(target_status)) {
        xniff_output_warning("%s exited with code %d", target_name,
                             WEXITSTATUS(target_status));
    } else if (target_finished && WIFSIGNALED(target_status)) {
        xniff_output_warning("%s exited due to signal %d", target_name,
                             WTERMSIG(target_status));
    }
    return 0;
}

int xniff_attach(pid_t pid, const char *dylib_path, int mode,
                 const listener_opts_t *listener_options) {
    xniff_output_status("attach", "pid %d", (int)pid);
    xniff_shared_transport_t transport;
    if (xniff_shared_transport_create(&transport) != 0) {
        xniff_output_error("cannot create shared transport: %s", strerror(errno));
        return -1;
    }
    int result = capture_attached_process(pid, dylib_path, mode, "target", false,
                                          false, false, &transport, listener_options);
    xniff_shared_transport_destroy(&transport);
    return result;
}

int xniff_launch(const char *dylib_path, int mode, const char *target_user,
                 char *const launch_argv[],
                 const listener_opts_t *listener_options) {
    xniff_target_identity_t identity;
    xniff_target_identity_t *identity_ptr = NULL;
    if (target_user) {
        if (xniff_target_identity_resolve(target_user, &identity) != 0) {
            xniff_output_error("cannot resolve target user %s: %s",
                               target_user, strerror(errno));
            return -1;
        }
        identity_ptr = &identity;
    }
    xniff_shared_transport_t transport;
    if (xniff_shared_transport_create(&transport) != 0) {
        xniff_output_error("cannot create shared transport: %s", strerror(errno));
        return -1;
    }
    pid_t pid = 0;
    if (spawn_suspended_target(launch_argv, dylib_path, mode, identity_ptr,
                               &transport, &pid) != 0) {
        xniff_output_error("cannot launch %s: %s",
                           launch_argv && launch_argv[0] ? launch_argv[0] : "target",
                           strerror(errno));
        xniff_shared_transport_destroy(&transport);
        return -1;
    }

    const char *name = command_name(launch_argv[0]);
    if (identity_ptr) {
        xniff_output_status("starting", "%s (%d) as %s (%u)", name, (int)pid,
                            identity.name, (unsigned int)identity.uid);
    } else {
        xniff_output_status("starting", "%s (%d)", name, (int)pid);
    }
    int rc = capture_attached_process(pid, dylib_path, mode, name, true, true,
                                      true, &transport, listener_options);
    if (rc != 0) {
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
    }
    xniff_shared_transport_destroy(&transport);
    return rc;
}
