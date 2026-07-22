#include <errno.h>
#include <fcntl.h>
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <xniff/inject.h>
#include <xniff/macho.h>

#include "capture.h"
#include "launch_environment.h"
#include "process_control.h"
#include "shared_transport.h"
#include "target_identity.h"

extern char **environ;

enum {
    XNIFF_HOOK_MODE_MACH = XNIFF_CAPTURE_MODE_MACH,
    XNIFF_HOOK_MODE_XPC = XNIFF_CAPTURE_MODE_XPC,
};

#define XNIFF_DIAGF(...) fprintf(stderr, __VA_ARGS__)

static int attach_and_get_task(pid_t pid, mach_port_t *out_task) {
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t result = task_for_pid(mach_task_self(), pid, &task);
    if (result == KERN_SUCCESS) {
        XNIFF_DIAGF("got task port for pid %d without attach\n", pid);
        *out_task = task;
        return 0;
    }

    XNIFF_DIAGF("attaching to pid %d\n", pid);
    if (ptrace(PT_ATTACHEXC, pid, 0, 0) != 0) {
        perror("ptrace(PT_ATTACHEXC)");
        return -1;
    }
    for (int attempt = 0; attempt < 40; attempt++) {
        result = task_for_pid(mach_task_self(), pid, &task);
        if (result == KERN_SUCCESS) break;
        if (attempt == 5) (void)kill(pid, SIGSTOP);
        usleep(50 * 1000);
    }
    if (result != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed after attach: %d\n", result);
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

static int copy_file(const char *source_path, const char *destination_path) {
    int source = open(source_path, O_RDONLY);
    if (source < 0) return -1;
    int destination = open(destination_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (destination < 0) {
        close(source);
        return -1;
    }

    uint8_t buffer[64 * 1024];
    int result = 0;
    for (;;) {
        ssize_t count = read(source, buffer, sizeof(buffer));
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            result = -1;
            break;
        }
        size_t offset = 0;
        while (offset < (size_t)count) {
            ssize_t written = write(destination, buffer + offset,
                                    (size_t)count - offset);
            if (written < 0) {
                if (errno == EINTR) continue;
                result = -1;
                break;
            }
            offset += (size_t)written;
        }
        if (result != 0) break;
    }
    if (result == 0) (void)fsync(destination);
    close(destination);
    close(source);
    if (result != 0) (void)unlink(destination_path);
    return result;
}

static int stage_dylib(const char *source_path, char *output_path,
                       size_t output_path_size) {
    const char *directories[] = {"/tmp", "/private/tmp", "/private/var/tmp"};
    for (size_t directory = 0;
         directory < sizeof(directories) / sizeof(directories[0]);
         directory++) {
        for (int attempt = 0; attempt < 16; attempt++) {
            unsigned int salt = arc4random() & 0xffff;
            int length = snprintf(output_path, output_path_size,
                                  "%s/xniff-hooks-%d-%u.dylib",
                                  directories[directory], (int)getpid(), salt);
            if (length <= 0 || (size_t)length >= output_path_size) continue;
            if (copy_file(source_path, output_path) == 0) return 0;
        }
    }
    output_path[0] = '\0';
    return -1;
}

static int install_hooks(pid_t pid, const char *dylib_path, int mode,
                         xniff_shared_transport_t *transport) {
    mach_port_t task;
    if (attach_and_get_task(pid, &task) != 0) return -1;

    // Resolve absolute path so dlopen() in the remote process finds the library
    char abs_path[PATH_MAX] = {0};
    if (!realpath(dylib_path, abs_path)) {
        perror("realpath");
        release_task(pid, task);
        return -1;
    }

    char inject_path[PATH_MAX] = {0};
    bool staged_copy =
        stage_dylib(abs_path, inject_path, sizeof(inject_path)) == 0;
    if (staged_copy) {
        XNIFF_DIAGF("attach: staged hooks dylib at %s (from %s)\n", inject_path, abs_path);
    } else {
        (void)strncpy(inject_path, abs_path, sizeof(inject_path) - 1);
        inject_path[sizeof(inject_path) - 1] = '\0';
        XNIFF_DIAGF("attach: warning: failed to stage hooks dylib; using original path %s\n", abs_path);
    }

    // Inject hooks dylib (uses filtered dlopen/pthread_exit resolution)
    if (xniff_inject_dylib_task(task, inject_path, NULL) != 0) {
        fprintf(stderr, "failed to inject hooks dylib into pid %d\n", pid);
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
        fprintf(stderr, "attach: failed to configure shared transport in pid %d\n", pid);
        release_task(pid, task);
        if (staged_copy) (void)unlink(inject_path);
        return -1;
    }
    release_task(pid, task);
    XNIFF_DIAGF("attach: injected %s; capture mode=%s\n", inject_path,
                mode == XNIFF_HOOK_MODE_XPC ? "xpc" : "mach");
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
            fprintf(stderr, "launch: failed to become %s (%u:%u): %s\n",
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
                                    bool resume_target,
                                    bool target_is_child,
                                    bool hooks_preloaded,
                                    xniff_shared_transport_t *transport,
                                    const listener_opts_t *listener_options) {
    const char *flow = resume_target ? "launch" : "attach";
    int ready_pipe[2] = {-1, -1};
    if (pipe(ready_pipe) != 0) {
        perror("pipe");
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
        perror("fork");
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
        fprintf(stderr, "%s: listener failed to start for pid %d\n", flow, (int)pid);
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        return -1;
    }

    if (!hooks_preloaded) {
        int rc = install_hooks(pid, dylib_path, mode, transport);
        if (rc != 0) {
            fprintf(stderr, "%s: hook injection failed; terminating listener (pid %d)\n", flow, (int)child);
            xniff_shared_transport_release_controller_producer(transport);
            kill(child, SIGTERM);
            (void)waitpid(child, NULL, 0);
            return -1;
        }
    }
    xniff_shared_transport_release_controller_producer(transport);

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

int xniff_attach(pid_t pid, const char *dylib_path, int mode,
                 const listener_opts_t *listener_options) {
    xniff_shared_transport_t transport;
    if (xniff_shared_transport_create(&transport) != 0) {
        fprintf(stderr, "attach: failed to create shared transport: %s\n", strerror(errno));
        return -1;
    }
    int result = capture_attached_process(pid, dylib_path, mode, false, false,
                                          false, &transport, listener_options);
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
            fprintf(stderr, "launch: failed to resolve target user '%s': %s\n",
                    target_user, strerror(errno));
            return -1;
        }
        identity_ptr = &identity;
        XNIFF_DIAGF("launch: target user %s (%u:%u)\n", identity.name,
                    (unsigned int)identity.uid, (unsigned int)identity.gid);
    }
    xniff_shared_transport_t transport;
    if (xniff_shared_transport_create(&transport) != 0) {
        fprintf(stderr, "launch: failed to create shared transport: %s\n", strerror(errno));
        return -1;
    }
    pid_t pid = 0;
    if (spawn_suspended_target(launch_argv, dylib_path, mode, identity_ptr,
                               &transport, &pid) != 0) {
        fprintf(stderr, "launch: failed to spawn suspended target '%s': %s\n",
                launch_argv && launch_argv[0] ? launch_argv[0] : "(null)", strerror(errno));
        xniff_shared_transport_destroy(&transport);
        return -1;
    }

    XNIFF_DIAGF("launch: spawned suspended pid %d (%s)\n", (int)pid, launch_argv[0]);
    int rc = capture_attached_process(pid, dylib_path, mode, true, true, true,
                                      &transport, listener_options);
    if (rc != 0) {
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
    }
    xniff_shared_transport_destroy(&transport);
    return rc;
}
