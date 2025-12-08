#include <xniff/inject.h>
#include <xniff/macho.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach/thread_act.h>
#include <dlfcn.h>
#endif

static inline int vm_write_string(mach_port_t task, mach_vm_address_t *out_addr, const char *s) {
    size_t len = strlen(s) + 1;
    vm_address_t addr = 0;
    kern_return_t kr = vm_allocate(task, &addr, len, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "vm_allocate string failed: %d\n", kr);
        return -1;
    }
    kr = vm_write(task, addr, (vm_offset_t)(uintptr_t)s, (mach_msg_type_number_t)len);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "vm_write string failed: %d\n", kr);
        (void)vm_deallocate(task, addr, len);
        return -1;
    }
    if (out_addr) *out_addr = addr;
    return 0;
}

int xniff_inject_dylib_task(mach_port_t task, const char *dylib_path, mach_vm_address_t *out_handle) {
#if defined(__APPLE__) && (defined(__aarch64__) || defined(__arm64__))
    if (!task || !dylib_path) return -1;

    // Resolve dlopen and pthread_exit in target
    mach_vm_address_t dlopen_addr = 0;
    mach_vm_address_t pthr_exit_addr = 0;

    printf("resolving _dlopen in target...\n");
    if (xniff_find_symbol_in_task(task, "_dlopen", &dlopen_addr) != 0) {
        fprintf(stderr, "could not resolve _dlopen in target\n");
        return -1;
    }

    printf("resolving _pthread_exit in target...\n");
    if (xniff_find_symbol_in_task(task, "_pthread_exit", &pthr_exit_addr) != 0) {
        // Fallback: thread_terminate? If not found, we still proceed and let thread spin.
        pthr_exit_addr = 0;
    }


    printf("dlopen addr: 0x%llx, pthread_exit addr: 0x%llx\n",
           (unsigned long long)dlopen_addr,
           (unsigned long long)pthr_exit_addr);

    printf("injecting dylib %s into target...\n", dylib_path);
    // Allocate path string in target
    mach_vm_address_t remote_path = 0;
    if (vm_write_string(task, &remote_path, dylib_path) != 0) return -1;

    // Allocate a small stack for the new thread
    printf("allocating remote thread stack...\n");
    const mach_vm_size_t stack_size = 1 << 16; // 64 KB
    vm_address_t stack_addr = 0;
    kern_return_t kr = vm_allocate(task, &stack_addr, stack_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "vm_allocate stack failed: %d\n", kr);
        (void)vm_deallocate(task, remote_path, strlen(dylib_path) + 1);
        return -1;
    }
    mach_vm_address_t sp = stack_addr + stack_size - 0x100; // leave red zone
    sp &= ~((mach_vm_address_t)0xF); // 16-byte alignment

    // Prepare ARM64 thread state to call dlopen(path, RTLD_NOW) and then pthread_exit(ret)
    arm_thread_state64_t state;
    memset(&state, 0, sizeof(state));
    // x0 = path, x1 = RTLD_NOW (2)
    state.__x[0] = remote_path;
    state.__x[1] = 2;
    state.__pc   = dlopen_addr;
    state.__sp   = sp;
    state.__lr   = pthr_exit_addr; // if 0, return to 0 -> crash; acceptable for quick and dirty

    printf("creating remote thread...\n");
    thread_act_t th = MACH_PORT_NULL;
    kr = thread_create_running(task, ARM_THREAD_STATE64,
                               (thread_state_t)&state, ARM_THREAD_STATE64_COUNT,
                               &th);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "thread_create_running failed: %d\n", kr);
        (void)vm_deallocate(task, remote_path, strlen(dylib_path) + 1);
        (void)vm_deallocate(task, stack_addr, stack_size);
        return -1;
    }

    // Best-effort: try to read x0 after a brief wait if caller wants a handle (non-blocking join avoided)
    if (out_handle) *out_handle = 0;
    // Caller can poll the task for the module if needed.
    (void)th; // leak or caller can wait/terminate later
    return 0;
#else
    (void)task; (void)dylib_path; (void)out_handle;
    fprintf(stderr, "xniff_inject_dylib_task: not supported on this build arch\n");
    return -1;
#endif
}

int xniff_load_runtime_task(mach_port_t task, const char *runtime_dylib_path,
                            mach_vm_address_t *out_ctx_enter,
                            mach_vm_address_t *out_ctx_exit,
                            mach_vm_address_t *out_exit_hook) {
    if (!task || !runtime_dylib_path) return -1;
    if (xniff_inject_dylib_task(task, runtime_dylib_path, NULL) != 0) return -1;

    // give dyld a moment (caller should ideally synchronize via breakpoint or polling)
    usleep(100 * 1000);

    // Resolve helpers exported by xniff-rt
    mach_vm_address_t addr = 0;
    if (out_ctx_enter) {
        if (xniff_find_symbol_in_task(task, "_xniff_ctx_enter", &addr) == 0 ||
            xniff_find_symbol_in_task(task, "xniff_ctx_enter", &addr) == 0) {
            *out_ctx_enter = addr;
        } else { *out_ctx_enter = 0; }
    }
    if (out_ctx_exit) {
        if (xniff_find_symbol_in_task(task, "_xniff_ctx_exit", &addr) == 0 ||
            xniff_find_symbol_in_task(task, "xniff_ctx_exit", &addr) == 0) {
            *out_ctx_exit = addr;
        } else { *out_ctx_exit = 0; }
    }
    if (out_exit_hook) {
        if (xniff_find_symbol_in_task(task, "_xniff_exit_hook", &addr) == 0 ||
            xniff_find_symbol_in_task(task, "xniff_exit_hook", &addr) == 0) {
            *out_exit_hook = addr;
        } else { *out_exit_hook = 0; }
    }
    return 0;
}
