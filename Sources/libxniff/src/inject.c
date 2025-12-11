#include <xniff/inject.h>
#include <xniff/macho.h>
#include <xniff/patch.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach/thread_act.h>
#include <dlfcn.h>
#endif

// Minimal basename helper (no allocation, no mutation)
static inline const char *xniff_path_basename(const char *path) {
    if (!path) return "";
    const char *slash = strrchr(path, '/');
    return slash ? (slash + 1) : path;
}

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

    // Resolve dlopen and pthread_exit in target using filtered lookups
    // Prefer exact paths; fall back to substring matches; finally optional global scan.
    mach_vm_address_t dlopen_addr = 0;
    mach_vm_address_t pthr_exit_addr = 0;

    printf("resolving _dlopen in target (filtered)...\n");
    const char *libdyld_exact = "/usr/lib/system/libdyld.dylib";
    const char *libdyld_sub   = "libdyld";
    const char *dyld_path     = "/usr/lib/dyld";

    if (xniff_find_symbol_in_image_exact_path(task, libdyld_exact, "_dlopen", &dlopen_addr) != 0 &&
        xniff_find_symbol_in_image_path_contains(task, libdyld_sub, "_dlopen", &dlopen_addr) != 0 &&
        xniff_find_symbol_in_image_exact_path(task, dyld_path, "_dlopen", &dlopen_addr) != 0 &&
        xniff_find_symbol_in_image_exact_path(task, libdyld_exact, "dlopen", &dlopen_addr) != 0 &&
        xniff_find_symbol_in_image_path_contains(task, libdyld_sub, "dlopen", &dlopen_addr) != 0 &&
        xniff_find_symbol_in_image_exact_path(task, dyld_path, "dlopen", &dlopen_addr) != 0) {
        fprintf(stderr, "could not resolve dlopen in target\n");
        return -1;
    }

    printf("resolving _pthread_exit in target (filtered)...\n");
    const char *libpth_exact = "/usr/lib/system/libsystem_pthread.dylib";
    const char *libpth_sub   = "libsystem_pthread";
    if (xniff_find_symbol_in_image_exact_path(task, libpth_exact, "_pthread_exit", &pthr_exit_addr) != 0 &&
        xniff_find_symbol_in_image_path_contains(task, libpth_sub, "_pthread_exit", &pthr_exit_addr) != 0 &&
        xniff_find_symbol_in_image_exact_path(task, dyld_path, "_pthread_exit", &pthr_exit_addr) != 0 &&
        xniff_find_symbol_in_image_exact_path(task, libpth_exact, "pthread_exit", &pthr_exit_addr) != 0 &&
        xniff_find_symbol_in_image_path_contains(task, libpth_sub, "pthread_exit", &pthr_exit_addr) != 0 &&
        xniff_find_symbol_in_image_exact_path(task, dyld_path, "pthread_exit", &pthr_exit_addr) != 0) {
        // Not fatal; we will proceed without a clean thread exit.
        pthr_exit_addr = 0;
    }

    // allocate 64kb stack for remote thread
    const mach_vm_size_t stack_size = 1 << 16;
    vm_address_t stack_addr = 0;
    kern_return_t kr = vm_allocate(task, &stack_addr, stack_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "vm_allocate stack failed: %d\n", kr);
        return -1;
    }
    mach_vm_address_t sp = stack_addr + stack_size - 0x100; sp &= ~((mach_vm_address_t)0xF);

    // Preferred path: copy assembled injection stub (dylib_inject_stub.S), patch placeholders, and launch it directly.
    do {
        extern uint8_t XNIFF_SHCODE_START[];
        extern uint8_t XNIFF_SHCODE_END[];
        size_t blob_size = (size_t)(XNIFF_SHCODE_END - XNIFF_SHCODE_START);
        vm_address_t code_addr2 = 0;
        if (vm_allocate(task, &code_addr2, (vm_size_t)blob_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
            break; // fall back to older loader path below
        }
        // Use the same helpers as trampoline JIT to widen then restore protections
        if (prepare_protections_for_patching_task(task, (mach_vm_address_t)code_addr2, (size_t)blob_size) != 0) {
            printf("prepare_protections_for_patching_task failed\n");
            (void)vm_deallocate(task, code_addr2, (vm_size_t)blob_size);
            break;
        }


        // get current memory protections of thing for debugging


        if (vm_write(task, code_addr2, (vm_offset_t)(uintptr_t)XNIFF_SHCODE_START, (mach_msg_type_number_t)blob_size) != KERN_SUCCESS) {
            (void)vm_deallocate(task, code_addr2, (vm_size_t)blob_size); break;
        }

        // Resolve pthread_create*_in_target (used by the stub itself)
        mach_vm_address_t pthr_create_from_mach2 = 0, pthr_create2 = 0;
        (void)xniff_find_symbol_in_image_exact_path(task, libpth_exact, "_pthread_create_from_mach_thread", &pthr_create_from_mach2);
        if (!pthr_create_from_mach2) (void)xniff_find_symbol_in_image_path_contains(task, libpth_sub, "_pthread_create_from_mach_thread", &pthr_create_from_mach2);
        if (!pthr_create_from_mach2) {
            (void)xniff_find_symbol_in_image_exact_path(task, libpth_exact, "_pthread_create", &pthr_create2);
            if (!pthr_create2) (void)xniff_find_symbol_in_image_path_contains(task, libpth_sub, "_pthread_create", &pthr_create2);
        }
        mach_vm_address_t which_create2 = pthr_create_from_mach2 ? pthr_create_from_mach2 : pthr_create2;
        if (!which_create2) { (void)vm_deallocate(task, code_addr2, (vm_size_t)blob_size); break; }

        // Patch placeholders in remote blob
        const char *PH_PTHR = "PTHRDCRT", *PH_DLOP = "DLOPEN__", *PH_EXIT = "PTHREXIT", *PH_LIB = "LIBLIBLIB";
        size_t off_pthr = 0, off_dlopen = 0, off_exit = 0, off_lib = 0;
        const uint8_t *blob = XNIFF_SHCODE_START;
        for (size_t i = 0; i + 8 <= blob_size; i++) {
            if (!off_pthr && memcmp(blob + i, PH_PTHR, 8) == 0) off_pthr = i;
            if (!off_dlopen && memcmp(blob + i, PH_DLOP, 8) == 0) off_dlopen = i;
            if (!off_exit && memcmp(blob + i, PH_EXIT, 8) == 0) off_exit = i;
            if (!off_lib && i + 9 <= blob_size && memcmp(blob + i, PH_LIB, 9) == 0) off_lib = i;
        }
        if (!off_pthr || !off_dlopen || !off_exit || !off_lib) { (void)vm_deallocate(task, code_addr2, (vm_size_t)blob_size); break; }
        // Ensure the embedded path fits inside the reserved inline buffer (~512 bytes)
        size_t path_len = strlen(dylib_path) + 1;
        if (path_len > 512) { (void)vm_deallocate(task, code_addr2, (vm_size_t)blob_size); break; }
        if (vm_write(task, code_addr2 + off_pthr, (vm_offset_t)(uintptr_t)&which_create2, (mach_msg_type_number_t)sizeof(which_create2)) != KERN_SUCCESS) { (void)vm_deallocate(task, code_addr2, (vm_size_t)blob_size); break; }
        if (vm_write(task, code_addr2 + off_dlopen, (vm_offset_t)(uintptr_t)&dlopen_addr, (mach_msg_type_number_t)sizeof(dlopen_addr)) != KERN_SUCCESS) { (void)vm_deallocate(task, code_addr2, (vm_size_t)blob_size); break; }
        if (vm_write(task, code_addr2 + off_exit, (vm_offset_t)(uintptr_t)&pthr_exit_addr, (mach_msg_type_number_t)sizeof(pthr_exit_addr)) != KERN_SUCCESS) { (void)vm_deallocate(task, code_addr2, (vm_size_t)blob_size); break; }
        if (vm_write(task, code_addr2 + off_lib, (vm_offset_t)(uintptr_t)dylib_path, (mach_msg_type_number_t)path_len) != KERN_SUCCESS) { (void)vm_deallocate(task, code_addr2, (vm_size_t)blob_size); break; }

        // Restore code mapping to RX before execution
        (void)restore_protections_after_patching_task(task, (mach_vm_address_t)code_addr2, (size_t)blob_size);

        // Launch the stub directly as a raw Mach thread. The stub itself creates
        // a proper pthread via pthread_create_from_mach_thread and then spins
        // with WFE to avoid CPU spikes.
        arm_thread_state64_t st; memset(&st, 0, sizeof(st));
        st.__sp = sp;
        st.__pc = code_addr2; // entry of stub
        thread_act_t th2 = MACH_PORT_NULL;

        kr = thread_create_running(task, ARM_THREAD_STATE64, (thread_state_t)&st, ARM_THREAD_STATE64_COUNT, &th2);

        if (kr == KERN_SUCCESS) {
            if (out_handle) *out_handle = 0;
            return 0;
        }
        // else fall back to legacy path
        (void)vm_deallocate(task, code_addr2, (vm_size_t)blob_size);
    } while (0);
    // Stub injection failed; clean up and return error
    (void)vm_deallocate(task, stack_addr, stack_size);
    return -1;
#else
    (void)task; (void)dylib_path; (void)out_handle;
    fprintf(stderr, "xniff_inject_dylib_task: not supported on this build arch\n");
    return -1;
#endif
}

/* xniff_load_runtime_task removed along with xniff-rt component. */
