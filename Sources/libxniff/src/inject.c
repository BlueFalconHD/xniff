#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xniff/inject.h>
#include <xniff/macho.h>
#include <xniff/patch.h>

#include <dlfcn.h>
#include <mach/thread_act.h>

#define PATH_LIBDYLD_EXACT "/usr/lib/system/libdyld.dylib"
#define PATH_LIBDYLD_SUB "libdyld"

#define PATH_LIBSYS_PTHREAD_EXACT "/usr/lib/system/libsystem_pthread.dylib"
#define PATH_LIBSYS_PTHREAD_SUB "libsystem_pthread"

int xniff_inject_dylib_task(mach_port_t task, const char *dylib_path,
                            mach_vm_address_t *out_handle) {
  if (!task || !dylib_path) {
    fprintf(stderr, "invalid arguments to xniff_inject_dylib_task\n");
    return -1;
  }

  // symbols resolved in the target
  mach_vm_address_t dlopen_addr = 0;
  mach_vm_address_t pthr_exit_addr = 0;

  const char *libdyld_exact = PATH_LIBDYLD_EXACT;
  const char *libdyld_sub = PATH_LIBDYLD_SUB;

  // look for dlopen
  if (xniff_find_symbol_in_image_exact_path(task, libdyld_exact, "_dlopen",
                                            &dlopen_addr) != 0 &&
      xniff_find_symbol_in_image_path_contains(task, libdyld_sub, "_dlopen",
                                               &dlopen_addr) != 0) {
    fprintf(stderr, "could not resolve dlopen in target\n");
    return -1;
  }

  const char *libpth_exact = PATH_LIBSYS_PTHREAD_EXACT;
  const char *libpth_sub = PATH_LIBSYS_PTHREAD_SUB;

  // look for pthread_exit
  // if not found, we can proceed without it and instead just infinite loop in the stub
  if (xniff_find_symbol_in_image_exact_path(task, libpth_exact, "_pthread_exit",
                                            &pthr_exit_addr) != 0 &&
      xniff_find_symbol_in_image_path_contains(
          task, libpth_sub, "_pthread_exit", &pthr_exit_addr) != 0) {
    pthr_exit_addr = 0;
  }

  // allocate a stack for the remote thread
  // 16 pages (64KB)
  const mach_vm_size_t stack_size = (1u << 16);
  vm_address_t stack_addr = 0;
  kern_return_t kr =
      vm_allocate(task, &stack_addr, stack_size, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "vm_allocate stack failed: %d\n", kr);
    return -1;
  }

  // leave some slack at the top of the stack
  mach_vm_address_t sp = stack_addr + stack_size - 0x100;

  // align the stack pointer to 16 bytes
  sp &= ~((mach_vm_address_t)0xF);

  // symbols from dylib_inject_stub.S
  extern uint8_t XNIFF_SHCODE_START[];
  extern uint8_t XNIFF_SHCODE_END[];

  // get the stub code blob
  const uint8_t *blob = XNIFF_SHCODE_START;
  size_t blob_size = (size_t)(XNIFF_SHCODE_END - XNIFF_SHCODE_START);

  // allocate space for the stub code
  vm_address_t code_addr = 0;
  if (vm_allocate(task, &code_addr, (vm_size_t)blob_size, VM_FLAGS_ANYWHERE) !=
      KERN_SUCCESS) {
    fprintf(stderr, "vm_allocate code blob failed\n");
    goto fail_stack;
  }

  // make the code region writable for patching
  // we will restore protections later
  if (prepare_protections_for_patching_task(task, (mach_vm_address_t)code_addr,
                                            blob_size) != 0) {
    fprintf(stderr, "prepare_protections_for_patching_task failed\n");
    goto fail_code;
  }

  // write the stub code into the target
  if (vm_write(task, code_addr, (vm_offset_t)(uintptr_t)blob,
               (mach_msg_type_number_t)blob_size) != KERN_SUCCESS) {
    fprintf(stderr, "vm_write code blob failed\n");
    goto fail_code;
  }

  // look for pthread_create or pthread_create_from_mach_thread
  mach_vm_address_t pthr_create_from_mach = 0, pthr_create = 0;
  (void)xniff_find_symbol_in_image_exact_path(
      task, libpth_exact, "_pthread_create_from_mach_thread",
      &pthr_create_from_mach);

  // try the substring path if exact failed
  if (!pthr_create_from_mach)
    (void)xniff_find_symbol_in_image_path_contains(
        task, libpth_sub, "_pthread_create_from_mach_thread",
        &pthr_create_from_mach);

  // fallback to pthread_create if from_mach not found
  if (!pthr_create_from_mach) {
    (void)xniff_find_symbol_in_image_exact_path(
        task, libpth_exact, "_pthread_create", &pthr_create);
    if (!pthr_create)
      (void)xniff_find_symbol_in_image_path_contains(
          task, libpth_sub, "_pthread_create", &pthr_create);
  }

  // choose which pthread_create to use
  mach_vm_address_t which_create =
      pthr_create_from_mach ? pthr_create_from_mach : pthr_create;
  if (!which_create) {
    fprintf(stderr, "could not resolve pthread_create in target\n");
    goto fail_code;
  }

  // check dylib_inject_stub.S for these placeholder definitions
  // essentially these are just dummy unique values we can search for and patch
  const char *PH_PTHR = "PTHRDCRT";
  const char *PH_DLOP = "DLOPEN__";
  const char *PH_EXIT = "PTHREXIT";
  const char *PH_LIB = "LIBLIBLIB";

  // find the offsets of the placeholders in the blob
  size_t off_pthr = 0, off_dlopen = 0, off_exit = 0, off_lib = 0;
  for (size_t i = 0; i + 8 <= blob_size; i++) {
    if (!off_pthr && memcmp(blob + i, PH_PTHR, 8) == 0)
      off_pthr = i;
    if (!off_dlopen && memcmp(blob + i, PH_DLOP, 8) == 0)
      off_dlopen = i;
    if (!off_exit && memcmp(blob + i, PH_EXIT, 8) == 0)
      off_exit = i;
    if (!off_lib && i + 9 <= blob_size && memcmp(blob + i, PH_LIB, 9) == 0)
      off_lib = i;
  }

  // if any placeholder not found, fail
  if (!off_pthr || !off_dlopen || !off_exit || !off_lib) {
    fprintf(stderr, "failed to locate placeholders in stub blob\n");
    goto fail_code;
  }

  // because we are dealing with memory, and strlen does not include the null terminator,
  // we add 1 to the length for writing
  size_t path_len = strlen(dylib_path) + 1;
  if (path_len > 512) {
    fprintf(stderr, "dylib path too long for inline buffer (%zu)\n", path_len);
    goto fail_code;
  }

  // patch the stub code with resolved address to pthread_create
  if (vm_write(task, code_addr + off_pthr,
               (vm_offset_t)(uintptr_t)&which_create,
               (mach_msg_type_number_t)sizeof(which_create)) != KERN_SUCCESS) {
    fprintf(stderr, "vm_write patch pthread_create failed\n");
    goto fail_code;
  }

  // patch the stub code with resolved address to dlopen
  if (vm_write(task, code_addr + off_dlopen,
               (vm_offset_t)(uintptr_t)&dlopen_addr,
               (mach_msg_type_number_t)sizeof(dlopen_addr)) != KERN_SUCCESS) {
    fprintf(stderr, "vm_write patch dlopen failed\n");
    goto fail_code;
  }

  // patch the stub code with resolved address to pthread_exit (or 0)
  if (vm_write(
          task, code_addr + off_exit, (vm_offset_t)(uintptr_t)&pthr_exit_addr,
          (mach_msg_type_number_t)sizeof(pthr_exit_addr)) != KERN_SUCCESS) {
    fprintf(stderr, "vm_write patch pthread_exit failed\n");
    goto fail_code;
  }

  // write the dylib path string
  if (vm_write(task, code_addr + off_lib, (vm_offset_t)(uintptr_t)dylib_path,
               (mach_msg_type_number_t)path_len) != KERN_SUCCESS) {
    fprintf(stderr, "vm_write patch dylib path failed\n");
    goto fail_code;
  }

  // this fixes permissions of the code region after patching
  // typically arm64 CPUs require executable pages to be non-writable
  (void)restore_protections_after_patching_task(
      task, (mach_vm_address_t)code_addr, blob_size);

  // setup the thread state
  // these are the initial register values for the new thread
  arm_thread_state64_t st;
  memset(&st, 0, sizeof(st));

  // the stack pointer is set to our allocated stack
  st.__sp = sp;

  // the program counter is equal to our allocated code address
  st.__pc = code_addr;

  // create the thread
  thread_act_t th = MACH_PORT_NULL;
  kr = thread_create_running(task, ARM_THREAD_STATE64, (thread_state_t)&st,
                             ARM_THREAD_STATE64_COUNT, &th);


  // check for thread creation error
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "thread_create_running failed: %d\n", kr);
    goto fail_code;
  }


  if (out_handle)
    *out_handle = 0;

  return 0;

fail_code:
  (void)vm_deallocate(task, code_addr, (vm_size_t)blob_size);
fail_stack:
  (void)vm_deallocate(task, stack_addr, stack_size);
  return -1;
}
