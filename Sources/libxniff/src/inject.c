#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xniff/inject.h>
#include <xniff/macho.h>
#include <xniff/patch.h>

#include <dlfcn.h>
#include <mach/thread_act.h>

#if defined(__has_feature)
#if __has_feature(ptrauth_calls) && defined(__LP64__)
#include <ptrauth.h>
#define XNIFF_HAS_PTRAUTH 1
#endif
#endif
#ifndef XNIFF_HAS_PTRAUTH
#define XNIFF_HAS_PTRAUTH 0
#endif

#define PATH_LIBDYLD_EXACT "/usr/lib/system/libdyld.dylib"
#define PATH_LIBDYLD_SUB "libdyld"

#define PATH_LIBSYS_PTHREAD_EXACT "/usr/lib/system/libsystem_pthread.dylib"
#define PATH_LIBSYS_PTHREAD_SUB "libsystem_pthread"
#define XNIFF_SYMBOL_WAIT_ATTEMPTS 100u

static int xniff_resolve_symbol_flexible(mach_port_t task,
                                         const char *exact_path,
                                         const char *path_sub,
                                         const char *symbol,
                                         mach_vm_address_t *out_addr) {
  if (!symbol || !out_addr) return -1;
  if (exact_path && *exact_path &&
      xniff_find_symbol_in_image_exact_path(task, exact_path, symbol, out_addr) == 0) {
    return 0;
  }
  if (path_sub && *path_sub &&
      xniff_find_symbol_in_image_path_contains(task, path_sub, symbol, out_addr) == 0) {
    return 0;
  }
  if (xniff_find_symbol_in_task(task, symbol, out_addr) == 0) return 0;

  // Some symbol tables omit or include the leading underscore depending on context.
  if (symbol[0] == '_') {
    if (xniff_find_symbol_in_task(task, symbol + 1, out_addr) == 0) return 0;
  } else {
    char alt[256];
    int n = snprintf(alt, sizeof(alt), "_%s", symbol);
    if (n > 0 && (size_t)n < sizeof(alt)) {
      if (xniff_find_symbol_in_task(task, alt, out_addr) == 0) return 0;
    }
  }
  return -1;
}

static int xniff_wait_for_symbol_flexible(mach_port_t task,
                                          const char *exact_path,
                                          const char *path_sub,
                                          const char *symbol,
                                          mach_vm_address_t *out_addr) {
  unsigned long long tries = 0;
  for (; tries < XNIFF_SYMBOL_WAIT_ATTEMPTS;) {
    if (xniff_resolve_symbol_flexible(task, exact_path, path_sub, symbol, out_addr) == 0) {
      return 0;
    }
    tries++;
    if (tries <= 10 || (tries % 100) == 0) {
      fprintf(stderr, "waiting for symbol %s in target...\n", symbol ? symbol : "<null>");
    }
    usleep(50 * 1000);
  }
  fprintf(stderr, "timed out waiting for symbol %s in target\n",
          symbol ? symbol : "<null>");
  return -1;
}

static int xniff_wait_for_create_symbol(mach_port_t task,
                                        const char *exact_path,
                                        const char *path_sub,
                                        mach_vm_address_t *out_addr) {
  unsigned long long tries = 0;
  for (; tries < XNIFF_SYMBOL_WAIT_ATTEMPTS;) {
    mach_vm_address_t from_mach = 0;
    if (xniff_resolve_symbol_flexible(task, exact_path, path_sub,
                                      "_pthread_create_from_mach_thread",
                                      &from_mach) == 0) {
      *out_addr = from_mach;
      return 0;
    }
    mach_vm_address_t plain = 0;
    if (xniff_resolve_symbol_flexible(task, exact_path, path_sub,
                                      "_pthread_create",
                                      &plain) == 0) {
      *out_addr = plain;
      return 0;
    }
    tries++;
    if (tries <= 10 || (tries % 100) == 0) {
      fprintf(stderr, "waiting for symbol _pthread_create*_ in target...\n");
    }
    usleep(50 * 1000);
  }
  fprintf(stderr, "timed out waiting for _pthread_create*_ in target\n");
  return -1;
}

static void (*xniff_sign_remote_pc_fptr(mach_vm_address_t entry))(void) {
#if XNIFF_HAS_PTRAUTH
  // arm64e thread state stores pc as process-independent-code-signed pointer.
  void *raw_pc = (void *)(uintptr_t)entry;
  void *signed_pc = ptrauth_sign_unauthenticated(
      raw_pc, ptrauth_key_process_independent_code,
      ptrauth_string_discriminator("pc"));
  return (void (*)(void))signed_pc;
#else
  return (void (*)(void))(uintptr_t)entry;
#endif
}

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
  if (xniff_wait_for_symbol_flexible(task, libdyld_exact, libdyld_sub, "_dlopen",
                                     &dlopen_addr) != 0) {
    fprintf(stderr, "could not resolve dlopen in target\n");
    return -1;
  }

  const char *libpth_exact = PATH_LIBSYS_PTHREAD_EXACT;
  const char *libpth_sub = PATH_LIBSYS_PTHREAD_SUB;

  // look for pthread_exit
  // if not found, we can proceed without it and instead just infinite loop in the stub
  if (xniff_resolve_symbol_flexible(task, libpth_exact, libpth_sub, "_pthread_exit",
                                    &pthr_exit_addr) != 0) {
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
  mach_vm_address_t which_create = 0;
  (void)xniff_wait_for_create_symbol(task, libpth_exact, libpth_sub,
                                     &which_create);
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
  if (restore_protections_after_patching_task(
          task, (mach_vm_address_t)code_addr, blob_size) != 0) {
    fprintf(stderr, "restore_protections_after_patching_task failed\n");
    goto fail_code;
  }

  // setup the thread state
  // these are the initial register values for the new thread
  arm_thread_state64_t st;
  memset(&st, 0, sizeof(st));

  // set stack/program counter through SDK accessors so arm64e opaque thread
  // state layouts are handled correctly.
  arm_thread_state64_set_sp(st, sp);
  arm_thread_state64_set_pc_presigned_fptr(st,
                                           xniff_sign_remote_pc_fptr(code_addr));

  // create the thread
  thread_act_t th = MACH_PORT_NULL;
  kr = thread_create_running(task, ARM_THREAD_STATE64, (thread_state_t)&st,
                             ARM_THREAD_STATE64_COUNT, &th);


  // check for thread creation error
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "thread_create_running: %d (%s)\n", kr, mach_error_string(kr));
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
