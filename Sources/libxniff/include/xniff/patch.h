#ifndef PATCH_H
#define PATCH_H

#include <errno.h>
#include <capstone.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Trampoline prelude inserted before copied prologue bytes.
// When the target is patched with a stub that uses X16/X17 as scratch (like Frida Gum),
// the stub first pushes {x16,x17}. The trampoline prelude then restores them (and SP)
// before executing the copied prologue to keep the callee's entry state intact.
#define XNIFF_TRAMPOLINE_PRELUDE_BYTES 8u

// from tramp_template.S
extern const uint8_t TRAMPOLINE_START_AFTER_PROLOGUE[];
extern const uint8_t TRAMPOLINE_INTERMEDIATE_ADRP[];
extern const uint8_t TRAMPOLINE_INTERMEDIATE_ADD[];
extern const uint8_t TRAMPOLINE_RELOAD_ADRP[];
extern const uint8_t TRAMPOLINE_RELOAD_ADD[];
extern const uint8_t TRAMPOLINE_AFTER_RESTORE[];
extern const uint8_t TRAMPOLINE_RETURN_ADRP[];
extern const uint8_t TRAMPOLINE_RETURN_ADD[];

// Extended trampoline (entry+exit) labels
extern const uint8_t XTRAMP_START_AFTER_PROLOGUE[];
extern const uint8_t XTRAMP_HOOK_ADRP[];
extern const uint8_t XTRAMP_HOOK_ADD[];
extern const uint8_t XTRAMP_CTX_ADRP[];
extern const uint8_t XTRAMP_CTX_ADD[];
extern const uint8_t XTRAMP_RESUME_ADRP[];
extern const uint8_t XTRAMP_RESUME_ADD[];
extern const uint8_t XTRAMP_EXITLR_ADRP[];
extern const uint8_t XTRAMP_EXITLR_ADD[];
extern const uint8_t XTRAMP_RETURN_ADRP[];
extern const uint8_t XTRAMP_RETURN_ADD[];
extern const uint8_t XTRAMP_EXIT_STUB[];
extern const uint8_t XTRAMP_EXIT_CTX_ADRP[];
extern const uint8_t XTRAMP_EXIT_CTX_ADD[];
extern const uint8_t XTRAMP_EXIT_HOOK_ADRP[];
extern const uint8_t XTRAMP_EXIT_HOOK_ADD[];
extern const uint8_t XTRAMP_END[];
extern const uint8_t XTRAMP_NOOP[];

/* Page size in bytes at runtime. */
#define PAGE_SIZE_BYTES ((size_t)getpagesize())

/* Start address of the page containing 'a'. */
#define ALIGN_DOWN_TO_PAGE(a) \
    ((mach_vm_address_t)((mach_vm_address_t)(a) & ~((mach_vm_address_t)PAGE_SIZE_BYTES - 1)))

/* 'a' rounded up to the next page boundary (or unchanged if already aligned). */
#define ALIGN_UP_TO_PAGE(a) \
    ((mach_vm_address_t)((((mach_vm_address_t)(a)) + ((mach_vm_address_t)PAGE_SIZE_BYTES - 1)) & ~((mach_vm_address_t)PAGE_SIZE_BYTES - 1)))

/* Page-aligned start for a byte range beginning at 'a'. */
#define PAGE_RANGE_START(a) ALIGN_DOWN_TO_PAGE((a))

/* Total page-aligned length needed to cover [a, a + s). */
#define PAGE_RANGE_SIZE(a, s) \
    ((mach_vm_size_t)(ALIGN_UP_TO_PAGE((mach_vm_address_t)(a) + (mach_vm_size_t)(s)) - PAGE_RANGE_START((a))))

/*
 * Determines whether an instruction contains PC-relative
 * or other non-copyable elements which will break if we
 * try to copy it before patching.
 *
 * These include:
 * - PC relative access/store/branch
 * - Branches
 */
bool is_instruction_copyable(const cs_insn *insn);

/*
 * Copies copyable instructions until the
 * limit or a non-copyable instruction is found.
 * Returns the number of bytes copied.
 *
 * If you already have a capstone handle,
 * you can pass it in via 'handle', otherwise
 * pass NULL and one will be created internally.
 */
int copy_instructions(uint8_t *dst, const uint8_t *src_fun, size_t limit,
                      csh handle);

/*
 * This is the default branch target for patched functions.
 * It does nothing and returns immediately.
 */
void dummy_patch_hook(void);

/*
 * This is the dummy return target for patched functions.
 * If the patch fails, execution might reach here, where
 * an error will be logged and the process will loop forever.
 */
void dummy_trampoline_return(void);

/*
 * Assembles the trampoline starting at some address
 * (should be instruction aligned after the copied prologue).
 *
 * Copies the assembly template from tramp_template.S into tramp_base,
 * then patches its ADRP/ADD pairs to target the provided hook and return
 * addresses.
 */
void assemble_trampoline_at(uint8_t *tramp_base, uint64_t hook_address,
                            uint64_t return_address,
                            int reload_reg, uint64_t reload_target);

// Extended: entry + exit (position-independent helper code embedded in trampoline).
// Assembles and installs a trampoline that saves args, redirects LR to an exit stub,
// and calls an exit hook on return.
// The entry hook is called as: entry_hook(xniff_ctx_frame_t * ctx)
// The exit hook is called as:  exit_hook(uint64_t ret_x0, xniff_ctx_frame_t * ctx)
// Context memory base is provided per trampoline slot.
int patch_function_with_exit_trampoline_task(mach_port_t task,
                                             mach_vm_address_t target_function,
                                             mach_vm_address_t trampoline_buffer,
                                             mach_vm_address_t entry_hook_function,
                                             mach_vm_address_t exit_hook_function,
                                             mach_vm_address_t ctx_slot_base);

/*
 * Trampoline Bank
 *
 * A simple manager for a fixed-size bank of trampolines, backed by a single
 * RWX (or JIT RX) mapping. It stores metadata for each installed trampoline
 * and provides space allocation for new ones.
 */

typedef struct trampoline_info {
    void   *target_function;     // function being patched
    void   *hook_function;       // function called from trampoline
    void   *trampoline;          // base address of this trampoline slot
    size_t  prologue_bytes;      // number of bytes copied from target
    bool    active;              // whether this entry is in use
    void   *ctx_base;            // optional per-trampoline context base (RW) for exit mode
    size_t  ctx_size;            // size of the context region for this trampoline
} trampoline_info_t;

typedef struct trampoline_bank {
    // When patching a remote task, this is the Mach task port; otherwise mach_task_self.
    mach_port_t        task;
    bool               is_remote;

    uint8_t           *region;                // base of region (numeric address; do not deref if remote)
    size_t             region_size;           // size of mapping
    size_t             per_trampoline_size;   // bytes reserved per trampoline
    size_t             capacity;              // max number of trampolines
    size_t             count;                 // currently active trampolines
    trampoline_info_t *infos;                 // metadata array of length capacity
} trampoline_bank_t;

/* Returns the size in bytes of the trampoline template tail. */
size_t trampoline_template_size(void);

/* Suggest a reasonable per-trampoline slot size. */
size_t trampoline_recommended_slot_size(void);

int trampoline_bank_init_task(trampoline_bank_t *bank, mach_port_t task, size_t capacity, size_t per_trampoline_size);

/* Tear down the bank and free resources. */
void trampoline_bank_deinit(trampoline_bank_t *bank);

/* Allocate a raw slot for manual use; returns NULL if full or size exceeds slot. */
void *trampoline_bank_alloc_slot(trampoline_bank_t *bank, size_t required_size, size_t *out_index);

int trampoline_bank_install_task(trampoline_bank_t *bank,
                                 mach_vm_address_t target_function,
                                 mach_vm_address_t hook_function,
                                 size_t *out_index);

// Install entry+exit trampoline, allocating a per-slot context region (RW) in the target.
int trampoline_bank_install_task_with_exit(trampoline_bank_t *bank,
                                           mach_vm_address_t target_function,
                                           mach_vm_address_t entry_hook_function,
                                           mach_vm_address_t exit_hook_function,
                                           size_t *out_index);

// Task-space variants for working on a remote task
kern_return_t modify_page_protections_task(mach_port_t task, mach_vm_address_t address, size_t size,
                                           vm_prot_t new_prot);
int prepare_protections_for_patching_task(mach_port_t task, mach_vm_address_t address, size_t size);
int restore_protections_after_patching_task(mach_port_t task, mach_vm_address_t address, size_t size);
int patch_function_with_trampoline_task(mach_port_t task,
                                        mach_vm_address_t target_function,
                                        mach_vm_address_t trampoline_buffer,
                                        mach_vm_address_t hook_function);

#endif /* PATCH_H */
