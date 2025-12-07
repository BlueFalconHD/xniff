#include "patch.h"
#include "assembler.h"
#include <pthread.h>


/*
 * Determines whether an instruction contains PC-relative
 * or other non-copyable elements which will break if we
 * try to copy it before patching.
 *
 * These include:
 * - PC relative access/store/branch
 * - Branches
 */
bool is_instruction_copyable(const cs_insn *insn) {
    // ARM64: non-copyable if instruction uses PC-relative addressing or is a branch/call/ret.
    if (!insn) {
      return false;
    }

    // Fast-path by instruction id for common control-flow and PC-relative generators.
    switch (insn->id) {
      case ARM64_INS_B:
      case ARM64_INS_BL:
      case ARM64_INS_BR:
      case ARM64_INS_BLR:
      case ARM64_INS_RET:
      case ARM64_INS_CBZ:
      case ARM64_INS_CBNZ:
      case ARM64_INS_TBZ:
      case ARM64_INS_TBNZ:
      case ARM64_INS_BRAA:
      case ARM64_INS_BRAB:
      case ARM64_INS_BLRAA:
      case ARM64_INS_BLRAB:
      case ARM64_INS_RETAA:
      case ARM64_INS_RETAB:
      case ARM64_INS_ERET:
      case ARM64_INS_ADR:
      case ARM64_INS_ADRP:
        return false;
      default:
        break;
    }

    if (!insn->detail) {
      // Without operand details, conservatively assume non-copyable to avoid breaking relocation.
      return false;
    }

    // Group-based detection (covers conditional branches, etc.).
    for (uint8_t i = 0; i < insn->detail->groups_count; i++) {
      uint8_t g = insn->detail->groups[i];
      if (g == CS_GRP_JUMP || g == CS_GRP_CALL || g == CS_GRP_RET) {
        return false;
      }
  #ifdef ARM64_GRP_BRANCH_RELATIVE
      if (g == ARM64_GRP_BRANCH_RELATIVE) {
        return false;
      }
  #endif
    }

    return true;
};

/*
 * Copies copyable instructions until the
 * limit or a non-copyable instruction is found.
 * Returns the number of bytes copied.
 *
 * If you already have a capstone handle,
 * you can pass it in via 'handle', otherwise
 * pass NULL and one will be created internally.
 *
 * Use to copy a prologue (roughly) to a trampoline.
 */
int copy_instructions(uint8_t *dst, const uint8_t *src_fun, size_t limit, csh handle) {
    csh local_handle = handle;
    bool created_handle = false;
    if (local_handle == 0) {
        if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &local_handle) != CS_ERR_OK) {
            return -1;
        }
        created_handle = true;
    }

    cs_option(local_handle, CS_OPT_DETAIL, CS_OPT_ON);

    size_t total_copied = 0;
    const uint8_t *current_ptr = src_fun;

    while (total_copied < limit) {
        cs_insn *insn;
        size_t count = cs_disasm(local_handle, current_ptr, limit - total_copied, (uint64_t)(uintptr_t)current_ptr, 1, &insn);
        if (count == 0) {
            break; // Failed to disassemble
        }

        if (!is_instruction_copyable(insn)) {
            cs_free(insn, count);
            break; // Found a non-copyable instruction
        }

        // Copy the instruction bytes
        memcpy(dst + total_copied, current_ptr, insn->size);
        total_copied += insn->size;
        current_ptr += insn->size;

        cs_free(insn, count);
    }

    if (created_handle) {
        cs_close(&local_handle);
    }

    return (int)total_copied;
};


/*
 * This is the default branch target for patched functions.
 * It does nothing and returns immediately.
 */
__attribute__((used, noinline)) void dummy_patch_hook(void) {
    return;
}

/*
 * This is the dummy return target for patched functions.
 * If the patch fails, execution might reach here, where
 * an error will be logged and the process will loop forever.
 */
__attribute__((used, noinline, noreturn)) void dummy_trampoline_return(void) {
    printf("Error: dummy_trampoline_return called! This indicates a patching error.\n");

    for(;;) {
    #if defined(__aarch64__) || defined(__arm64__)
        __asm__ volatile ("wfe");
    #else
        // On non-ARM targets, yield without special instructions
        usleep(1000);
    #endif
    }
}

/*
 * Assembles the trampoline starting at some address
 * (should be instruction aligned after the copied prologue).
 *
 * Copies the assembly template from tramp_template.S into tramp_base,
 * then patches its ADRP/ADD pairs to target the provided hook and return
 * addresses.
 */
void assemble_trampoline_at(uint8_t *tramp_base, uint64_t hook_address, uint64_t return_address) {

    const uint8_t *tmpl_start = TRAMPOLINE_START_AFTER_PROLOGUE;
    const uint8_t *tmpl_end = TRAMPOLINE_RETURN_ADD + 8; // add followed by 2 instructions of 4 bytes each
    size_t tmpl_size = (size_t)(tmpl_end - tmpl_start);

    // Copy template to destination
    memcpy(tramp_base, tmpl_start, tmpl_size);

    // Calculate offsets of patch points within the template
    size_t off_hook_adrp = (size_t)(TRAMPOLINE_INTERMEDIATE_ADRP - tmpl_start);
    size_t off_hook_add  = (size_t)(TRAMPOLINE_INTERMEDIATE_ADD  - tmpl_start);
    size_t off_ret_adrp  = (size_t)(TRAMPOLINE_RETURN_ADRP       - tmpl_start);
    size_t off_ret_add   = (size_t)(TRAMPOLINE_RETURN_ADD        - tmpl_start);

    // Patch hook ADRP/ADD
    uint64_t pc_hook_adrp = (uint64_t)(uintptr_t)(tramp_base + off_hook_adrp);
    uint32_t insn_hook_adrp = assemble_adrp_x16_page(pc_hook_adrp, hook_address);
    uint32_t insn_hook_add  = assemble_add_x16_pageoff(hook_address);
    *(uint32_t *)(tramp_base + off_hook_adrp) = insn_hook_adrp;
    *(uint32_t *)(tramp_base + off_hook_add)  = insn_hook_add;

    // Patch return ADRP/ADD
    uint64_t pc_ret_adrp = (uint64_t)(uintptr_t)(tramp_base + off_ret_adrp);
    uint32_t insn_ret_adrp = assemble_adrp_x16_page(pc_ret_adrp, return_address);
    uint32_t insn_ret_add  = assemble_add_x16_pageoff(return_address);
    *(uint32_t *)(tramp_base + off_ret_adrp) = insn_ret_adrp;
    *(uint32_t *)(tramp_base + off_ret_add)  = insn_ret_add;

    // Ensure the CPU sees the newly written instructions
    __builtin___clear_cache((char *)tramp_base, (char *)tramp_base + tmpl_size);
}

/*
 * Extracts the prologue from a function, copies it to a trampoline,
 * and patches the original function to jump to the trampoline.
 *
 * Returns bytes copied to the trampoline, or -1 on error.
 */
int patch_function_with_trampoline(void *target_function, void *trampoline_buffer, void *hook_function) {

    // first, copy the prologue
    const size_t max_prologue_size = 32; // Arbitrary limit for prologue
    int copied_bytes = copy_instructions((uint8_t *)trampoline_buffer, (const uint8_t *)target_function, max_prologue_size, (csh)0);

    if (copied_bytes <= 0) {
        return -1; // Error copying prologue
    }

    // calculate the "return" address for the trampoline
    uint64_t return_address = (uint64_t)(uintptr_t)target_function + (uint64_t)copied_bytes;

    // assemble the trampoline
    assemble_trampoline_at((uint8_t *)trampoline_buffer + copied_bytes, (uint64_t)(uintptr_t)hook_function, return_address);

    // now patch the original function to jump to the trampoline
    uint64_t target_address = (uint64_t)(uintptr_t)target_function;
    uint64_t tramp_address = (uint64_t)(uintptr_t)trampoline_buffer;
    uint32_t adrp_insn = assemble_adrp_x16_page(target_address, tramp_address);
    uint32_t add_insn  = assemble_add_x16_pageoff(tramp_address);
    uint32_t br_insn   = 0xD61F0200u | (16u << 5); // BR X16

    // write the patch instructions
    uint8_t *patch_ptr = (uint8_t *)(uintptr_t)target_function;
    *(uint32_t *)(patch_ptr)       = adrp_insn;
    *(uint32_t *)(patch_ptr + 4)   = add_insn;
    *(uint32_t *)(patch_ptr + 8)   = br_insn;

    // clear instruction cache for the patched area
    __builtin___clear_cache((char *)patch_ptr, (char *)patch_ptr + 12);
    return copied_bytes;
}

/*
 * Internal helper to modify protections with control over set_maximum.
 */
static kern_return_t vm_protect_pages(void *address, size_t size, boolean_t set_max, vm_prot_t new_prot) {
    mach_port_t task = mach_task_self();
    mach_vm_address_t addr = (mach_vm_address_t)(uintptr_t)address;
    mach_vm_size_t sz = (mach_vm_size_t)size;

    mach_vm_address_t page_start = PAGE_RANGE_START(addr);
    mach_vm_size_t page_size = PAGE_RANGE_SIZE(addr, sz);

    return vm_protect(task, page_start, page_size, set_max, new_prot);
}

/*
 * Modifies the page protections for a memory region.
 * (Compat wrapper: does not change maximum protections.)
 */
kern_return_t modify_page_protections(void *address, size_t size, vm_prot_t new_prot) {
    return vm_protect_pages(address, size, FALSE, new_prot);
}

/*
 * Sets up page protections for patching instructions.
 * Given a starting address and a number of bytes, makes
 * the memory region readable and writable.
 */
int prepare_protections_for_patching(void *address, size_t size) {
    // On Apple platforms, W^X forbids simultaneous W+X. Make the page RW (not RXW),
    // but first widen the maximum protections so WRITE is allowed on text pages.
    // Include VM_PROT_COPY to allow COW on file-backed pages like __TEXT.
    kern_return_t kr = vm_protect_pages(address, size, TRUE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS && kr != KERN_INVALID_ARGUMENT) {
        // Some kernels may not allow changing maximum; continue to try current anyway.
        // If it still fails below, we will report the error.
    }

    kr = vm_protect_pages(address, size, FALSE, (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY));
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Error: make_page_rw failed with %d\n", kr);
        return -1;
    }
    return 0;
}

/*
 * Restores page protections after patching.
 * Given a starting address and a number of bytes, makes
 * the memory region read and execute only.
 */
int restore_protections_after_patching(void *address, size_t size) {
    kern_return_t kr = modify_page_protections(address, size, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Error: make_page_rx failed with %d\n", kr);
        return -1;
    }
    return 0;
}

static inline size_t page_align_up(size_t sz) {
    size_t ps = PAGE_SIZE_BYTES;
    return (sz + (ps - 1)) & ~(ps - 1);
}

size_t trampoline_template_size(void) {
    const uint8_t *tmpl_start = TRAMPOLINE_START_AFTER_PROLOGUE;
    const uint8_t *tmpl_end = TRAMPOLINE_RETURN_ADD + 8; // ADD + BR
    return (size_t)(tmpl_end - tmpl_start);
}

size_t trampoline_recommended_slot_size(void) {
    // Prologue typically small; add headroom for safety.
    return trampoline_template_size() + 64; // 64 bytes for copied prologue & alignment slop
}

static inline void jit_write_allow(void) {
#if defined(__APPLE__) && defined(MAP_JIT)
    pthread_jit_write_protect_np(0);
#else
    (void)0;
#endif
}

static inline void jit_write_deny(void) {
#if defined(__APPLE__) && defined(MAP_JIT)
    pthread_jit_write_protect_np(1);
#else
    (void)0;
#endif
}

int trampoline_bank_init(trampoline_bank_t *bank, size_t capacity, size_t per_trampoline_size) {
    if (!bank || capacity == 0) {
        errno = EINVAL;
        return -1;
    }

    if (per_trampoline_size == 0) {
        per_trampoline_size = trampoline_recommended_slot_size();
    }

    // ensure instruction alignment (4 bytes) and a minimum size
    if (per_trampoline_size < trampoline_template_size() + 32) {
        per_trampoline_size = trampoline_template_size() + 32;
    }
    per_trampoline_size = (per_trampoline_size + 3) & ~((size_t)3);

    size_t region_size = page_align_up(per_trampoline_size * capacity);

    int prot = PROT_READ | PROT_EXEC;
    int flags = MAP_PRIVATE | MAP_ANON;
#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif
#if defined(MAP_JIT)
    flags |= MAP_JIT;
#else
    // Fallback to RWX if MAP_JIT unavailable; caller should ensure safety.
    prot |= PROT_WRITE;
#endif

    void *region = mmap(NULL, region_size, prot, flags, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap for trampoline bank failed");
        return -1;
    }

    trampoline_info_t *infos = (trampoline_info_t *)calloc(capacity, sizeof(trampoline_info_t));
    if (!infos) {
        munmap(region, region_size);
        return -1;
    }

    bank->region = (uint8_t *)region;
    bank->region_size = region_size;
    bank->per_trampoline_size = per_trampoline_size;
    bank->capacity = capacity;
    bank->count = 0;
    bank->infos = infos;
    return 0;
}

void trampoline_bank_deinit(trampoline_bank_t *bank) {
    if (!bank) return;
    if (bank->region) {
        munmap(bank->region, bank->region_size);
    }
    if (bank->infos) {
        free(bank->infos);
    }
    memset(bank, 0, sizeof(*bank));
}

void *trampoline_bank_alloc_slot(trampoline_bank_t *bank, size_t required_size, size_t *out_index) {
    if (!bank || !bank->region || bank->count >= bank->capacity) {
        return NULL;
    }
    if (required_size > bank->per_trampoline_size) {
        return NULL;
    }

    size_t idx = bank->count; // reserve the next slot
    uint8_t *slot = bank->region + idx * bank->per_trampoline_size;
    if (out_index) *out_index = idx;
    return slot;
}

int trampoline_bank_install(trampoline_bank_t *bank, void *target_function, void *hook_function, size_t *out_index) {
    if (!bank || !bank->region || !target_function || !hook_function) {
        return -1;
    }
    if (bank->count >= bank->capacity) {
        fprintf(stderr, "No more trampoline slots available (capacity=%zu)\n", bank->capacity);
        return -1;
    }

    // Measure required prologue size without writing to the bank yet
    const size_t max_prologue = 32; // must match usage in patch_function_with_trampoline
    uint8_t scratch[max_prologue];
    int prologue_bytes = copy_instructions(scratch, (const uint8_t *)target_function, max_prologue, 0);
    if (prologue_bytes <= 0) {
        fprintf(stderr, "Failed to analyze target prologue\n");
        return -1;
    }

    size_t need = (size_t)prologue_bytes + trampoline_template_size();
    size_t idx = 0;
    uint8_t *slot = (uint8_t *)trampoline_bank_alloc_slot(bank, need, &idx);
    if (!slot) {
        fprintf(stderr, "Trampoline slot too small (need=%zu, slot=%zu)\n", need, bank->per_trampoline_size);
        return -1;
    }

    // Allow writing to trampoline slot and target function while patching
    // 1) Make the trampoline slot writable (it is RX by default when MAP_JIT is used)
    //    Widen maximum protections first to ensure WRITE is allowed.
    (void)vm_protect_pages(slot, need, TRUE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (vm_protect_pages(slot, need, FALSE, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) {
        fprintf(stderr, "Error: could not make trampoline slot RW\n");
        return -1;
    }

    // 2) Temporarily make target text writable for the 12-byte patch sequence
    int rc = 0;
    if (prepare_protections_for_patching(target_function, 12) != 0) {
        // restore slot back to RX before returning
        (void)vm_protect_pages(slot, need, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
        return -1;
    }

    // 3) Write trampoline body and patch the target
    jit_write_allow();
    int copied = patch_function_with_trampoline(target_function, slot, hook_function);
    jit_write_deny();

    // 4) Restore protections
    if (restore_protections_after_patching(target_function, 12) != 0) {
        rc = -1; // continue to set metadata only if previous steps were OK
    }

    (void)vm_protect_pages(slot, need, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    if (copied <= 0) {
        return -1;
    }

    // Record metadata and advance the count
    trampoline_info_t *info = &bank->infos[idx];
    info->target_function = target_function;
    info->hook_function = hook_function;
    info->trampoline = slot;
    info->prologue_bytes = (size_t)copied;
    info->active = true;
    bank->count = idx + 1;

    if (out_index) *out_index = idx;
    return rc;
}
