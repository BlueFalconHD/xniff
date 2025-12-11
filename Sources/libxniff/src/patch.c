#include <xniff/patch.h>
#include "assembler.h"
#include <pthread.h>


// Forward declarations for helpers used before their definitions
static int remote_copy_prologue_bytes(mach_port_t task, mach_vm_address_t target_function, uint8_t *out_buf, size_t max_bytes);
kern_return_t vm_protect_pages_task(mach_port_t task, mach_vm_address_t addr, size_t size, boolean_t set_max, vm_prot_t new_prot);
int prepare_protections_for_patching_task(mach_port_t task, mach_vm_address_t address, size_t size);
int restore_protections_after_patching_task(mach_port_t task, mach_vm_address_t address, size_t size);


// Returns false for instructions that rely on PC-relative state or branch semantics.
// Prevents copying instructions that would misbehave once relocated.
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

// Copies instructions until the limit is hit or a non-copyable instruction appears.
// Returns the number of bytes copied and can reuse a caller provided Capstone handle.
// Handy for lifting a prologue into a trampoline buffer.
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
            // Capstone may not recognize some arm64e PAC instructions (e.g., PACIBSP/AUTIBSP).
            // Fallback: conservatively copy 4 bytes and continue, up to the requested limit.
            // This keeps us progressing through typical prologues that start with PAC + stack frame.
            if ((limit - total_copied) >= 4) {
                memcpy(dst + total_copied, current_ptr, 4);
                total_copied += 4;
                current_ptr += 4;
                continue;
            }
            break; // not enough bytes left to safely copy
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


// Default branch target for patched functions; acts as a safe no-op.
__attribute__((used, noinline)) void dummy_patch_hook(void) {
    return;
}

// Dummy return target used if a patch fails and execution falls through.
// Logs the failure and then parks the thread forever.
__attribute__((used, noinline, noreturn)) void dummy_trampoline_return(void) {
    printf("Error: dummy_trampoline_return called! This indicates a patching error.\n");

    for (;;) {
        __asm__ volatile ("wfe");
    }
}

// Builds a trampoline directly in the provided buffer after the copied prologue.
// Copies the template bytes and patches the ADRP/ADD pairs to point at the hook,
// the resume address, and any optional reload target.
void assemble_trampoline_at(uint8_t *tramp_base, uint64_t hook_address, uint64_t return_address,
                            int reload_reg, uint64_t reload_target) {

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
    size_t off_reload_adrp = (size_t)(TRAMPOLINE_RELOAD_ADRP     - tmpl_start);
    size_t off_reload_add  = (size_t)(TRAMPOLINE_RELOAD_ADD      - tmpl_start);

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

    // Optionally re-materialize a relocated ADRP/ADD pair for a general register
    if (reload_reg >= 0 && reload_reg <= 30) {
        uint64_t pc_reload_adrp = (uint64_t)(uintptr_t)(tramp_base + off_reload_adrp);
        uint32_t insn_reload_adrp = assemble_adrp_reg_page((uint32_t)reload_reg, pc_reload_adrp, reload_target);
        uint32_t insn_reload_add  = assemble_add_reg_pageoff((uint32_t)reload_reg, reload_target);
        *(uint32_t *)(tramp_base + off_reload_adrp) = insn_reload_adrp;
        *(uint32_t *)(tramp_base + off_reload_add)  = insn_reload_add;
    }

    // Ensure the CPU sees the newly written instructions
    __builtin___clear_cache((char *)tramp_base, (char *)tramp_base + tmpl_size);
}

// Builds a trampoline in a local buffer while calculating ADRP immediates as if it ran remotely.
// Needed for remote patching because ADRP encodes deltas from the instruction's PC.
static void assemble_trampoline_at_with_remote_pc(uint8_t *tramp_local_base,
                                                  uint64_t tramp_remote_base,
                                                  uint64_t hook_address,
                                                  uint64_t return_address,
                                                  int reload_reg,
                                                  uint64_t reload_target) {
    const uint8_t *tmpl_start = TRAMPOLINE_START_AFTER_PROLOGUE;
    const uint8_t *tmpl_end   = TRAMPOLINE_RETURN_ADD + 8; // add followed by 2 instructions of 4 bytes each
    size_t tmpl_size = (size_t)(tmpl_end - tmpl_start);

    // Copy template into local destination buffer
    memcpy(tramp_local_base, tmpl_start, tmpl_size);

    // Calculate offsets of patch points within the template
    size_t off_hook_adrp = (size_t)(TRAMPOLINE_INTERMEDIATE_ADRP - tmpl_start);
    size_t off_hook_add  = (size_t)(TRAMPOLINE_INTERMEDIATE_ADD  - tmpl_start);
    size_t off_ret_adrp  = (size_t)(TRAMPOLINE_RETURN_ADRP       - tmpl_start);
    size_t off_ret_add   = (size_t)(TRAMPOLINE_RETURN_ADD        - tmpl_start);
    size_t off_reload_adrp = (size_t)(TRAMPOLINE_RELOAD_ADRP     - tmpl_start);
    size_t off_reload_add  = (size_t)(TRAMPOLINE_RELOAD_ADD      - tmpl_start);

    // Compute PCs as they will be in the remote process
    uint64_t pc_hook_adrp = (uint64_t)(tramp_remote_base + off_hook_adrp);
    uint64_t pc_ret_adrp  = (uint64_t)(tramp_remote_base + off_ret_adrp);

    // Patch hook ADRP/ADD using remote PCs
    uint32_t insn_hook_adrp = assemble_adrp_x16_page(pc_hook_adrp, hook_address);
    uint32_t insn_hook_add  = assemble_add_x16_pageoff(hook_address);
    *(uint32_t *)(tramp_local_base + off_hook_adrp) = insn_hook_adrp;
    *(uint32_t *)(tramp_local_base + off_hook_add)  = insn_hook_add;

    // Patch return ADRP/ADD using remote PCs
    uint32_t insn_ret_adrp = assemble_adrp_x16_page(pc_ret_adrp, return_address);
    uint32_t insn_ret_add  = assemble_add_x16_pageoff(return_address);
    *(uint32_t *)(tramp_local_base + off_ret_adrp) = insn_ret_adrp;
    *(uint32_t *)(tramp_local_base + off_ret_add)  = insn_ret_add;

    // Optionally re-materialize ADRP/ADD for a general-purpose register
    if (reload_reg >= 0 && reload_reg <= 30) {
        uint64_t pc_reload_adrp = tramp_remote_base + off_reload_adrp;
        uint32_t insn_reload_adrp = assemble_adrp_reg_page((uint32_t)reload_reg, pc_reload_adrp, reload_target);
        uint32_t insn_reload_add  = assemble_add_reg_pageoff((uint32_t)reload_reg, reload_target);
        *(uint32_t *)(tramp_local_base + off_reload_adrp) = insn_reload_adrp;
        *(uint32_t *)(tramp_local_base + off_reload_add)  = insn_reload_add;
    }

    // Ensure the CPU sees the newly written instructions (for local buffer too)
    __builtin___clear_cache((char *)tramp_local_base, (char *)tramp_local_base + tmpl_size);
}

static size_t xtrampoline_template_size(void) {
    const uint8_t *tmpl_start = XTRAMP_START_AFTER_PROLOGUE;
    const uint8_t *tmpl_end   = XTRAMP_END;
    return (size_t)(tmpl_end - tmpl_start);
}

static void assemble_xtrampoline_at_with_remote_pc(uint8_t *tramp_local_base,
                                                   uint64_t tramp_remote_base,
                                                   uint64_t entry_hook,
                                                   uint64_t return_address,
                                                   uint64_t exit_hook,
                                                   uint64_t ctx_base_remote) {
    const uint8_t *tmpl_start = XTRAMP_START_AFTER_PROLOGUE;
    const uint8_t *tmpl_end   = XTRAMP_END;
    size_t tmpl_size = (size_t)(tmpl_end - tmpl_start);

    memcpy(tramp_local_base, tmpl_start, tmpl_size);

    // Offsets to patch points
    size_t off_hook_adrp   = (size_t)(XTRAMP_HOOK_ADRP   - tmpl_start);
    size_t off_hook_add    = (size_t)(XTRAMP_HOOK_ADD    - tmpl_start);
    size_t off_ctx_adrp    = (size_t)(XTRAMP_CTX_ADRP    - tmpl_start);
    size_t off_ctx_add     = (size_t)(XTRAMP_CTX_ADD     - tmpl_start);
    size_t off_res_adrp    = (size_t)(XTRAMP_RESUME_ADRP - tmpl_start);
    size_t off_res_add     = (size_t)(XTRAMP_RESUME_ADD  - tmpl_start);
    size_t off_exitlr_adrp = (size_t)(XTRAMP_EXITLR_ADRP - tmpl_start);
    size_t off_exitlr_add  = (size_t)(XTRAMP_EXITLR_ADD  - tmpl_start);
    size_t off_ret_adrp    = (size_t)(XTRAMP_RETURN_ADRP - tmpl_start);
    size_t off_ret_add     = (size_t)(XTRAMP_RETURN_ADD  - tmpl_start);
    size_t off_exit_ctx_adrp = (size_t)(XTRAMP_EXIT_CTX_ADRP - tmpl_start);
    size_t off_exit_ctx_add  = (size_t)(XTRAMP_EXIT_CTX_ADD  - tmpl_start);
    size_t off_exhook_adrp = (size_t)(XTRAMP_EXIT_HOOK_ADRP - tmpl_start);
    size_t off_exhook_add  = (size_t)(XTRAMP_EXIT_HOOK_ADD  - tmpl_start);

    // Compute remote PCs for ADRP calculation
    uint64_t pc_hook_adrp   = tramp_remote_base + off_hook_adrp;
    uint64_t pc_ctx_adrp    = tramp_remote_base + off_ctx_adrp;
    uint64_t pc_res_adrp    = tramp_remote_base + off_res_adrp;
    uint64_t pc_exitlr_adrp = tramp_remote_base + off_exitlr_adrp;
    uint64_t pc_ret_adrp    = tramp_remote_base + off_ret_adrp;
    uint64_t pc_exit_ctx_adrp = tramp_remote_base + off_exit_ctx_adrp;
    uint64_t pc_exhook_adrp = tramp_remote_base + off_exhook_adrp;

    // Patch entry hook
    uint32_t insn_hook_adrp = assemble_adrp_x16_page(pc_hook_adrp, entry_hook);
    uint32_t insn_hook_add  = assemble_add_x16_pageoff(entry_hook);
    *(uint32_t *)(tramp_local_base + off_hook_adrp) = insn_hook_adrp;
    *(uint32_t *)(tramp_local_base + off_hook_add)  = insn_hook_add;

    // Patch context base (both entry and exit sides)
    // Context base uses X9 in the template
    uint32_t insn_ctx_adrp = assemble_adrp_reg_page(9u, pc_ctx_adrp, ctx_base_remote);
    uint32_t insn_ctx_add  = assemble_add_reg_pageoff(9u, ctx_base_remote);
    *(uint32_t *)(tramp_local_base + off_ctx_adrp) = insn_ctx_adrp;
    *(uint32_t *)(tramp_local_base + off_ctx_add)  = insn_ctx_add;
    // Exit side also recomputes context base into X9
    uint32_t insn_exit_ctx_adrp = assemble_adrp_reg_page(9u, pc_exit_ctx_adrp, ctx_base_remote);
    uint32_t insn_exit_ctx_add  = assemble_add_reg_pageoff(9u, ctx_base_remote);
    *(uint32_t *)(tramp_local_base + off_exit_ctx_adrp) = insn_exit_ctx_adrp;
    *(uint32_t *)(tramp_local_base + off_exit_ctx_add)  = insn_exit_ctx_add;

    // Patch resume PC (entry side store) and branch-return pair
    // Resume PC is stored from X15 in the template
    uint32_t insn_res_adrp = assemble_adrp_reg_page(15u, pc_res_adrp, return_address);
    uint32_t insn_res_add  = assemble_add_reg_pageoff(15u, return_address);
    *(uint32_t *)(tramp_local_base + off_res_adrp) = insn_res_adrp;
    *(uint32_t *)(tramp_local_base + off_res_add)  = insn_res_add;

    uint32_t insn_ret_adrp = assemble_adrp_x16_page(pc_ret_adrp, return_address);
    uint32_t insn_ret_add  = assemble_add_x16_pageoff(return_address);
    *(uint32_t *)(tramp_local_base + off_ret_adrp) = insn_ret_adrp;
    *(uint32_t *)(tramp_local_base + off_ret_add)  = insn_ret_add;

    // Patch exit stub address into the code path that writes LR
    uint64_t exit_stub_addr = tramp_remote_base + (uint64_t)(XTRAMP_EXIT_STUB - XTRAMP_START_AFTER_PROLOGUE);
    uint32_t insn_exitlr_adrp = assemble_adrp_x16_page(pc_exitlr_adrp, exit_stub_addr);
    uint32_t insn_exitlr_add  = assemble_add_x16_pageoff(exit_stub_addr);
    *(uint32_t *)(tramp_local_base + off_exitlr_adrp) = insn_exitlr_adrp;
    *(uint32_t *)(tramp_local_base + off_exitlr_add)  = insn_exitlr_add;

    // Patch exit hook
    // Allow exit_hook==0 to mean "no-op"; patch to an internal RET stub.
    if (exit_hook == 0) {
        exit_hook = tramp_remote_base + (uint64_t)(XTRAMP_NOOP - XTRAMP_START_AFTER_PROLOGUE);
    }
    uint32_t insn_exhook_adrp = assemble_adrp_x16_page(pc_exhook_adrp, exit_hook);
    uint32_t insn_exhook_add  = assemble_add_x16_pageoff(exit_hook);
    *(uint32_t *)(tramp_local_base + off_exhook_adrp) = insn_exhook_adrp;
    *(uint32_t *)(tramp_local_base + off_exhook_add)  = insn_exhook_add;

    __builtin___clear_cache((char *)tramp_local_base, (char *)tramp_local_base + tmpl_size);
}

int patch_function_with_exit_trampoline_task(mach_port_t task,
                                             mach_vm_address_t target_function,
                                             mach_vm_address_t trampoline_buffer,
                                             mach_vm_address_t entry_hook_function,
                                             mach_vm_address_t exit_hook_function,
                                             mach_vm_address_t ctx_slot_base) {
    const size_t max_prologue = 32;
    uint8_t local_prologue[64];
    if (sizeof(local_prologue) < max_prologue) return -1;
    int prologue_bytes = remote_copy_prologue_bytes(task, target_function, local_prologue, max_prologue);
    if (prologue_bytes <= 0) {
        fprintf(stderr, "[xniff] exit-tramp: failed to analyze prologue for 0x%llx\n",
                (unsigned long long)target_function);
        return -1;
    }
    if ((size_t)prologue_bytes < 12) {
        fprintf(stderr, "[xniff] exit-tramp: prologue too short/non-copyable (%d) at 0x%llx\n",
                prologue_bytes, (unsigned long long)target_function);
        return -1;
    }

    size_t need = (size_t)prologue_bytes + xtrampoline_template_size();

    kern_return_t krp = vm_protect_pages_task(task, trampoline_buffer, need, TRUE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (krp != KERN_SUCCESS) {
        fprintf(stderr, "[xniff] exit-tramp: vm_protect set_max RWX failed for slot 0x%llx len %zu (kr=%d)\n",
                (unsigned long long)trampoline_buffer, need, krp);
    }
    krp = vm_protect_pages_task(task, trampoline_buffer, need, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    if (krp != KERN_SUCCESS) {
        fprintf(stderr, "[xniff] exit-tramp: vm_protect RW failed for slot 0x%llx len %zu (kr=%d)\n",
                (unsigned long long)trampoline_buffer, need, krp);
        return -1;
    }
    if (prepare_protections_for_patching_task(task, target_function, 12) != 0) {
        fprintf(stderr, "[xniff] exit-tramp: prepare_protections_for_patching_task failed for target 0x%llx\n",
                (unsigned long long)target_function);
        (void)vm_protect_pages_task(task, trampoline_buffer, need, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
        return -1;
    }

    if ((size_t)prologue_bytes > sizeof(local_prologue)) return -1;
    kern_return_t kr = vm_write(task, trampoline_buffer,
                                (vm_offset_t)(uintptr_t)local_prologue,
                                (mach_msg_type_number_t)prologue_bytes);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[xniff] exit-tramp: vm_write prologue to 0x%llx failed (kr=%d)\n",
                (unsigned long long)trampoline_buffer, kr);
        return -1;
    }

    size_t tmpl_size = xtrampoline_template_size();
    uint8_t *tail = (uint8_t *)malloc(tmpl_size);
    if (!tail) return -1;

    uint64_t remote_tail_pc = (uint64_t)trampoline_buffer + (uint64_t)prologue_bytes;
    assemble_xtrampoline_at_with_remote_pc(tail, remote_tail_pc,
                                           (uint64_t)entry_hook_function,
                                           (uint64_t)target_function + (uint64_t)prologue_bytes,
                                           (uint64_t)exit_hook_function,
                                           (uint64_t)ctx_slot_base);

    kr = vm_write(task, trampoline_buffer + (mach_vm_address_t)prologue_bytes,
                  (vm_offset_t)(uintptr_t)tail, (mach_msg_type_number_t)tmpl_size);
    free(tail);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[xniff] exit-tramp: vm_write tail to 0x%llx failed (kr=%d)\n",
                (unsigned long long)(trampoline_buffer + (mach_vm_address_t)prologue_bytes), kr);
        return -1;
    }

    // Patch original entry with branch to trampoline
    uint64_t target_address = (uint64_t)target_function;
    uint64_t tramp_address = (uint64_t)trampoline_buffer;
    uint32_t adrp_insn = assemble_adrp_x16_page(target_address, tramp_address);
    uint32_t add_insn  = assemble_add_x16_pageoff(tramp_address);
    uint32_t br_insn   = 0xD61F0200u | (16u << 5);
    uint8_t patch_bytes[12];
    memcpy(patch_bytes + 0, &adrp_insn, 4);
    memcpy(patch_bytes + 4, &add_insn, 4);
    memcpy(patch_bytes + 8, &br_insn, 4);
    kr = vm_write(task, target_function, (vm_offset_t)(uintptr_t)patch_bytes, (mach_msg_type_number_t)sizeof(patch_bytes));
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[xniff] exit-tramp: vm_write patch to target 0x%llx failed (kr=%d)\n",
                (unsigned long long)target_function, kr);
        return -1;
    }

    (void)vm_protect_pages_task(task, trampoline_buffer, need, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    return prologue_bytes;
}

// Copies a function prologue into the given trampoline buffer and patches the entry.
// Returns the number of bytes relocated or -1 on failure.
int patch_function_with_trampoline(void *target_function, void *trampoline_buffer, void *hook_function) {

    // first, copy the prologue
    const size_t max_prologue_size = 32; // Arbitrary limit for prologue
    int copied_bytes = copy_instructions((uint8_t *)trampoline_buffer, (const uint8_t *)target_function, max_prologue_size, (csh)0);

    if (copied_bytes <= 0) {
        return -1; // Error copying prologue
    }
    // Require relocating at least the 12-byte patch window to ensure we don't skip
    // non-copyable instructions when returning past the entry patch.
    if ((size_t)copied_bytes < 12) {
        fprintf(stderr, "Refusing to patch: non-copyable within first 12 bytes (copied=%d)\n", copied_bytes);
        return -1;
    }

    // calculate the "return" address for the trampoline
    // We overwrite 12 bytes at the target (ADRP+ADD+BR). Ensure we resume after the patch window
    // at minimum.
    size_t patch_len = 12;
    size_t resume_off = copied_bytes < patch_len ? patch_len : (size_t)copied_bytes;
    uint64_t return_address = (uint64_t)(uintptr_t)target_function + (uint64_t)resume_off;

    // assemble the trampoline
    assemble_trampoline_at((uint8_t *)trampoline_buffer + copied_bytes,
                           (uint64_t)(uintptr_t)hook_function,
                           return_address,
                           -1, 0);

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

// Internal helper that exposes vm_protect with explicit set_max control for any task.
kern_return_t vm_protect_pages_task(mach_port_t task, mach_vm_address_t addr, size_t size, boolean_t set_max, vm_prot_t new_prot) {
    mach_vm_size_t sz = (mach_vm_size_t)size;
    mach_vm_address_t page_start = PAGE_RANGE_START(addr);
    mach_vm_size_t page_size = PAGE_RANGE_SIZE(addr, sz);
    return vm_protect(task, page_start, page_size, set_max, new_prot);
}

kern_return_t vm_protect_pages(void *address, size_t size, boolean_t set_max, vm_prot_t new_prot) {
    mach_port_t task = mach_task_self();
    mach_vm_address_t addr = (mach_vm_address_t)(uintptr_t)address;
    return vm_protect_pages_task(task, addr, size, set_max, new_prot);
}

// Convenience wrapper that switches current protections without touching max permissions.
kern_return_t modify_page_protections(void *address, size_t size, vm_prot_t new_prot) {
    return vm_protect_pages(address, size, FALSE, new_prot);
}

kern_return_t modify_page_protections_task(mach_port_t task, mach_vm_address_t address, size_t size, vm_prot_t new_prot) {
    return vm_protect_pages_task(task, address, size, FALSE, new_prot);
}

// Expands protections so the target range becomes writable for patching.
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

int prepare_protections_for_patching_task(mach_port_t task, mach_vm_address_t address, size_t size) {
    // Widen maximum protections so WRITE is allowed, then set RW (+COPY for COW text pages).
    kern_return_t kr = vm_protect_pages_task(task, address, size, TRUE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS && kr != KERN_INVALID_ARGUMENT) {
        // ignore and try current anyway
    }
    kr = vm_protect_pages_task(task, address, size, FALSE, (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY));
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Error: remote make_page_rw failed with %d\n", kr);
        return -1;
    }
    return 0;
}

// Restores patched code back to RX once writing is complete.
int restore_protections_after_patching(void *address, size_t size) {
    kern_return_t kr = modify_page_protections(address, size, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Error: make_page_rx failed with %d\n", kr);
        return -1;
    }
    return 0;
}

int restore_protections_after_patching_task(mach_port_t task, mach_vm_address_t address, size_t size) {
    kern_return_t kr = modify_page_protections_task(task, address, size, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Error: remote make_page_rx failed with %d\n", kr);
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
#if defined(MAP_JIT)
    pthread_jit_write_protect_np(0);
#else
    (void)0;
#endif
}

static inline void jit_write_deny(void) {
#if defined(MAP_JIT)
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

    bank->task = mach_task_self();
    bank->is_remote = false;
    bank->region = (uint8_t *)region;
    bank->region_size = region_size;
    bank->per_trampoline_size = per_trampoline_size;
    bank->capacity = capacity;
    bank->count = 0;
    bank->infos = infos;
    return 0;
}

int trampoline_bank_init_task(trampoline_bank_t *bank, mach_port_t task, size_t capacity, size_t per_trampoline_size) {
    if (!bank || capacity == 0) {
        errno = EINVAL;
        return -1;
    }
    if (per_trampoline_size == 0) {
        per_trampoline_size = trampoline_recommended_slot_size();
    }
    if (per_trampoline_size < trampoline_template_size() + 32) {
        per_trampoline_size = trampoline_template_size() + 32;
    }
    per_trampoline_size = (per_trampoline_size + 3) & ~((size_t)3);

    size_t region_size = page_align_up(per_trampoline_size * capacity);
    vm_address_t addr = 0;
    kern_return_t kr = vm_allocate(task, &addr, region_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "mach_vm_allocate for trampoline bank failed: %d\n", kr);
        return -1;
    }
    // set maximum to R/W/X and current to RX
    (void)vm_protect_pages_task(task, addr, region_size, TRUE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    (void)vm_protect_pages_task(task, addr, region_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    trampoline_info_t *infos = (trampoline_info_t *)calloc(capacity, sizeof(trampoline_info_t));
    if (!infos) {
        vm_deallocate(task, addr, region_size);
        return -1;
    }

    bank->task = task;
    bank->is_remote = true;
    bank->region = (uint8_t *)(uintptr_t)addr;
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
        if (bank->is_remote) {
            vm_deallocate(bank->task, (mach_vm_address_t)(uintptr_t)bank->region, bank->region_size);
        } else {
            munmap(bank->region, bank->region_size);
        }
    }
    // Attempt to free any per-slot context regions for exit mode
    if (bank->infos && bank->is_remote) {
        for (size_t i = 0; i < bank->capacity; i++) {
            if (bank->infos[i].active && bank->infos[i].ctx_base && bank->infos[i].ctx_size) {
                vm_deallocate(bank->task, (mach_vm_address_t)(uintptr_t)bank->infos[i].ctx_base,
                              (mach_vm_size_t)bank->infos[i].ctx_size);
                bank->infos[i].ctx_base = NULL;
                bank->infos[i].ctx_size = 0;
            }
        }
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
    if ((size_t)prologue_bytes < 12) {
        fprintf(stderr, "Refusing to patch: non-copyable within first 12 bytes (copied=%d)\n", prologue_bytes);
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

static int remote_copy_prologue_bytes(mach_port_t task, mach_vm_address_t target_function, uint8_t *out_buf, size_t max_bytes) {
    vm_size_t out_sz = 0;
    kern_return_t kr = vm_read_overwrite(task, target_function, max_bytes,
                                              (mach_vm_address_t)(uintptr_t)out_buf, &out_sz);
    if (kr != KERN_SUCCESS || out_sz == 0) {
        return -1;
    }
    int copied = copy_instructions(out_buf, out_buf, (size_t)out_sz, 0);
    return copied;
}

int patch_function_with_trampoline_task(mach_port_t task,
                                        mach_vm_address_t target_function,
                                        mach_vm_address_t trampoline_buffer,
                                        mach_vm_address_t hook_function) {
    const size_t max_prologue_size = 32;
    uint8_t prologue[max_prologue_size];
    int copied_bytes = remote_copy_prologue_bytes(task, target_function, prologue, max_prologue_size);
    if (copied_bytes <= 0) {
        return -1;
    }
    if ((size_t)copied_bytes < 12) {
        fprintf(stderr, "Refusing to patch remote target: non-copyable within first 12 bytes (copied=%d)\n", copied_bytes);
        return -1;
    }

    // write prologue copy into trampoline slot
    kern_return_t kr = vm_write(task, trampoline_buffer, (vm_offset_t)(uintptr_t)prologue, (mach_msg_type_number_t)copied_bytes);
    if (kr != KERN_SUCCESS) {
        return -1;
    }

    // Ensure we resume at least after the 12-byte patch window to avoid loops.
    size_t patch_len2 = 12;
    size_t resume_off2 = (size_t)copied_bytes < patch_len2 ? patch_len2 : (size_t)copied_bytes;
    uint64_t return_address = (uint64_t)target_function + (uint64_t)resume_off2;
    size_t tmpl_size = trampoline_template_size();
    uint8_t *tail = (uint8_t *)malloc(tmpl_size);
    if (!tail) return -1;

    // Detect a leading ADRP/ADD pair so we can re-materialize it before returning.
    int reload_reg = -1;
    uint64_t reload_target = 0;
    do {
        uint8_t head[8] = {0};
        vm_size_t out_sz = 0;
        if (vm_read_overwrite(task, target_function, sizeof(head), (mach_vm_address_t)(uintptr_t)head, &out_sz) != KERN_SUCCESS || out_sz < sizeof(head)) {
            break;
        }
        uint32_t insn0 = *(const uint32_t *)(head + 0);
        uint32_t insn1 = *(const uint32_t *)(head + 4);
        // Detect ADRP (0b10000 opcode in top bits)
        if ( (insn0 & 0x9F000000u) != 0x90000000u ) break;
        uint32_t rd = (insn0 & 0x1Fu);
        uint32_t immlo = (insn0 >> 29) & 0x3u;
        uint32_t immhi = (insn0 >> 5) & 0x7FFFFu;
        int64_t imm21 = (int64_t)((immhi << 2) | immlo);
        // sign-extend 21-bit immediate
        if (imm21 & (1ll << 20)) {
            imm21 |= ~((1ll << 21) - 1);
        }
        uint64_t pc0 = (uint64_t)target_function; // PC of ADRP
        uint64_t base = (pc0 & ~0xFFFULL) + ((uint64_t)imm21 << 12);
        // Detect ADD (64-bit, immediate)
        if ( (insn1 & 0xFF000000u) != 0x91000000u ) break;
        uint32_t rd1 = (insn1 & 0x1Fu);
        uint32_t rn1 = (insn1 >> 5) & 0x1Fu;
        uint32_t imm12 = (insn1 >> 10) & 0xFFFu;
        uint32_t shift = (insn1 >> 22) & 0x3u; // 0 or 1 for LSL12
        if (rd1 != rn1 || rd1 != rd) break;
        if (shift > 1) break; // unexpected variant
        uint64_t add_off = (uint64_t)imm12 << (shift ? 12 : 0);
        reload_reg = (int)rd;
        reload_target = base + add_off;
    } while (0);

    // Assemble trampoline using the remote PC base where it will execute
    uint64_t remote_tail_pc = (uint64_t)trampoline_buffer + (uint64_t)copied_bytes;
    assemble_trampoline_at_with_remote_pc(tail, remote_tail_pc, (uint64_t)hook_function, return_address,
                                          reload_reg, reload_target);
    kr = vm_write(task, trampoline_buffer + (mach_vm_address_t)copied_bytes,
                       (vm_offset_t)(uintptr_t)tail, (mach_msg_type_number_t)tmpl_size);
    free(tail);
    if (kr != KERN_SUCCESS) {
        return -1;
    }

    // patch original: ADRP, ADD, BR
    uint64_t target_address = (uint64_t)target_function;
    uint64_t tramp_address = (uint64_t)trampoline_buffer;
    uint32_t adrp_insn = assemble_adrp_x16_page(target_address, tramp_address);
    uint32_t add_insn  = assemble_add_x16_pageoff(tramp_address);
    uint32_t br_insn   = 0xD61F0200u | (16u << 5);
    uint8_t patch_bytes[12];
    memcpy(patch_bytes + 0, &adrp_insn, 4);
    memcpy(patch_bytes + 4, &add_insn, 4);
    memcpy(patch_bytes + 8, &br_insn, 4);
    kr = vm_write(task, target_function, (vm_offset_t)(uintptr_t)patch_bytes, (mach_msg_type_number_t)sizeof(patch_bytes));
    if (kr != KERN_SUCCESS) {
        return -1;
    }
    return copied_bytes;
}

int trampoline_bank_install_task(trampoline_bank_t *bank,
                                 mach_vm_address_t target_function,
                                 mach_vm_address_t hook_function,
                                 size_t *out_index) {
    if (!bank || !bank->region || bank->count >= bank->capacity) {
        return -1;
    }
    if (!bank->is_remote) {
        // fall back to local install if not initialized for remote
        return trampoline_bank_install(bank, (void *)(uintptr_t)target_function, (void *)(uintptr_t)hook_function, out_index);
    }

    const size_t max_prologue = 32;
    uint8_t scratch[max_prologue];
    int prologue_bytes = remote_copy_prologue_bytes(bank->task, target_function, scratch, max_prologue);
    if (prologue_bytes <= 0) {
        fprintf(stderr, "Failed to analyze remote target prologue\n");
        return -1;
    }
    if ((size_t)prologue_bytes < 12) {
        fprintf(stderr, "Refusing to patch remote target: non-copyable within first 12 bytes (copied=%d)\n", prologue_bytes);
        return -1;
    }

    size_t need = (size_t)prologue_bytes + trampoline_template_size();
    size_t idx = 0;
    uint8_t *slot_ptr = (uint8_t *)trampoline_bank_alloc_slot(bank, need, &idx);
    if (!slot_ptr) {
        fprintf(stderr, "Remote trampoline slot too small (need=%zu, slot=%zu)\n", need, bank->per_trampoline_size);
        return -1;
    }
    mach_vm_address_t slot = (mach_vm_address_t)(uintptr_t)slot_ptr;

    // Make slot RW and target patchable
    (void)vm_protect_pages_task(bank->task, slot, need, TRUE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (vm_protect_pages_task(bank->task, slot, need, FALSE, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) {
        fprintf(stderr, "Error: could not make remote trampoline slot RW\n");
        return -1;
    }
    if (prepare_protections_for_patching_task(bank->task, target_function, 12) != 0) {
        (void)vm_protect_pages_task(bank->task, slot, need, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
        return -1;
    }

    int copied = patch_function_with_trampoline_task(bank->task, target_function, slot, hook_function);

    int rc = 0;
    if (restore_protections_after_patching_task(bank->task, target_function, 12) != 0) {
        rc = -1;
    }
    (void)vm_protect_pages_task(bank->task, slot, need, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    if (copied <= 0) {
        return -1;
    }

    trampoline_info_t *info = &bank->infos[idx];
    info->target_function = (void *)(uintptr_t)target_function;
    info->hook_function = (void *)(uintptr_t)hook_function;
    info->trampoline = (void *)(uintptr_t)slot;
    info->prologue_bytes = (size_t)copied;
    info->active = true;
    bank->count = idx + 1;
    if (out_index) *out_index = idx;
    return rc;
}

int trampoline_bank_install_task_with_exit(trampoline_bank_t *bank,
                                           mach_vm_address_t target_function,
                                           mach_vm_address_t entry_hook_function,
                                           mach_vm_address_t exit_hook_function,
                                           size_t *out_index) {
    if (!bank || !bank->region || bank->count >= bank->capacity) {
        return -1;
    }
    if (!bank->is_remote) {
        // Not supported in local mode for now.
        return -1;
    }

    const size_t max_prologue = 32;
    uint8_t scratch[max_prologue];
    int prologue_bytes = remote_copy_prologue_bytes(bank->task, target_function, scratch, max_prologue);
    if (prologue_bytes <= 0) {
        fprintf(stderr, "Failed to analyze remote target prologue\n");
        return -1;
    }
    if ((size_t)prologue_bytes < 12) {
        fprintf(stderr, "Refusing to patch remote target: non-copyable within first 12 bytes (copied=%d)\n", prologue_bytes);
        return -1;
    }

    size_t need = (size_t)prologue_bytes + xtrampoline_template_size();
    fprintf(stderr, "[xniff] bank-install exit: prologue=%d xtramp=%zu need=%zu slot_size=%zu\n",
            prologue_bytes, xtrampoline_template_size(), need, bank->per_trampoline_size);
    size_t idx = 0;
    uint8_t *slot_ptr = (uint8_t *)trampoline_bank_alloc_slot(bank, need, &idx);
    if (!slot_ptr) {
        fprintf(stderr, "Remote trampoline slot too small (need=%zu, slot=%zu)\n", need, bank->per_trampoline_size);
        return -1;
    }
    mach_vm_address_t slot = (mach_vm_address_t)(uintptr_t)slot_ptr;

    // Allocate per-slot context region (RW).
    // Context region layout per trampoline slot:
    // - 256 thread slots (indexed by low 8 bits of TPIDRRO_EL0)
    // - 256 bytes per thread slot (2 frames × 128B)
    // Total = 256 * 256 = 65536 bytes (64KB)
    const size_t ctx_per_slot = (256u * 256u);
    vm_address_t ctx_addr = 0;
    if (vm_allocate(bank->task, &ctx_addr, (vm_size_t)ctx_per_slot, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        fprintf(stderr, "Failed to allocate remote context slot\n");
        return -1;
    }

    // Make slot RW and target patchable
    (void)vm_protect_pages_task(bank->task, slot, need, TRUE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (vm_protect_pages_task(bank->task, slot, need, FALSE, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) {
        fprintf(stderr, "Error: could not make remote trampoline slot RW\n");
        vm_deallocate(bank->task, ctx_addr, (vm_size_t)ctx_per_slot);
        return -1;
    }
    if (prepare_protections_for_patching_task(bank->task, target_function, 12) != 0) {
        (void)vm_protect_pages_task(bank->task, slot, need, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
        vm_deallocate(bank->task, ctx_addr, (vm_size_t)ctx_per_slot);
        return -1;
    }

    int copied = patch_function_with_exit_trampoline_task(bank->task, target_function, slot,
                                                          entry_hook_function, exit_hook_function,
                                                          (mach_vm_address_t)ctx_addr);

    int rc = 0;
    if (restore_protections_after_patching_task(bank->task, target_function, 12) != 0) {
        rc = -1;
    }
    (void)vm_protect_pages_task(bank->task, slot, need, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    if (copied <= 0) {
        vm_deallocate(bank->task, ctx_addr, (vm_size_t)ctx_per_slot);
        return -1;
    }

    trampoline_info_t *info = &bank->infos[idx];
    info->target_function = (void *)(uintptr_t)target_function;
    info->hook_function = (void *)(uintptr_t)entry_hook_function;
    info->trampoline = (void *)(uintptr_t)slot;
    info->prologue_bytes = (size_t)copied;
    info->active = true;
    info->ctx_base = (void *)(uintptr_t)ctx_addr;
    info->ctx_size = ctx_per_slot;
    bank->count = idx + 1;
    if (out_index) *out_index = idx;
    return rc;
}
