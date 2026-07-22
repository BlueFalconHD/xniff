#include <xniff/patch.h>

#include <mach/mach_vm.h>
#include <stdio.h>
#include <unistd.h>

static kern_return_t vm_protect_pages_task(mach_port_t task,
                                          mach_vm_address_t addr,
                                          size_t size,
                                          boolean_t set_max,
                                          vm_prot_t new_prot) {
    mach_vm_size_t sz = (mach_vm_size_t)size;
    mach_vm_address_t page_start = PAGE_RANGE_START(addr);
    mach_vm_size_t page_size = PAGE_RANGE_SIZE(addr, sz);
    return vm_protect(task, page_start, page_size, set_max, new_prot);
}

kern_return_t modify_page_protections_task(mach_port_t task, mach_vm_address_t address, size_t size,
                                          vm_prot_t new_prot) {
    return vm_protect_pages_task(task, address, size, FALSE, new_prot);
}

int prepare_protections_for_patching_task(mach_port_t task, mach_vm_address_t address, size_t size) {
    // Do not mutate maximum protections here: lowering max to RW can make a later
    // RX transition impossible on some maps. Only request current RW protections.
    kern_return_t kr = vm_protect_pages_task(task, address, size, FALSE,
                                             (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY));
    if (kr != KERN_SUCCESS) {
        // Some regions reject VM_PROT_COPY; try plain RW as fallback.
        kr = vm_protect_pages_task(task, address, size, FALSE,
                                   (VM_PROT_READ | VM_PROT_WRITE));
    }
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Error: remote make_page_rw failed with %d\n", kr);
        return -1;
    }
    return 0;
}

int restore_protections_after_patching_task(mach_port_t task, mach_vm_address_t address, size_t size) {
    // First try changing current protections only.
    kern_return_t kr = modify_page_protections_task(task, address, size,
                                                    (VM_PROT_READ | VM_PROT_EXECUTE));
    if (kr != KERN_SUCCESS) {
        // If current RX fails due max-prot constraints, try widening max to RX, then apply RX.
        kr = vm_protect_pages_task(task, address, size, TRUE,
                                   (VM_PROT_READ | VM_PROT_EXECUTE));
        if (kr == KERN_SUCCESS) {
            kr = modify_page_protections_task(task, address, size,
                                              (VM_PROT_READ | VM_PROT_EXECUTE));
        }
    }
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Error: remote make_page_rx failed with %d\n", kr);
        return -1;
    }
    return 0;
}
