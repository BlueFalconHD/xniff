#ifndef XNIFF_PATCH_H
#define XNIFF_PATCH_H

#include <mach/mach.h>
#include <stddef.h>
#include <unistd.h>

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

kern_return_t modify_page_protections_task(mach_port_t task, mach_vm_address_t address, size_t size,
                                          vm_prot_t new_prot);
int prepare_protections_for_patching_task(mach_port_t task, mach_vm_address_t address, size_t size);
int restore_protections_after_patching_task(mach_port_t task, mach_vm_address_t address, size_t size);

#endif /* XNIFF_PATCH_H */
