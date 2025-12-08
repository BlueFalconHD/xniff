#ifndef XNIFF_MACHO_H
#define XNIFF_MACHO_H

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <stdbool.h>

/* Find a Mach-O symbol's runtime address in a task. */
int xniff_find_symbol_in_task(mach_port_t task, const char *symbol, mach_vm_address_t *out_addr);

/* Search only the main executable image. */
int xniff_find_symbol_in_main_image(mach_port_t task, const char *symbol, mach_vm_address_t *out_addr);

#endif /* XNIFF_MACHO_H */
