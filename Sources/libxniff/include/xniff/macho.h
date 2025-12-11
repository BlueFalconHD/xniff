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

/* Search for a symbol only within images whose file path contains the given substring. */
int xniff_find_symbol_in_image_path_contains(mach_port_t task,
                                            const char *path_substring,
                                            const char *symbol,
                                            mach_vm_address_t *out_addr);

/* Search for a symbol only within the image whose file path matches exactly. */
int xniff_find_symbol_in_image_exact_path(mach_port_t task,
                                          const char *exact_path,
                                          const char *symbol,
                                          mach_vm_address_t *out_addr);

/* Unconditionally print all dyld images in the target task (index, header, slide, type, path). */
int xniff_dump_task_images(mach_port_t task);

/* Return 1 if an image with an exact file path is present, 0 if not, -1 on error. */
int xniff_image_exists_exact(mach_port_t task, const char *exact_path);

/* Return 1 if any image path contains the substring, 0 if not, -1 on error. */
int xniff_image_exists_contains(mach_port_t task, const char *substring);

#endif /* XNIFF_MACHO_H */
