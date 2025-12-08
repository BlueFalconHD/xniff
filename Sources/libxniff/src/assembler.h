#ifndef ASSEMBLER_H
#define ASSEMBLER_H

#include <stdint.h>

/*
 * Assembles an instruction in the form of
 * ADRP X16, _dummy_patch_hook@PAGE
 */
 uint32_t assemble_adrp_x16_page(uint64_t pc, uint64_t target_address);

/* Generic variants allowing any X register (0-30). */
uint32_t assemble_adrp_reg_page(uint32_t reg, uint64_t pc, uint64_t target_address);

 /*
  * Assembles an instruction in the form of
  * ADD X16, X16, _dummy_patch_hook@PAGEOFF
  */
uint32_t assemble_add_x16_pageoff(uint64_t target_address);

/* Generic ADD (immediate) variant for any X register (dest=src=reg). */
uint32_t assemble_add_reg_pageoff(uint32_t reg, uint64_t target_address);

/*
 * Assembles an instruction in the form of
 * BR X16
 */
uint32_t assemble_br_x16(void);

#endif /* ASSEMBLER_H */
