#ifndef ASSEMBLER_H
#define ASSEMBLER_H

#include <stdint.h>

// Encodes ADRP X16, target@PAGE.
uint32_t assemble_adrp_x16_page(uint64_t pc, uint64_t target_address);

// Generic ADRP that accepts any X register (0-30).
uint32_t assemble_adrp_reg_page(uint32_t reg, uint64_t pc, uint64_t target_address);

// Encodes ADD X16, X16, target@PAGEOFF.
uint32_t assemble_add_x16_pageoff(uint64_t target_address);

// Generic ADD immediate variant for any X register (dest=src=reg).
uint32_t assemble_add_reg_pageoff(uint32_t reg, uint64_t target_address);

// Encodes BR X16.
uint32_t assemble_br_x16(void);

#endif // ASSEMBLER_H
