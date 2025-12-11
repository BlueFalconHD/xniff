#include "assembler.h"

// Encodes ADRP X16, target@PAGE.
uint32_t assemble_adrp_x16_page(uint64_t pc, uint64_t target_address) {
    int64_t pages = (int64_t)(target_address >> 12) - (int64_t)(pc >> 12);
    uint32_t immlo = (uint32_t)(pages & 0x3);
    uint32_t immhi = (uint32_t)((pages >> 2) & 0x7FFFF);
    return 0x90000000u | (immlo << 29) | (immhi << 5) | 16u;
}

// Generic ADRP for any X register (0-30).
uint32_t assemble_adrp_reg_page(uint32_t reg, uint64_t pc, uint64_t target_address) {
    if (reg > 30) reg &= 0x1F;
    int64_t pages = (int64_t)(target_address >> 12) - (int64_t)(pc >> 12);
    uint32_t immlo = (uint32_t)(pages & 0x3);
    uint32_t immhi = (uint32_t)((pages >> 2) & 0x7FFFF);
    return 0x90000000u | (immlo << 29) | (immhi << 5) | (reg & 0x1F);
}

// Encodes ADD X16, X16, target@PAGEOFF.
uint32_t assemble_add_x16_pageoff(uint64_t target_address) {
    uint32_t imm12 = (uint32_t)(target_address & 0xFFFu);
    return 0x91000000u | (imm12 << 10) | (16u << 5) | 16u;
}

// Generic ADD immediate for any X register with imm12 page offset.
uint32_t assemble_add_reg_pageoff(uint32_t reg, uint64_t target_address) {
    if (reg > 30) reg &= 0x1F;
    uint32_t imm12 = (uint32_t)(target_address & 0xFFFu);
    return 0x91000000u | (imm12 << 10) | ((reg & 0x1F) << 5) | (reg & 0x1F);
}

// Encodes BR X16.
uint32_t assemble_br_x16(void) {
    return 0xD61F0200u;
}
