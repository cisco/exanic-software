#ifndef Z10_ZPU_H_F7EBEB9D8F8433FE43B72DDC3525CEAA
#define Z10_ZPU_H_F7EBEB9D8F8433FE43B72DDC3525CEAA

/* Read a word from the CPLD's memory map */
uint32_t z10_zpu_read(exanic_t *exanic, uint32_t addr);

/* Write a word to the CPLD's memory map */
uint32_t z10_zpu_write(exanic_t *exanic, uint32_t addr, uint32_t value);

#endif /* Z10_ZPU_H_F7EBEB9D8F8433FE43B72DDC3525CEAA */
