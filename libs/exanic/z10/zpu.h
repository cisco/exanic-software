#ifndef EXANIC_Z10_ZPU_H
#define EXANIC_Z10_ZPU_H

/* Read a word from the CPLD's memory map */
uint32_t z10_zpu_read(exanic_t *exanic, uint32_t addr);

/* Write a word to the CPLD's memory map */
uint32_t z10_zpu_write(exanic_t *exanic, uint32_t addr, uint32_t value);

#endif /* EXANIC_Z10_ZPU_H */
