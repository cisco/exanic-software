#include "../exanic.h"
#include "../pcie_if.h"
#include "zpu.h"

/* Read a word from the CPLD's memory map */
uint32_t z10_zpu_read(exanic_t *exanic, uint32_t addr)
{
    uint32_t cmd, prev_ack;

    prev_ack = exanic->registers[REG_HW_INDEX(REG_HW_CPLD_ACK)];
    cmd = exanic->registers[REG_HW_INDEX(REG_HW_CPLD_CMD)];
    exanic->registers[REG_HW_INDEX(REG_HW_CPLD_DATA)] = addr;
    cmd = cmd ^ 4;      /* toggle the trigger bit */
    cmd = cmd & ~3;     /* CMD = 0 */
    exanic->registers[REG_HW_INDEX(REG_HW_CPLD_CMD)] = cmd;
    while (exanic->registers[REG_HW_INDEX(REG_HW_CPLD_ACK)] == prev_ack);

    return exanic->registers[REG_HW_INDEX(REG_HW_CPLD_DATA)];
}

/* Write a word to the CPLD's memory map */
uint32_t z10_zpu_write(exanic_t *exanic, uint32_t addr, uint32_t value)
{
    uint32_t cmd, prev_ack, prev_data;

    cmd = exanic->registers[REG_HW_INDEX(REG_HW_CPLD_CMD)];

    /* Set address and read */
    prev_ack = exanic->registers[REG_HW_INDEX(REG_HW_CPLD_ACK)];
    exanic->registers[REG_HW_INDEX(REG_HW_CPLD_DATA)] = addr;
    cmd = cmd ^ 4;      /* toggle the trigger bit */
    cmd = cmd & ~3;     /* CMD = 0 */
    exanic->registers[REG_HW_INDEX(REG_HW_CPLD_CMD)] = cmd;
    while (exanic->registers[REG_HW_INDEX(REG_HW_CPLD_ACK)] == prev_ack);

    prev_data = exanic->registers[REG_HW_INDEX(REG_HW_CPLD_DATA)];

    /* Write */
    prev_ack = exanic->registers[REG_HW_INDEX(REG_HW_CPLD_ACK)];
    exanic->registers[REG_HW_INDEX(REG_HW_CPLD_DATA)] = value;
    cmd = cmd ^ 4;          /* toggle the trigger bit */
    cmd = (cmd & ~3) | 1;   /* CMD = 1 */
    exanic->registers[REG_HW_INDEX(REG_HW_CPLD_CMD)] = cmd;
    while (exanic->registers[REG_HW_INDEX(REG_HW_CPLD_ACK)] == prev_ack);

    return prev_data;
}
