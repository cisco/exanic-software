/**
 * ExaNIC Z10 specific logic for backwards compatibility
 * Copyright (C) 2011-2013 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/netdevice.h>
#include <linux/miscdevice.h>

#include "../../libs/exanic/pcie_if.h"
#include "../../libs/exanic/const.h"
#include "exanic.h"
#include "exanic-structs.h"

/* Read a word from the CPLD's memory map */
static uint32_t zpu_read(struct exanic *exanic, uint32_t addr)
{
    volatile uint32_t *registers = exanic_registers(exanic);
    uint32_t cmd, prev_ack;

    prev_ack = registers[REG_HW_INDEX(REG_HW_CPLD_ACK)];
    cmd = registers[REG_HW_INDEX(REG_HW_CPLD_CMD)];
    registers[REG_HW_INDEX(REG_HW_CPLD_DATA)] = addr;
    cmd = cmd ^ 4;      /* toggle the trigger bit */
    cmd = cmd & ~3;     /* CMD = 0 */
    registers[REG_HW_INDEX(REG_HW_CPLD_CMD)] = cmd;
    while (registers[REG_HW_INDEX(REG_HW_CPLD_ACK)] == prev_ack);

    return registers[REG_HW_INDEX(REG_HW_CPLD_DATA)];
}

/* Write a word to the CPLD's memory map */
static uint32_t zpu_write(struct exanic *exanic, uint32_t addr, uint32_t value)
{
    volatile uint32_t *registers = exanic_registers(exanic);
    uint32_t cmd, prev_ack, prev_data;

    cmd = registers[REG_HW_INDEX(REG_HW_CPLD_CMD)];

    /* Set address and read */
    prev_ack = registers[REG_HW_INDEX(REG_HW_CPLD_ACK)];
    registers[REG_HW_INDEX(REG_HW_CPLD_DATA)] = addr;
    cmd = cmd ^ 4;      /* toggle the trigger bit */
    cmd = cmd & ~3;     /* CMD = 0 */
    registers[REG_HW_INDEX(REG_HW_CPLD_CMD)] = cmd;
    while (registers[REG_HW_INDEX(REG_HW_CPLD_ACK)] == prev_ack);

    prev_data = registers[REG_HW_INDEX(REG_HW_CPLD_DATA)];

    /* Write */
    prev_ack = registers[REG_HW_INDEX(REG_HW_CPLD_ACK)];
    registers[REG_HW_INDEX(REG_HW_CPLD_DATA)] = value;
    cmd = cmd ^ 4;          /* toggle the trigger bit */
    cmd = (cmd & ~3) | 1;   /* CMD = 1 */
    registers[REG_HW_INDEX(REG_HW_CPLD_CMD)] = cmd;
    while (registers[REG_HW_INDEX(REG_HW_CPLD_ACK)] == prev_ack);

    return prev_data;
}

struct i2c_bus
{
    uint32_t zpu_reg;
    uint32_t sda_out_bit;
    uint32_t sda_in_bit;
    uint32_t clk_bit;
    uint32_t en_bit;
};

/* Lookup table for talking on the various I2C busses */
static const struct i2c_bus i2c_bus[] = {
    { 0x1434, 0x10, 0x10000, 0x1, 0x2 },    /* 0: SFP 0 */
    { 0x1434, 0x20, 0x20000, 0x1, 0x2 },    /* 1: SFP 1 */
    { 0x1434, 0x40, 0x40000, 0x1, 0x2 },    /* 2: SFP 2 */
    { 0x1434, 0x80, 0x80000, 0x1, 0x2 },    /* 3: SFP 3 */
    { 0x1430, 0x4, 0x10, 0x1, 0x2 },        /* 4: PHY 0 and 1 */
    { 0x1430, 0x8, 0x20, 0x1, 0x2 },        /* 5: PHY 2 and 3 */
};

static void setsda(struct exanic *exanic, int bus, int val)
{
    uint32_t reg = zpu_read(exanic, i2c_bus[bus].zpu_reg);
    if (val)
        reg = reg | i2c_bus[bus].sda_out_bit;
    else
        reg = reg & ~i2c_bus[bus].sda_out_bit;
    zpu_write(exanic, i2c_bus[bus].zpu_reg, reg);
}

static void setscl(struct exanic *exanic, int bus, int val)
{
    uint32_t reg = zpu_read(exanic, i2c_bus[bus].zpu_reg);
    if (val)
        reg = reg | i2c_bus[bus].clk_bit;
    else
        reg = reg & ~i2c_bus[bus].clk_bit;
    zpu_write(exanic, i2c_bus[bus].zpu_reg, reg);
}

static void setoutput(struct exanic *exanic, int bus, int en)
{
    uint32_t reg = zpu_read(exanic, i2c_bus[bus].zpu_reg);
    if (en)
        reg = reg | i2c_bus[bus].en_bit;
    else
        reg = reg & ~i2c_bus[bus].en_bit;
    zpu_write(exanic, i2c_bus[bus].zpu_reg, reg);
}

static int getsda(struct exanic *exanic, int bus)
{
    uint32_t reg = zpu_read(exanic, i2c_bus[bus].zpu_reg);
    return (reg & i2c_bus[bus].sda_in_bit) ? 1 : 0;
}

static void i2c_reset(struct exanic *exanic, int bus)
{
    int count = 0;
    setoutput(exanic, bus, 1);
    setscl(exanic, bus, 1);
    setsda(exanic, bus, 1);
    setoutput(exanic, bus, 0);
    while (getsda(exanic, bus) == 0 && count < 100)
    {
        setscl(exanic, bus, 0);
        setscl(exanic, bus, 1);
    }
    setoutput(exanic, bus, 1);
}

static void i2c_start(struct exanic *exanic, int bus)
{
    /* sda, scl are high */
    setsda(exanic, bus, 0);
    setscl(exanic, bus, 0);
}

static void i2c_repstart(struct exanic *exanic, int bus)
{
    /* scl is low */
    setsda(exanic, bus, 1);
    setscl(exanic, bus, 1);
    setsda(exanic, bus, 0);
    setscl(exanic, bus, 0);
}

static void i2c_stop(struct exanic *exanic, int bus)
{
    /* scl is low */
    setsda(exanic, bus, 0);
    setscl(exanic, bus, 1);
    setsda(exanic, bus, 1);
}

/* Returns non-zero if ack received, or 0 if the device did not ack */
static int i2c_outb(struct exanic *exanic, int bus, char data)
{
    int i, nak;

    /* scl is low */
    for (i = 7; i >= 0; i--)
    {
        setsda(exanic, bus, data & (1 << i));
        setscl(exanic, bus, 1);
        setscl(exanic, bus, 0);
    }
    setoutput(exanic, bus, 0);
    setsda(exanic, bus, 1);
    setscl(exanic, bus, 1);

    nak = getsda(exanic, bus);
    setscl(exanic, bus, 0);
    setoutput(exanic, bus, 1);
    /* scl is low */

    return !nak;
}

static char i2c_inb(struct exanic *exanic, int bus)
{
    int i;
    char data = 0;

    /* scl is low */
    setoutput(exanic, bus, 0);
    setsda(exanic, bus, 1);
    for (i = 7; i >= 0; i--)
    {
        setscl(exanic, bus, 1);
        if (getsda(exanic, bus))
            data |= (1 << i);
        setscl(exanic, bus, 0);
    }
    setoutput(exanic, bus, 1);
    /* scl is low */

    return data;
}

static int i2c_read(struct exanic *exanic, int bus, uint8_t devaddr,
                    uint8_t regaddr, char *buffer, size_t size)
{
    size_t i;

    i2c_reset(exanic, bus);
    i2c_start(exanic, bus);
    if (!i2c_outb(exanic, bus, devaddr) || !i2c_outb(exanic, bus, regaddr))
    {
        dev_err(exanic_dev(exanic), "no ack from device on I2C write\n");
        return -1;
    }
    for (i = 0; i < size; i++)
    {
        i2c_repstart(exanic, bus);
        if (!i2c_outb(exanic, bus, devaddr | 1))
        {
            dev_err(exanic_dev(exanic), "no ack from device on I2C write\n");
            return -1;
        }
        buffer[i] = i2c_inb(exanic, bus);
    }
    i2c_stop(exanic, bus);

    return 0;
}

static int i2c_write(struct exanic *exanic, int bus, uint8_t devaddr,
                     uint8_t regaddr, const char *buffer, size_t size)
{
    size_t i;

    i2c_reset(exanic, bus);
    i2c_start(exanic, bus);
    if (!i2c_outb(exanic, bus, devaddr) || !i2c_outb(exanic, bus, regaddr))
    {
        dev_err(exanic_dev(exanic), "no ack from device on I2C write\n");
        return -1;
    }
    for (i = 0; i < size; i++)
    {
        if (!i2c_outb(exanic, bus, buffer[i]))
        {
            dev_err(exanic_dev(exanic), "no ack from device on I2C write\n");
            return -1;
        }
    }
    i2c_stop(exanic, bus);

    return 0;
}

struct phy_i2c
{
    int bus;
    int devaddr;
};

/* Lookup I2C bus and slave addresses for the PHYs */
static struct phy_i2c phy_i2c[] = {
    { 4, 0x86 },    /* PHY 0 */
    { 4, 0x88 },    /* PHY 1 */
    { 5, 0x86 },    /* PHY 2 */
    { 5, 0x88 },    /* PHY 3 */
};

int exanic_z10_i2c_sfp_read(struct exanic *exanic, int port_number, uint8_t devaddr,
                            uint8_t regaddr, char *buffer, size_t size)
{
    /* SFPs are on busses 0-3 */
    int bus = port_number;

    return i2c_read(exanic, bus, devaddr, regaddr, buffer, size);
}

static int exanic_z10_i2c_phy_write(struct exanic *exanic, int port_number,
                                    uint8_t regaddr, char *buffer, size_t size)
{
    int bus = phy_i2c[port_number].bus;
    int devaddr = phy_i2c[port_number].devaddr;

    return i2c_write(exanic, bus, devaddr, regaddr, buffer, size);
}

enum {
    Z10_CPLD_SFP_CMD = 0x1434,
    Z10_TX_DIS_SFP0_BIT = 8,
};

int exanic_z10_poweron_port(struct exanic *exanic, unsigned port_number)
{
    uint32_t reg;

    /* Initialise the PHY */
    char zero = '\0';
    char init_regs[12] = {
        0xFF, 0xFB, 0xFF, 0xFB, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x15, 0xE5, 0x3F
    };

    if (exanic_z10_i2c_phy_write(exanic, port_number, 0x7F, &zero, 1) == -1)
        return -1;
    if (exanic_z10_i2c_phy_write(exanic, port_number, 0x00, init_regs, 12) == -1)
        return -1;

    /* Turn on the SFP TX */
    reg = zpu_read(exanic, Z10_CPLD_SFP_CMD);
    reg = reg & ~(1 << (Z10_TX_DIS_SFP0_BIT + port_number));
    zpu_write(exanic, Z10_CPLD_SFP_CMD, reg);

    return 0;
}

int exanic_z10_poweroff_port(struct exanic *exanic, unsigned port_number)
{
    uint32_t reg;

    /* Turn off the SFP TX */
    reg = zpu_read(exanic, Z10_CPLD_SFP_CMD);
    reg = reg | (1 << (Z10_TX_DIS_SFP0_BIT + port_number));
    zpu_write(exanic, Z10_CPLD_SFP_CMD, reg);

    return 0;
}
