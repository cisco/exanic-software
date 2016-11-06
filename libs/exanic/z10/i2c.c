#include "../exanic.h"
#include "../pcie_if.h"
#include "zpu.h"

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

static void setsda(exanic_t *exanic, int bus, int val)
{
    uint32_t reg = z10_zpu_read(exanic, i2c_bus[bus].zpu_reg);
    if (val)
        reg = reg | i2c_bus[bus].sda_out_bit;
    else
        reg = reg & ~i2c_bus[bus].sda_out_bit;
    z10_zpu_write(exanic, i2c_bus[bus].zpu_reg, reg);
}

static void setscl(exanic_t *exanic, int bus, int val)
{
    uint32_t reg = z10_zpu_read(exanic, i2c_bus[bus].zpu_reg);
    if (val)
        reg = reg | i2c_bus[bus].clk_bit;
    else
        reg = reg & ~i2c_bus[bus].clk_bit;
    z10_zpu_write(exanic, i2c_bus[bus].zpu_reg, reg);
}

static void setoutput(exanic_t *exanic, int bus, int en)
{
    uint32_t reg = z10_zpu_read(exanic, i2c_bus[bus].zpu_reg);
    if (en)
        reg = reg | i2c_bus[bus].en_bit;
    else
        reg = reg & ~i2c_bus[bus].en_bit;
    z10_zpu_write(exanic, i2c_bus[bus].zpu_reg, reg);
}

static int getsda(exanic_t *exanic, int bus)
{
    uint32_t reg = z10_zpu_read(exanic, i2c_bus[bus].zpu_reg);
    return (reg & i2c_bus[bus].sda_in_bit) ? 1 : 0;
}


static void i2c_reset(exanic_t *exanic, int bus)
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

static void i2c_start(exanic_t *exanic, int bus)
{
    /* sda, scl are high */
    setsda(exanic, bus, 0);
    setscl(exanic, bus, 0);
}

static void i2c_repstart(exanic_t *exanic, int bus)
{
    /* scl is low */
    setsda(exanic, bus, 1);
    setscl(exanic, bus, 1);
    setsda(exanic, bus, 0);
    setscl(exanic, bus, 0);
}

static void i2c_stop(exanic_t *exanic, int bus)
{
    /* scl is low */
    setsda(exanic, bus, 0);
    setscl(exanic, bus, 1);
    setsda(exanic, bus, 1);
}

/* Returns non-zero if ack received, or 0 if the device did not ack */
static int i2c_outb(exanic_t *exanic, int bus, char data)
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

static char i2c_inb(exanic_t *exanic, int bus)
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

static int i2c_read(exanic_t *exanic, int bus, uint8_t devaddr, uint8_t regaddr,
                    char *buffer, size_t size)
{
    size_t i;

    i2c_reset(exanic, bus);
    i2c_start(exanic, bus);
    if (!i2c_outb(exanic, bus, devaddr) || !i2c_outb(exanic, bus, regaddr))
    {
        exanic_err_printf("no ack from device on I2C write");
        return -1;
    }
    for (i = 0; i < size; i++)
    {
        i2c_repstart(exanic, bus);
        if (!i2c_outb(exanic, bus, devaddr | 1))
        {
            exanic_err_printf("no ack from device on I2C write");
            return -1;
        }
        buffer[i] = i2c_inb(exanic, bus);
    }
    i2c_stop(exanic, bus);

    return 0;
}

static int i2c_write(exanic_t *exanic, int bus, uint8_t devaddr, uint8_t regaddr,
                     const char *buffer, size_t size)
{
    size_t i;

    i2c_reset(exanic, bus);
    i2c_start(exanic, bus);
    if (!i2c_outb(exanic, bus, devaddr) || !i2c_outb(exanic, bus, regaddr))
    {
        exanic_err_printf("no ack from device on I2C write");
        return -1;
    }
    for (i = 0; i < size; i++)
    {
        if (!i2c_outb(exanic, bus, buffer[i]))
        {
            exanic_err_printf("no ack from device on I2C write");
            return -1;
        }
    }
    i2c_stop(exanic, bus);

    return 0;
}

int z10_i2c_sfp_read(exanic_t *exanic, int port_number, uint8_t devaddr,
                     uint8_t regaddr, char *buffer, size_t size)
{
    /* SFPs are on busses 0-3 */
    int bus = port_number;

    return i2c_read(exanic, bus, devaddr, regaddr, buffer, size);
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

int z10_i2c_phy_write(exanic_t *exanic, int port_number, uint8_t regaddr,
                      char *buffer, size_t size)
{
    int bus = phy_i2c[port_number].bus;
    int devaddr = phy_i2c[port_number].devaddr;

    return i2c_write(exanic, bus, devaddr, regaddr, buffer, size);
}
