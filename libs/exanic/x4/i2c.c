#include <unistd.h>
#include "../exanic.h"
#include "../pcie_if.h"
#include <stdio.h>

struct phy_i2c
{
    int bus;
    int devaddr;
};

/* Lookup I2C bus and slave addresses for the PHYs */
static struct phy_i2c x4_phy_i2c[] = {
    { 4, 0x86 },    /* PHY 0 */
    { 4, 0x88 },    /* PHY 1 */
    { 5, 0x86 },    /* PHY 2 */
    { 5, 0x88 },    /* PHY 3 */
};

static struct phy_i2c x2_phy_i2c[] = {
    { 4, 0x86 },    /* PHY 0 */
    { 4, 0x88 },    /* PHY 1 */
};

#define X4_EEPROM_I2C_BUS   5
#define X4_EEPROM_I2C_ADDR  0xA0

#define X2_EEPROM_I2C_BUS   4
#define X2_EEPROM_I2C_ADDR  0xA0

#define X40_MODULE_BUS 0

static void delay(void)
{
    usleep(20);
}

static void setsda(exanic_t *exanic, int bus_number, int val)
{
    if (val)
        exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            &= ~(1 << (EXANIC_GPIO_DRV_SDA0 + bus_number));
    else
        exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            |= (1 << (EXANIC_GPIO_DRV_SDA0 + bus_number));
    delay();
}

static void setscl(exanic_t *exanic, int val)
{
    if (val)
        exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            &= ~(1 << (EXANIC_GPIO_DRV_SCL0));
    else
        exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            |= (1 << (EXANIC_GPIO_DRV_SCL0));
    delay();
}

static int getsda(exanic_t* exanic, int bus_number)
{
    return (exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
        & (1 << (EXANIC_GPIO_SDA0 + bus_number))) ? 1 : 0;
}

/* Returns 0 if reset times out */
static int i2c_reset(exanic_t *exanic, int bus_number)
{
    int count = 0;
    setscl(exanic, 1);
    setsda(exanic, bus_number, 1);
    while (getsda(exanic, bus_number) == 0 && count < 100)
    {
        setscl(exanic, 0);
        setscl(exanic, 1);
        count++;
    }
    return (count < 100);
}

static void i2c_start(exanic_t *exanic, int bus_number)
{
    /* sda, scl are high */
    setsda(exanic, bus_number, 0);
    setscl(exanic, 0);
}

static void i2c_repstart(exanic_t *exanic, int bus_number)
{
    /* scl is low */
    setsda(exanic, bus_number, 1);
    setscl(exanic, 1);
    setsda(exanic, bus_number, 0);
    setscl(exanic, 0);
}

static void i2c_stop(exanic_t *exanic, int bus_number)
{
    /* scl is low */
    setsda(exanic, bus_number, 0);
    setscl(exanic, 1);
    setsda(exanic, bus_number, 1);
}

/* Returns non-zero if ack received, or 0 if the device did not ack */
static int i2c_outb(exanic_t *exanic, int bus_number, char data)
{
    int i, nak;

    /* scl is low */
    for (i = 7; i >= 0; i--)
    {
        setsda(exanic, bus_number, data & (1 << i));
        setscl(exanic, 1);
        setscl(exanic, 0);
    }
    setsda(exanic, bus_number, 1);
    setscl(exanic, 1);

    nak = getsda(exanic, bus_number);
    setscl(exanic, 0);
    /* scl is low */

    return !nak;
}

static char i2c_inb(exanic_t *exanic, int bus_number)
{
    int i;
    char data = 0;

    /* scl is low */
    setsda(exanic, bus_number, 1);
    for (i = 7; i >= 0; i--)
    {
        setscl(exanic, 1);
        if (getsda(exanic, bus_number))
            data |= (1 << i);
        setscl(exanic, 0);
    }
    /* scl is low */

    return data;
}

static int i2c_read(exanic_t *exanic, int bus_number, uint8_t devaddr,
                    uint8_t regaddr, char *buffer, size_t size)
{
    size_t i;

    if (!i2c_reset(exanic, bus_number))
    {
        exanic_err_printf("I2C reset error");
        return -1;
    }
    i2c_start(exanic, bus_number);
    if (!i2c_outb(exanic, bus_number, devaddr) ||
            !i2c_outb(exanic, bus_number, regaddr))
    {
        exanic_err_printf("no ack from device on I2C read");
        return -1;
    }
    for (i = 0; i < size; i++)
    {
        i2c_repstart(exanic, bus_number);
        if (!i2c_outb(exanic, bus_number, devaddr | 1))
        {
            exanic_err_printf("no ack from device on I2C read");
            return -1;
        }
        buffer[i] = i2c_inb(exanic, bus_number);
    }
    i2c_stop(exanic, bus_number);

    return 0;
}

static int i2c_write(exanic_t *exanic, int bus_number, uint8_t devaddr,
                     uint8_t regaddr, const char *buffer, size_t size)
{
    size_t i;

    if (!i2c_reset(exanic, bus_number))
    {
        exanic_err_printf("I2C reset error");
        return -1;
    }
    i2c_start(exanic, bus_number);
    if (!i2c_outb(exanic, bus_number, devaddr) ||
            !i2c_outb(exanic, bus_number, regaddr))
    {
        exanic_err_printf("no ack from device on I2C write");
        return -1;
    }
    for (i = 0; i < size; i++)
    {
        if (!i2c_outb(exanic, bus_number, buffer[i]))
        {
            exanic_err_printf("no ack from device on I2C write");
            return -1;
        }
    }
    i2c_stop(exanic, bus_number);

    return 0;
}

static int i2c_eeprom_write(exanic_t *exanic, int bus_number, uint8_t devaddr,
                            uint8_t regaddr, const char *buffer, size_t size)
{
    int ret, i;

    ret = i2c_write(exanic, bus_number, devaddr, regaddr, buffer, size);

    if (ret)
        return ret;

    /* Wait for write cycle to complete */
    for (i = 0; i < 100; i++)
    {
        usleep(1000);
        i2c_reset(exanic, bus_number);
        i2c_start(exanic, bus_number);
        if (i2c_outb(exanic, bus_number, devaddr))
        {
            i2c_stop(exanic, bus_number);
            return 0;
        }
    }

    exanic_err_printf("timeout waiting for EEPROM write cycle to complete");
    return -1;
}

int exanic_x4_i2c_phy_read(exanic_t *exanic, int phy_number, uint8_t regaddr,
                           char *buffer, size_t size)
{
    int bus = x4_phy_i2c[phy_number].bus;
    int devaddr = x4_phy_i2c[phy_number].devaddr;

    return i2c_read(exanic, bus, devaddr, regaddr, buffer, size);
}

int exanic_x4_i2c_phy_write(exanic_t *exanic, int phy_number, uint8_t regaddr,
                            char *buffer, size_t size)
{
    int bus = x4_phy_i2c[phy_number].bus;
    int devaddr = x4_phy_i2c[phy_number].devaddr;

    return i2c_write(exanic, bus, devaddr, regaddr, buffer, size);
}

int exanic_x2_i2c_phy_read(exanic_t *exanic, int phy_number, uint8_t regaddr,
                           char *buffer, size_t size)
{
    int bus = x2_phy_i2c[phy_number].bus;
    int devaddr = x2_phy_i2c[phy_number].devaddr;

    return i2c_read(exanic, bus, devaddr, regaddr, buffer, size);
}

int exanic_x2_i2c_phy_write(exanic_t *exanic, int phy_number, uint8_t regaddr,
                            char *buffer, size_t size)
{
    int bus = x2_phy_i2c[phy_number].bus;
    int devaddr = x2_phy_i2c[phy_number].devaddr;

    return i2c_write(exanic, bus, devaddr, regaddr, buffer, size);
}

int exanic_x4_x2_i2c_sfp_read(exanic_t *exanic, int sfp_number, uint8_t devaddr,
                              uint8_t regaddr, char *buffer, size_t size)
{
    /* SFPs are on busses 0-3 */
    int bus = sfp_number;

    return i2c_read(exanic, bus, devaddr, regaddr, buffer, size);
}

int exanic_x40_i2c_sfp_read(exanic_t *exanic, int sfp_number, uint8_t devaddr,
                            uint8_t regaddr, char *buffer, size_t size)
{
    /* QSFPs are on busses 0-1 */
    int module = sfp_number/4;
    int ret;

    exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
                    &= ~(1 << (EXANIC_GPIO_MOD0NSEL + module));
    usleep(2000); /* 2ms setup time. */
    ret = i2c_read(exanic, X40_MODULE_BUS, devaddr, regaddr, buffer, size);
    exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
                    |= (1 << (EXANIC_GPIO_MOD0NSEL + module));

    return ret;
}

int exanic_x4_x2_i2c_sfp_write(exanic_t *exanic, int sfp_number, uint8_t devaddr,
                               uint8_t regaddr, char *buffer, size_t size)
{
    /* SFPs are on busses 0-3 */
    int bus = sfp_number;

    return i2c_eeprom_write(exanic, bus, devaddr, regaddr, buffer, size);
}

int exanic_x40_i2c_sfp_write(exanic_t *exanic, int sfp_number, uint8_t devaddr,
                             uint8_t regaddr, char *buffer, size_t size)
{
    /* QSFPs are on busses 0-1 */
    int module = sfp_number/4;
    int ret;

    exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
                    &= ~(1 << (EXANIC_GPIO_MOD0NSEL + module));
    usleep(2000); /* 2ms setup time. */
    ret = i2c_eeprom_write(exanic, X40_MODULE_BUS, devaddr, regaddr, buffer, size);
    exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
                    |= (1 << (EXANIC_GPIO_MOD0NSEL + module));
    return ret;
}

int exanic_x4_i2c_eeprom_read(exanic_t *exanic, uint8_t regaddr, char *buffer,
                              size_t size)
{
    return i2c_read(exanic, X4_EEPROM_I2C_BUS, X4_EEPROM_I2C_ADDR, regaddr,
                    buffer, size);
}

int exanic_x2_i2c_eeprom_read(exanic_t *exanic, uint8_t regaddr, char *buffer,
                              size_t size)
{
    return i2c_read(exanic, X2_EEPROM_I2C_BUS, X2_EEPROM_I2C_ADDR, regaddr,
                    buffer, size);
}

int exanic_x4_i2c_eeprom_write(exanic_t *exanic, uint8_t regaddr, char *buffer,
                               size_t size)
{
    return i2c_eeprom_write(exanic, X4_EEPROM_I2C_BUS, X4_EEPROM_I2C_ADDR,
                            regaddr, buffer, size);
}

int exanic_x2_i2c_eeprom_write(exanic_t *exanic, uint8_t regaddr, char *buffer,
                               size_t size)
{
    return i2c_eeprom_write(exanic, X2_EEPROM_I2C_BUS, X2_EEPROM_I2C_ADDR,
                            regaddr, buffer, size);
}
