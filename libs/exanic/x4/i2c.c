#include <unistd.h>
#include "../exanic.h"
#include "../pcie_if.h"
#include <stdio.h>

struct exanic_i2c_dev
{
    struct exanic *exanic;
    int bus_number;
    int supports_getscl;
};

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

static int getsda(struct exanic_i2c_dev *dev)
{
    return (dev->exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
        & (1 << (EXANIC_GPIO_SDA0 + dev->bus_number))) ? 1 : 0;
}

static void setsda(struct exanic_i2c_dev *dev, int val)
{
    if (val)
        dev->exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            &= ~(1 << (EXANIC_GPIO_DRV_SDA0 + dev->bus_number));
    else
        dev->exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            |= (1 << (EXANIC_GPIO_DRV_SDA0 + dev->bus_number));
    delay();
}

static int getscl(struct exanic_i2c_dev *dev)
{
    return (dev->exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
        & (1 << (EXANIC_GPIO_SCL0))) ? 1 : 0;
}

static void __setscl(struct exanic_i2c_dev *dev, int val)
{
    if (val)
        dev->exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            &= ~(1 << (EXANIC_GPIO_DRV_SCL0));
    else
        dev->exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            |= (1 << (EXANIC_GPIO_DRV_SCL0));
    delay();
}

static void setscl(struct exanic_i2c_dev *dev, int val)
{
    int count;

    __setscl(dev, val);
    /* devices may clock stretch by holding SCL low; wait for it to go high */
    if (val && dev->supports_getscl)
    {
        for (count = 0; getscl(dev) == 0 && count < 100; count++)
           delay();
    }
}

/* Returns 0 if reset times out */
static int i2c_init(struct exanic_i2c_dev *dev, exanic_t *exanic, int bus_number)
{
    int count;

    dev->exanic = exanic;
    dev->bus_number = bus_number;
    __setscl(dev, 1);
    dev->supports_getscl = (getscl(dev) == 0) ? 0 : 1;

    setsda(dev, 1);
    for (count = 0; getsda(dev) == 0 && count < 100; count++)
    {
        setscl(dev, 0);
        setscl(dev, 1);
    }

    return (count < 100);
}

static void i2c_start(struct exanic_i2c_dev *dev)
{
    /* sda, scl are high */
    setsda(dev, 0);
    setscl(dev, 0);
}

static void i2c_repstart(struct exanic_i2c_dev *dev)
{
    /* scl is low */
    setsda(dev, 1);
    setscl(dev, 1);
    setsda(dev, 0);
    setscl(dev, 0);
}

static void i2c_stop(struct exanic_i2c_dev *dev)
{
    /* scl is low */
    setsda(dev, 0);
    setscl(dev, 1);
    setsda(dev, 1);
}

/* Returns non-zero if ack received, or 0 if the device did not ack */
static int i2c_outb(struct exanic_i2c_dev *dev, unsigned char data)
{
    int i, nak;

    /* scl is low */
    for (i = 7; i >= 0; i--)
    {
        setsda(dev, data & (1 << i));
        setscl(dev, 1);
        setscl(dev, 0);
    }
    setsda(dev, 1);
    setscl(dev, 1);

    nak = getsda(dev);
    setscl(dev, 0);
    /* scl is low */

    return !nak;
}

static unsigned char i2c_inb(struct exanic_i2c_dev *dev)
{
    int i;
    char data = 0;

    /* scl is low */
    setsda(dev, 1);
    for (i = 7; i >= 0; i--)
    {
        setscl(dev, 1);
        if (getsda(dev))
            data |= (1 << i);
        setscl(dev, 0);
    }
    /* scl is low */

    return data;
}

static void i2c_ack(struct exanic_i2c_dev *dev)
{
    /* scl is low */
    setsda(dev, 0);
    setscl(dev, 1);
    setscl(dev, 0);
    setsda(dev, 1);
    /* scl is low */
}

static void i2c_nack(struct exanic_i2c_dev *dev)
{
    /* scl is low, sda is high */
    setscl(dev, 1);
    setscl(dev, 0);
    /* scl is low */
}

static int i2c_read(exanic_t *exanic, int bus_number, uint8_t devaddr,
                    uint8_t regaddr, char *buffer, size_t size)
{
    struct exanic_i2c_dev dev;
    size_t i;

    if (size == 0)
        return 0;

    if (!i2c_init(&dev, exanic, bus_number))
    {
        exanic_err_printf("I2C reset error");
        return -1;
    }
    i2c_start(&dev);
    if (!i2c_outb(&dev, devaddr) ||
            !i2c_outb(&dev, regaddr))
    {
        exanic_err_printf("no ack from device on I2C read");
        return -1;
    }
    i2c_repstart(&dev);
    if (!i2c_outb(&dev, devaddr | 1))
    {
        exanic_err_printf("no ack from device on I2C read");
        return -1;
    }
    for (i = 0; i < size-1; i++)
    {
        buffer[i] = i2c_inb(&dev);
        i2c_ack(&dev);
    }
    buffer[i] = i2c_inb(&dev);
    /* NACK after last byte per I2C protocol */
    i2c_nack(&dev);
    i2c_stop(&dev);

    return 0;
}

static int i2c_write(exanic_t *exanic, int bus_number, uint8_t devaddr,
                     uint8_t regaddr, const char *buffer, size_t size)
{
    struct exanic_i2c_dev dev;
    size_t i;

    if (!i2c_init(&dev, exanic, bus_number))
    {
        exanic_err_printf("I2C reset error");
        return -1;
    }
    i2c_start(&dev);
    if (!i2c_outb(&dev, devaddr) ||
            !i2c_outb(&dev, regaddr))
    {
        exanic_err_printf("no ack from device on I2C write");
        return -1;
    }
    for (i = 0; i < size; i++)
    {
        if (!i2c_outb(&dev, buffer[i]))
        {
            exanic_err_printf("no ack from device on I2C write");
            return -1;
        }
    }
    i2c_stop(&dev);

    return 0;
}

static int i2c_eeprom_write(exanic_t *exanic, int bus_number, uint8_t devaddr,
                            uint8_t regaddr, const char *buffer, size_t size)
{
    struct exanic_i2c_dev dev;
    int ret, i;

    ret = i2c_write(exanic, bus_number, devaddr, regaddr, buffer, size);

    if (ret)
        return ret;

    /* Wait for write cycle to complete */
    for (i = 0; i < 100; i++)
    {
        usleep(1000);
        if (!i2c_init(&dev, exanic, bus_number))
            break;
        i2c_start(&dev);
        if (i2c_outb(&dev, devaddr))
        {
            i2c_stop(&dev);
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
