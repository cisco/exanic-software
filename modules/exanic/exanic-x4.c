/**
 * ExaNIC driver
 * Copyright (C) 2011-2013 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/miscdevice.h>

#include "../../libs/exanic/pcie_if.h"
#include "../../libs/exanic/const.h"
#include "exanic.h"
#include "exanic-structs.h"

/* Lookup I2C bus and slave addresses for the PHYs */
static struct {
    int bus;
    int devaddr;
} x4_phy_i2c[] = {
    { 4, 0x86 },    /* PHY 0 */
    { 4, 0x88 },    /* PHY 1 */
    { 5, 0x86 },    /* PHY 2 */
    { 5, 0x88 },    /* PHY 3 */
};

static struct {
    int bus;
    int devaddr;
} x2_phy_i2c[] = {
    { 4, 0x86 },    /* PHY 0 */
    { 4, 0x88 },    /* PHY 1 */
    { 0, 0 },
    { 0, 0 },
};

#define X4_EEPROM_I2C_BUS   5
#define X4_EEPROM_I2C_ADDR  0xA0

#define X2_EEPROM_I2C_BUS   4
#define X2_EEPROM_I2C_ADDR  0xA0

#define X10_EEPROM_I2C_BUS   4
#define X10_EEPROM_I2C_ADDR  0xA0

/* Serial number */
#define EEPROM_ADDR_SERIAL  0x00

/* Bridging and mirroring configuration */
#define EEPROM_BRIDGING_CFG 0x40

/* Port speed settings, 1 byte for each port */
#define EEPROM_PORT_SPEED   0x50

#define PORT_SPEED_1G       0x01
#define PORT_SPEED_10G      0x02

/* Port flags configuration base, 1 byte for each port */
#define EEPROM_PORT_CFG     0x54

#define PORT_CFG_AUTONEG    0x01

static void setsda(struct exanic *exanic, int bus_number, int val)
{
    volatile uint32_t *registers = exanic_registers(exanic);

    if (val)
        registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            &= ~(1 << (EXANIC_GPIO_DRV_SDA0 + bus_number));
    else
        registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            |= (1 << (EXANIC_GPIO_DRV_SDA0 + bus_number));

    udelay(20);
}

static void setscl(struct exanic *exanic, int val)
{
    volatile uint32_t *registers = exanic_registers(exanic);

    if (val)
        registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            &= ~(1 << (EXANIC_GPIO_DRV_SCL0));
    else
        registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            |= (1 << (EXANIC_GPIO_DRV_SCL0));

    udelay(20);
}

static int getsda(struct exanic* exanic, int bus_number)
{
    volatile uint32_t *registers = exanic_registers(exanic);

    return (registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
        & (1 << (EXANIC_GPIO_SDA0 + bus_number))) ? 1 : 0;
}

/* Returns 0 if reset times out */
static int i2c_reset(struct exanic *exanic, int bus_number)
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

static void i2c_start(struct exanic *exanic, int bus_number)
{
    /* sda, scl are high */
    setsda(exanic, bus_number, 0);
    setscl(exanic, 0);
}

static void i2c_repstart(struct exanic *exanic, int bus_number)
{
    /* scl is low */
    setsda(exanic, bus_number, 1);
    setscl(exanic, 1);
    setsda(exanic, bus_number, 0);
    setscl(exanic, 0);
}

static void i2c_stop(struct exanic *exanic, int bus_number)
{
    /* scl is low */
    setsda(exanic, bus_number, 0);
    setscl(exanic, 1);
    setsda(exanic, bus_number, 1);
}

/* Returns non-zero if ack received, or 0 if the device did not ack */
static int i2c_outb(struct exanic *exanic, int bus_number, char data)
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

static char i2c_inb(struct exanic *exanic, int bus_number)
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

static int i2c_read(struct exanic *exanic, int bus_number, uint8_t devaddr,
                    uint8_t regaddr, char *buffer, size_t size)
{
    size_t i;

    if (!i2c_reset(exanic, bus_number))
    {
        dev_err(exanic_dev(exanic), "I2C reset error\n");
        return -1;
    }
    i2c_start(exanic, bus_number);
    if (!i2c_outb(exanic, bus_number, devaddr) ||
            !i2c_outb(exanic, bus_number, regaddr))
    {
        dev_err(exanic_dev(exanic), "no ack from device on I2C read\n");
        return -1;
    }
    for (i = 0; i < size; i++)
    {
        i2c_repstart(exanic, bus_number);
        if (!i2c_outb(exanic, bus_number, devaddr | 1))
        {
            dev_err(exanic_dev(exanic), "no ack from device on I2C read\n");
            return -1;
        }
        buffer[i] = i2c_inb(exanic, bus_number);
    }
    i2c_stop(exanic, bus_number);

    return 0;
}

static int i2c_write(struct exanic *exanic, int bus_number, uint8_t devaddr,
                     uint8_t regaddr, const char *buffer, size_t size)
{
    size_t i;

    if (!i2c_reset(exanic, bus_number))
    {
        dev_err(exanic_dev(exanic), "I2C reset error\n");
        return -1;
    }
    i2c_start(exanic, bus_number);
    if (!i2c_outb(exanic, bus_number, devaddr) ||
            !i2c_outb(exanic, bus_number, regaddr))
    {
        dev_err(exanic_dev(exanic), "no ack from device on I2C write\n");
        return -1;
    }
    for (i = 0; i < size; i++)
    {
        if (!i2c_outb(exanic, bus_number, buffer[i]))
        {
            dev_err(exanic_dev(exanic), "no ack from device on I2C write\n");
            return -1;
        }
    }
    i2c_stop(exanic, bus_number);

    return 0;
}

static int exanic_x4_x2_i2c_phy_write(struct exanic *exanic, int phy_number,
                                      uint8_t regaddr, char *buffer, size_t size)
{
    int bus;
    int devaddr;

    if (exanic->hw_id == EXANIC_HW_X4)
    {
        bus = x4_phy_i2c[phy_number].bus;
        devaddr = x4_phy_i2c[phy_number].devaddr;
    }
    else if (exanic->hw_id == EXANIC_HW_X2)
    {
        bus = x2_phy_i2c[phy_number].bus;
        devaddr = x2_phy_i2c[phy_number].devaddr;
    }
    else
        BUG();

    return i2c_write(exanic, bus, devaddr, regaddr, buffer, size);
}

static int exanic_x4_x2_i2c_eeprom_read(struct exanic *exanic, uint8_t regaddr,
                                        char *buffer, size_t size)
{
    if (exanic->hw_id == EXANIC_HW_X4)
        return i2c_read(exanic, X4_EEPROM_I2C_BUS, X4_EEPROM_I2C_ADDR, regaddr,
                buffer, size);
    else if (exanic->hw_id == EXANIC_HW_X2) 
        return i2c_read(exanic, X2_EEPROM_I2C_BUS, X2_EEPROM_I2C_ADDR, regaddr,
                buffer, size);
    else if (exanic->hw_id == EXANIC_HW_X10 || 
                exanic->hw_id == EXANIC_HW_X10_GM ||
                exanic->hw_id == EXANIC_HW_X40 ||
                exanic->hw_id == EXANIC_HW_X10_HPT)
        return i2c_read(exanic, X10_EEPROM_I2C_BUS, X10_EEPROM_I2C_ADDR, regaddr,
                buffer, size);
    else
        BUG();
}

static int exanic_x4_x2_i2c_eeprom_write(struct exanic *exanic, uint8_t regaddr,
                                         char *buffer, size_t size)
{
    int bus;
    int devaddr;
    int err, i;

    if (exanic->hw_id == EXANIC_HW_X4)
    {
        bus = X4_EEPROM_I2C_BUS;
        devaddr = X4_EEPROM_I2C_ADDR;
    }
    else if (exanic->hw_id == EXANIC_HW_X2)
    {
        bus = X2_EEPROM_I2C_BUS;
        devaddr = X2_EEPROM_I2C_ADDR;
    }
    else if (exanic->hw_id == EXANIC_HW_X10 || 
                exanic->hw_id == EXANIC_HW_X10_GM ||
                exanic->hw_id == EXANIC_HW_X40)
    {
        bus = X10_EEPROM_I2C_BUS;
        devaddr = X10_EEPROM_I2C_ADDR;
    }
    else
        BUG();

    err = i2c_write(exanic, bus, devaddr, regaddr, buffer, size);
    if (err)
        return err;

    /* Wait for write cycle to complete */
    for (i = 0; i < 100; i++)
    {
        udelay(1000);
        i2c_reset(exanic, bus);
        i2c_start(exanic, bus);
        if (i2c_outb(exanic, bus, devaddr))
        {
            i2c_stop(exanic, bus);
            return 0;
        }
    }
    return -1;
}

int exanic_x4_x2_get_serial(struct exanic *exanic, unsigned char serial[ETH_ALEN])
{
    return exanic_x4_x2_i2c_eeprom_read(exanic, EEPROM_ADDR_SERIAL, serial,
            ETH_ALEN);
}

static int sfp_read(struct exanic *exanic, int port_number, 
               uint8_t devaddr, uint8_t regaddr, char *buffer, size_t size)
{
    /* SFPs are on bus 0-3 in ExaNIC. */
    int bus_number;
    if (exanic->hw_id == EXANIC_HW_X40)
        bus_number = port_number / 4;
    else
        bus_number = port_number;
    return i2c_read(exanic, bus_number, devaddr, regaddr, buffer, size);
}

static int sfp_write(struct exanic *exanic, int port_number, 
             uint8_t devaddr, uint8_t regaddr, const char *buffer, size_t size)
{
    /* SFPs are on bus 0-3 in ExaNIC. */
    int bus_number;
    if (exanic->hw_id == EXANIC_HW_X40)
        bus_number = port_number / 4;
    else
        bus_number = port_number;
    return i2c_write(exanic, bus_number, devaddr, regaddr, buffer, size);
}

static int exanic_x4_x2_optimize_phy_parameters(struct exanic *exanic, unsigned int port_number)
{
    /* conservative default parameters */
    char rx_param[] = { 0x50, 0x14, 0x00 };
    char tx_param[] = { 0x04, 0x0C, 0x05 };
    char cable_type, cable_length;

    /* optimise parameters based on cable type and length */
    if ((sfp_read(exanic, port_number, 0xA0, 8, &cable_type, 1) != -1)
        && (cable_type & 4))
    {
        if (sfp_read(exanic, port_number, 0xA0, 18, &cable_length, 1) != -1
            && (cable_length < 5))
        {
            /* short passive cable */
            /* apply some extra analog gain and pre-boost settings */
            rx_param[0] = 0x58 + 8*cable_length;
            rx_param[1] = 0x16 + 2*cable_length;
            tx_param[1] = 0x0E + 2*cable_length;
            dev_info(exanic_dev(exanic), DRV_NAME "%u: Port %u detected passive cable (%um).\n",
                        exanic->id, port_number, cable_length);
        }
        else
        { 
            /* very long passive cable >= 5m */
            /* apply most aggressive analog gain and pre-boost settings */
            rx_param[0] = 0x7F;
            rx_param[1] = 0x1E;
            tx_param[1] = 0x16;
            dev_info(exanic_dev(exanic), DRV_NAME "%u: Port %u detected passive cable (long).\n",
                        exanic->id, port_number);
        }
    }

    if (exanic_x4_x2_i2c_phy_write(exanic, port_number, 0x10, rx_param, 3) == -1)
        return -1;
    if (exanic_x4_x2_i2c_phy_write(exanic, port_number, 0x16, tx_param, 3) == -1)
        return -1;

    return 0;
}

int exanic_x4_x2_poweron_port(struct exanic *exanic, unsigned port_number)
{
    volatile uint32_t *registers = exanic_registers(exanic);

    char reg_val = 0;
    char init_regs[12] = {
        0xFF, 0xFB, 0xFF, 0xFB, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x15, 0xE5, 0x3F
    };

    if (exanic->hw_id == EXANIC_HW_X4 || exanic->hw_id == EXANIC_HW_X2)
    {
        /* Turn on the PHY */
        registers[REG_HW_INDEX(REG_HW_POWERDOWN)] &= ~(1 << port_number);
    }

    /* Turn on the SFP TX */
    registers[REG_HW_INDEX(REG_HW_POWERDOWN)] |=
        (1 << (EXANIC_SFP_TXDIS0 + port_number) );


    if (exanic->hw_id == EXANIC_HW_X4 || exanic->hw_id == EXANIC_HW_X2)
    {
        /* Initialise the PHY */
        reg_val = 0;
        if (exanic_x4_x2_i2c_phy_write(exanic, port_number, 0x7F, &reg_val, 1) == -1)
            return -1;
        if (exanic_x4_x2_i2c_phy_write(exanic, port_number, 0x00, init_regs, 12) == -1)
            return -1;
        return exanic_x4_x2_optimize_phy_parameters(exanic, port_number);
    }

    return 0;
}

int exanic_x4_x2_poweroff_port(struct exanic *exanic, unsigned port_number)
{
    volatile uint32_t *registers = exanic_registers(exanic);

    /* Turn off the SFP TX */
    registers[REG_HW_INDEX(REG_HW_POWERDOWN)] &=
        ~(1 << (EXANIC_SFP_TXDIS0 + port_number) );

    if (exanic->hw_id == EXANIC_HW_X4 || exanic->hw_id == EXANIC_HW_X2)
    {
        /* Turn off the PHY */
        registers[REG_HW_INDEX(REG_HW_POWERDOWN)] |= (1 << port_number);
    }
    return 0;
}

int exanic_x4_x2_save_feature_cfg(struct exanic *exanic)
{
    volatile uint32_t *registers = exanic_registers(exanic);
    char old, new;

    if (exanic_x4_x2_i2c_eeprom_read(exanic, EEPROM_BRIDGING_CFG, &old, 1) == -1)
        return -1;
    new = (registers[REG_EXANIC_INDEX(REG_EXANIC_FEATURE_CFG)]
            & EXANIC_FEATURE_BRIDGE_MIRROR_MASK);

    if (old == new)
        return 0;

    return exanic_x4_x2_i2c_eeprom_write(exanic, EEPROM_BRIDGING_CFG, &new, 1);
}

int exanic_x4_x2_save_speed(struct exanic *exanic, unsigned port_number,
                            unsigned speed)
{
    uint8_t regaddr = EEPROM_PORT_SPEED + port_number;
    char old, new;

    /* Save port speed setting to EEPROM */
    if (exanic_x4_x2_i2c_eeprom_read(exanic, regaddr, &old, 1) == -1)
        return -1;

    if (speed == SPEED_1000)
        new = PORT_SPEED_1G;
    else
        new = PORT_SPEED_10G;

    if (old == new)
        return 0;

    return exanic_x4_x2_i2c_eeprom_write(exanic, regaddr, &new, 1);
}

int exanic_x4_x2_save_autoneg(struct exanic *exanic, unsigned port_number,
                              bool autoneg)
{
    uint8_t regaddr = EEPROM_PORT_CFG + port_number;
    char old, new;

    /* Save autoneg setting to EEPROM */
    if (exanic_x4_x2_i2c_eeprom_read(exanic, regaddr, &old, 1) == -1)
        return -1;

    if (autoneg)
        new = old | PORT_CFG_AUTONEG;
    else
        new = old & ~PORT_CFG_AUTONEG;

    if (old == new)
        return 0;

    return exanic_x4_x2_i2c_eeprom_write(exanic, regaddr, &new, 1);
}

static void exanic_x4_x2_marvell_reset(struct exanic *exanic, unsigned port_number)
{
    volatile uint32_t *registers = exanic_registers(exanic);

    /* Turn off the SFP TX */
    registers[REG_HW_INDEX(REG_HW_POWERDOWN)] &=
        ~(1 << (EXANIC_SFP_TXDIS0 + port_number) );
    msleep(10);
    /* Turn on the SFP TX */
    registers[REG_HW_INDEX(REG_HW_POWERDOWN)] |=
        (1 << (EXANIC_SFP_TXDIS0 + port_number) );
}

static void exanic_x4_x2_marvell_enable_fast_ethernet(struct exanic *exanic, unsigned port_number)
{
    /* Per Finisar AN-2036 */
    uint16_t data;
    data = htons(0x0000);
    sfp_write(exanic, port_number, 0xAC, 0x16, (char *)&data, 2);

    /* Extended PHY Specific Status Register */
    sfp_read(exanic, port_number, 0xAC, 0x1B, (char *)&data, 2);
    /* "SGMII without clock with SGMII auto-neg to copper" */
    data = (data & ~htons(0x000F)) | htons(0x0004);
    sfp_write(exanic, port_number, 0xAC, 0x1B, (char *)&data, 2);

    /* Control Register (Copper) */
    sfp_read(exanic, port_number, 0xAC, 0x00, (char *)&data, 2);
    /* Reset bit */
    data |= htons(0x8000);
    sfp_write(exanic, port_number, 0xAC, 0x00, (char *)&data, 2);

    /* 1000BASE-T Control Register */
    sfp_read(exanic, port_number, 0xAC, 0x09, (char *)&data, 2);
    /* Do not advertise 1000BASE-T */
    data &= ~htons(0x0300);
    sfp_write(exanic, port_number, 0xAC, 0x09, (char *)&data, 2);

    /* Auto-Negotiation Advertisement Register (Copper) */
    sfp_read(exanic, port_number, 0xAC, 0x04, (char *)&data, 2);
    /* Advertise 100BASE-TX Full-Duplex and Half-Duplex */
    data = (data & ~htons(0x03E0)) | htons(0x0180);
    sfp_write(exanic, port_number, 0xAC, 0x04, (char *)&data, 2);

    /* Control Register (Copper) */
    sfp_read(exanic, port_number, 0xAC, 0x00, (char *)&data, 2);
    /* 100Mbps */
    data = (data & ~htons(0x2040)) | htons(0x2000);
    /* Reset bit */
    data |= htons(0x8000);
    /* Full-duplex */
    data |= htons(0x0100);
    /* Enable autonegotiation */
    data |= htons(0x1000);
    sfp_write(exanic, port_number, 0xAC, 0x00, (char *)&data, 2);

    /* LED Control Register */
    sfp_read(exanic, port_number, 0xAC, 0x18, (char *)&data, 2);
    /* LED_Link = 001 (use LED_LINK1000 pin as global link indicator) */
    data = (data & htons(0x0038)) | htons(0x0008);
    sfp_write(exanic, port_number, 0xAC, 0x18, (char *)&data, 2);
}

static int exanic_x4_x2_is_sfp_marvell(struct exanic *exanic, unsigned port_number)
{
    uint16_t data = 0;

    /* PHY Identifier */
    sfp_read(exanic, port_number, 0xAC, 0x02, (char *)&data, 2);
    if (data != htons(0x0141))
        return 0;

    /* PHY Identifier */
    sfp_read(exanic, port_number, 0xAC, 0x03, (char *)&data, 2);
    if ((data & htons(0xFFF0)) != htons(0x0CC0))
        return 0;

    return 1;
}

int exanic_x4_x2_set_speed(struct exanic *exanic, unsigned port_number,
                           unsigned old_speed, unsigned speed)
{
    if (speed == SPEED_100)
    {
        if (!exanic_x4_x2_is_sfp_marvell(exanic, port_number))
            return -1;

        exanic_x4_x2_marvell_enable_fast_ethernet(exanic, port_number);
        return 0;
    }
    else if (old_speed == SPEED_100)
    {
        exanic_x4_x2_marvell_reset(exanic, port_number);
    }
    return 0;
}

