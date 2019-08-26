/**
 * I2C logic for ExaNIC cards
 * Copyright (C) 2011-2019 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/miscdevice.h>
#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>

#include "../../libs/exanic/pcie_if.h"
#include "../../libs/exanic/const.h"
#include "exanic.h"
#include "exanic-structs.h"

/* Serial number */
#define EEPROM_ADDR_SERIAL      0x00

/* Bridging and mirroring configuration */
#define EEPROM_BRIDGING_CFG     0x40

/* Port speed settings, 1 byte for each port */
#define EEPROM_PORT_SPEED       0x50

#define PORT_SPEED_1G           0x01
#define PORT_SPEED_10G          0x02

/* Port flags configuration base, 1 byte for each port */
#define EEPROM_PORT_CFG         0x54

#define PORT_CFG_AUTONEG        0x01

#define SFP_DIAG_ADDR           0xA2
#define SFP_EEPROM_ADDR         0xA0

#define SFP_DIAG_MON_BYTE       92
#define SFP_DIAG_MON_BIT        6

/* Maximum number of I2C clock cycles to send during bus clear sequence
 * using a very large number here for reliability */
#define I2C_RESET_CYCLES        100

/* EEPROM write completion timeout in jiffies */
#define EEPROM_WRITE_TIMEOUT    HZ

/* x4 and x2 phy chip addresses */
static struct {
    int bus;
    int devaddr;
} x2_x4_phy_i2c[] = {
    { 4, 0x86 },    /* PHY 0 */
    { 4, 0x88 },    /* PHY 1 */
    { 5, 0x86 },    /* PHY 2 */
    { 5, 0x88 },    /* PHY 3 */
};

/* bitbang methods */
static void exanic_bit_setscl(void *data, int val)
{
    volatile uint32_t *registers =
        exanic_registers(((struct exanic_i2c_data *)data)->exanic);
    if (val)
        registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            &= ~(1 << (EXANIC_GPIO_DRV_SCL0));
    else
        registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            |= (1 << (EXANIC_GPIO_DRV_SCL0));
}

static int exanic_bit_getscl(void *data)
{
    volatile uint32_t *registers =
        exanic_registers(((struct exanic_i2c_data *)data)->exanic);

    return (registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
        & (1 << (EXANIC_GPIO_SCL0))) ? 1 : 0;
}

static void exanic_bit_setsda(void *data, int val)
{
    volatile uint32_t *registers =
        exanic_registers(((struct exanic_i2c_data *)data)->exanic);
    int bus_number = ((struct exanic_i2c_data *)data)->bus_number;

    if (val)
        registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            &= ~(1 << (EXANIC_GPIO_DRV_SDA0 + bus_number));
    else
        registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            |= (1 << (EXANIC_GPIO_DRV_SDA0 + bus_number));
}

static int exanic_bit_getsda(void *data)
{
    volatile uint32_t *registers =
        exanic_registers(((struct exanic_i2c_data *)data)->exanic);
    int bus_number = ((struct exanic_i2c_data *)data)->bus_number;

    return (registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
        & (1 << (EXANIC_GPIO_SDA0 + bus_number))) ? 1 : 0;
}

/* i2c bus clear sequence
 * send i2c clock cycles until slave releases data line */
static int
exanic_i2c_reset(struct exanic_i2c_data *data)
{
    int count = 0;
    exanic_bit_setscl(data, 1);
    exanic_bit_setsda(data, 1);

    for (; count < I2C_RESET_CYCLES; count++)
    {
        if (exanic_bit_getsda(data) == 1)
            return 0;
        exanic_bit_setscl(data, 0);
        exanic_bit_setscl(data, 1);
    }

    return -ETIMEDOUT;
}

/* some firmware versions do not support scl sensing */
static bool exanic_supports_scl_sense(struct exanic *exanic)
{
    struct exanic_i2c_data data =
    {
        .exanic = exanic
    };
    exanic_bit_setscl(&data, 1);
    udelay(20);
    return exanic_bit_getscl(&data) == 1;
}

static struct i2c_adapter *
exanic_sfp_i2c_adapter(struct exanic *exanic, unsigned port_num)
{
    if (port_num >= exanic->num_ports)
        return NULL;

    return exanic->sfp_i2c_adapters[port_num];
}

static struct i2c_adapter *
exanic_phy_i2c_adapter(struct exanic *exanic, unsigned port_num)
{
    if (exanic->hw_id != EXANIC_HW_X2 && exanic->hw_id != EXANIC_HW_X4)
        return NULL;

    if (port_num >= exanic->num_ports)
        return NULL;

    return exanic->phy_i2c_adapters[port_num];
}

static struct i2c_adapter *
exanic_eeprom_i2c_adapter(struct exanic *exanic)
{
    return exanic->eep_i2c_adapter;
}

/* QSFP and QSFPDD (physical) ports can be broken out into
 * multiple interfaces; this function computes physical port
 * number given ethernet interface number */
static int
exanic_to_phys_port(struct exanic *exanic, int port_num)
{
    switch (exanic->hwinfo.port_ff)
    {
        /* only single-lane interfaces possible */
        case EXANIC_PORT_SFP:
            return port_num;

        /* 40G or 4 *10G/1G */
        case EXANIC_PORT_QSFP:
            return exanic->hwinfo.nports == exanic->num_ports ?
                   port_num : port_num / 4;

        /* 2 * 40G or 8 * 10G/1G */
        case EXANIC_PORT_QSFPDD:
           if (exanic->num_ports == exanic->hwinfo.nports * 2)
               return port_num / 2;

           if (exanic->num_ports == exanic->hwinfo.nports * 8)
               return port_num / 8;

        default: break;
    }

    return -1;
}

/* return i2c bus numbers of pluggable transceivers and
 * off-chip serdes given ethernet interface number */

static int
exanic_i2c_sfp_bus_number(struct exanic *exanic, int port_num)
{
    if (port_num < 0 || port_num >= exanic->num_ports)
        return -1;

    /* QSFP and QSFPDD modules are all on bus 0 */
    if (exanic->hwinfo.port_ff == EXANIC_PORT_QSFP ||
        exanic->hwinfo.port_ff == EXANIC_PORT_QSFPDD)
        return 0;

    /* each SFP module is on its separate bus */
    return port_num;
}

static int
exanic_i2c_phy_bus_number(struct exanic *exanic, int port_num)
{
    if (exanic->hw_id != EXANIC_HW_X2 && exanic->hw_id != EXANIC_HW_X4)
        return -1;

    return x2_x4_phy_i2c[port_num].bus;
}

/* custom i2c algorithm, wraps over i2c_algo_bit */
static int
exanic_i2c_master_xfer(struct i2c_adapter *adap, struct i2c_msg *msgs, int num)
{
    struct i2c_algo_bit_data *algo_data =
        (struct i2c_algo_bit_data *)adap->algo_data;
    struct exanic_i2c_data *exanic_data = algo_data->data;
    struct exanic *exanic = exanic_data->exanic;

    int ret;
    if (in_atomic() || irqs_disabled())
    {
        ret = mutex_trylock(&exanic_data->exanic->i2c_lock);
        if (!ret)
            ret = -EAGAIN;
    }
    else
        ret = mutex_lock_interruptible(&exanic_data->exanic->i2c_lock);

    if (ret)
        return ret;

    if (exanic_data->toggle_modsel)
    {
        /* drive modsel low to select module */
        volatile uint32_t *registers = exanic_registers(exanic);
        registers[REG_HW_INDEX(REG_HW_I2C_GPIO)] &=
            ~(1 << (EXANIC_GPIO_MOD0NSEL + exanic_data->phys_port));
        msleep(2);
    }

    ret = exanic_i2c_reset(exanic_data);
    if (ret)
        goto modsel_unassert;

    /* perform i2c transfer */
    ret = exanic_data->xfer_wrapped(adap, msgs, num);

modsel_unassert:
    if (exanic_data->toggle_modsel)
    {
        /* drive modsel high to deselect module */
        volatile uint32_t *registers = exanic_registers(exanic);
        registers[REG_HW_INDEX(REG_HW_I2C_GPIO)] |=
            (1 << (EXANIC_GPIO_MOD0NSEL + exanic_data->phys_port));
        msleep(2);
    }

    mutex_unlock(&exanic_data->exanic->i2c_lock);
    return ret;
}

static struct i2c_algorithm exanic_i2c_bit_algo =
{
    .master_xfer = exanic_i2c_master_xfer,
};

#define EXANIC_I2C_SFP 0
#define EXANIC_I2C_PHY 1
#define EXANIC_I2C_EEP 2
int exanic_i2c_register_bus(struct exanic *exanic, int port,
                            int bus, int type, bool scl_sense,
                            struct i2c_adapter **radap)
{
    struct exanic_i2c_data *data;
    struct i2c_adapter *adap;
    int phys_port = exanic_to_phys_port(exanic, port);
    int ret;

    /* look for busses already registered */
    list_for_each_entry(data, &exanic->i2c_list, link)
        if (bus == data->bus_number && phys_port == data->phys_port)
        {
            *radap = &data->adap;
            return 0;
        }

    data = devm_kzalloc(&exanic->pci_dev->dev, sizeof *data, GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    data->phys_port = type == EXANIC_I2C_EEP ? -1 : phys_port;
    data->toggle_modsel = false;
    data->bus_number = bus;
    adap = &data->adap;

    switch (type)
    {
        case EXANIC_I2C_SFP:
            snprintf(adap->name, sizeof adap->name,
                     "%s:%d-sfp", exanic->name, port);
            /* QSFP and QSFPDD modules require toggling MODSEL */
            if (exanic->hwinfo.port_ff == EXANIC_PORT_QSFP ||
                exanic->hwinfo.port_ff == EXANIC_PORT_QSFPDD)
                data->toggle_modsel = true;
            break;

        case EXANIC_I2C_PHY:
            snprintf(adap->name, sizeof adap->name,
                     "%s:%d-phy", exanic->name, port);
            break;

        /* EEPROM */
        default:
            snprintf(adap->name, sizeof adap->name,
                     "%s-eeprom", exanic->name);
            break;
    }

    /* fill in i2c bitbang data */
    data->bit_data.getscl = scl_sense ? exanic_bit_getscl : NULL;
    data->bit_data.getsda = exanic_bit_getsda;
    data->bit_data.setsda = exanic_bit_setsda;
    data->bit_data.setscl = exanic_bit_setscl;
    data->bit_data.udelay = 20;
    data->bit_data.timeout = HZ;
    data->bit_data.data = data;

    /* fill in i2c adapter */
    adap->owner = THIS_MODULE;
    adap->algo_data = &data->bit_data;
    adap->dev.parent = &exanic->pci_dev->dev;

    /* register bus */
    if ((ret = i2c_bit_add_bus(adap)) < 0)
        return ret;

    *radap = adap;
    /* replace i2c algorithm with wrapper
     * doing it this way to work around poor i2c-mux availability */
    data->xfer_wrapped = adap->algo->master_xfer;
    exanic_i2c_bit_algo.functionality = adap->algo->functionality;
    adap->algo = &exanic_i2c_bit_algo;

    /* fill in exanic pointer */
    data->exanic = exanic;
    /* add to bus list */
    list_add_tail(&data->link, &exanic->i2c_list);

    return 0;
}

/* ExaNIC i2c probe and remove functions */

static void exanic_i2c_unregister_all(struct exanic *exanic)
{
    struct exanic_i2c_data *item;
    list_for_each_entry(item, &exanic->i2c_list, link)
        i2c_del_adapter(&item->adap);
}

int exanic_i2c_init(struct exanic *exanic)
{
    int ret = 0;
    int i = 0;
    bool offchip_phy = false;
    bool scl_sense = exanic_supports_scl_sense(exanic);
    int busno;
    struct i2c_adapter *bus;

    mutex_init(&exanic->i2c_lock);
    INIT_LIST_HEAD(&exanic->i2c_list);

    /* older ExaNIC cards have external serdes controlled by i2c
     * whereas newer designs use on-chip gigabit transceivers */
    if (exanic->hw_id == EXANIC_HW_X2 || exanic->hw_id == EXANIC_HW_X4)
        offchip_phy = true;

    /* register all pluggable transceiver busses */
    for (i = 0; i < exanic->num_ports; ++i)
    {
        busno = exanic_i2c_sfp_bus_number(exanic, i);
        ret = exanic_i2c_register_bus(exanic, i, busno,
                                      EXANIC_I2C_SFP, scl_sense, &bus);
        if (ret)
        {
            dev_err(&exanic->pci_dev->dev,
                    "Failed to register port %d SFP i2c bus\n", i);
            goto err_i2c_bus;
        }

        exanic->sfp_i2c_adapters[i] = bus;
    }

    /* register all external serdes busses */
    if (offchip_phy)
        for (i = 0; i < exanic->num_ports; ++i)
        {
            busno = exanic_i2c_phy_bus_number(exanic, i);
            ret = exanic_i2c_register_bus(exanic, i, busno,
                                          EXANIC_I2C_PHY, scl_sense, &bus);
            if (ret)
            {
                dev_err(&exanic->pci_dev->dev,
                        "Failed to register port %d PHY chip i2c bus\n", i);
                goto err_i2c_bus;
            }

            exanic->phy_i2c_adapters[i] = bus;
        }

    /* register EEPROM bus */
    busno = exanic->hwinfo.eep_bus;
    ret = exanic_i2c_register_bus(exanic, 0, busno, EXANIC_I2C_EEP,
                                  scl_sense, &bus);
    if (ret)
    {
        dev_err(&exanic->pci_dev->dev,
                "Failed to register EEPROM bus\n");
        goto err_i2c_bus;
    }
    exanic->eep_i2c_adapter = bus;

    return ret;

err_i2c_bus:
    exanic_i2c_unregister_all(exanic);
    dev_err(&exanic->pci_dev->dev, "exanic_i2c_init failed!\n");
    return ret;
}

void exanic_i2c_exit(struct exanic *exanic)
{
    exanic_i2c_unregister_all(exanic);
}

/* wrappers over i2c_transfer
 * expect "8-bit" device addresses, i.e. with the r/w bit attached */

static int exanic_i2c_read(struct i2c_adapter *adap, uint8_t devaddr,
                           uint8_t regaddr, char *buffer, size_t size)
{
    struct i2c_msg msg[2];
    /* send register address */
    msg[0].addr = devaddr >> 1;
    msg[0].flags = 0;
    msg[0].len = 1;
    msg[0].buf = &regaddr;
    /* receive content */
    msg[1].addr = devaddr >> 1;
    msg[1].flags = I2C_M_RD;
    msg[1].len = size;
    msg[1].buf = buffer;

    return i2c_transfer(adap, msg, 2) == 2 ? 0 : -1;
}

static int exanic_i2c_write(struct i2c_adapter *adap, uint8_t devaddr,
                            uint8_t regaddr, char *buffer, size_t size)
{
    struct i2c_msg msg[2];
    /* send register address */
    msg[0].addr = devaddr >> 1;
    msg[0].flags = 0;
    msg[0].len = 1;
    msg[0].buf = &regaddr;
    /* send content in the same transaction as msg[0] */
    msg[1].addr = 0;
    msg[1].flags = I2C_M_NOSTART;
    msg[1].len = size;
    msg[1].buf = buffer;

    return i2c_transfer(adap, msg, 2) == 2 ? 0 : -1;
}

/* these functions perform I2C read and write on the external serdes,
 * eeprom and pluggable transceiver busses
 * sfp_write and sfp_read take devaddr because a transceiver presents
 * multiple devices on its bus */

static int exanic_i2c_phy_write(struct exanic *exanic, int phy_number,
                                uint8_t regaddr, char *buffer, size_t size)
{
    uint8_t slave_addr;
    struct i2c_adapter *phy_adap;
    if (phy_number >=
        sizeof(x2_x4_phy_i2c) / sizeof(x2_x4_phy_i2c[0]))
        return -1;

    phy_adap = exanic_phy_i2c_adapter(exanic, phy_number);
    if (!phy_adap)
        return -1;

    slave_addr = x2_x4_phy_i2c[phy_number].devaddr;
    return exanic_i2c_write(phy_adap, slave_addr, regaddr, buffer, size);
}

static int exanic_i2c_eeprom_read(struct exanic *exanic, uint8_t regaddr,
                                  char *buffer, size_t size)
{
    uint8_t slave_addr = exanic->hwinfo.eep_addr;
    struct i2c_adapter *eep_adap = exanic_eeprom_i2c_adapter(exanic);
    return exanic_i2c_read(eep_adap, slave_addr, regaddr, buffer, size);
}

static int exanic_i2c_eeprom_write(struct exanic *exanic, uint8_t regaddr,
                                   char *buffer, size_t size)
{
    uint8_t slave_addr = exanic->hwinfo.eep_addr;
    struct i2c_adapter *eep_adap = exanic_eeprom_i2c_adapter(exanic);
    int ret = exanic_i2c_write(eep_adap, slave_addr, regaddr, buffer, size);
    unsigned long deadline = jiffies + EEPROM_WRITE_TIMEOUT;

    if (ret)
        return ret;

    /* wait for the write cycle to finish */
    while (!time_after(jiffies, deadline))
    {
        char byte;
        udelay(1000);
        if (exanic_i2c_eeprom_read(exanic, 0, &byte, 1) == 0)
            return 0;
    }

    return -ETIMEDOUT;
}

static int sfp_read(struct exanic *exanic, int port_number,
                    uint8_t devaddr, uint8_t regaddr, char *buffer, size_t size)
{
    struct i2c_adapter *sfp_adap = exanic_sfp_i2c_adapter(exanic, port_number);
    if (!sfp_adap)
        return -1;
    return exanic_i2c_read(sfp_adap, devaddr, regaddr, buffer, size);
}

static int sfp_write(struct exanic *exanic, int port_number,
                     uint8_t devaddr, uint8_t regaddr, char *buffer, size_t size)
{
    struct i2c_adapter *sfp_adap = exanic_sfp_i2c_adapter(exanic, port_number);
    if (!sfp_adap)
        return -1;
    return exanic_i2c_write(sfp_adap, devaddr, regaddr, buffer, size);
}

static void exanic_marvell_reset(struct exanic *exanic, unsigned port_number)
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

static void exanic_marvell_enable_fast_ethernet(struct exanic *exanic, unsigned port_number)
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

static int exanic_is_sfp_marvell(struct exanic *exanic, unsigned port_number)
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

static int exanic_optimize_phy_parameters(struct exanic *exanic, unsigned int port_number)
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

    if (exanic_i2c_phy_write(exanic, port_number, 0x10, rx_param, 3) == -1)
        return -1;
    if (exanic_i2c_phy_write(exanic, port_number, 0x16, tx_param, 3) == -1)
        return -1;

    return 0;
}

/* external functions */

int exanic_get_serial(struct exanic *exanic, unsigned char serial[ETH_ALEN])
{
    return exanic_i2c_eeprom_read(exanic, EEPROM_ADDR_SERIAL,
                                  serial, ETH_ALEN);
}

int exanic_sfp_eeprom_read(struct exanic *exanic, int port_number,
                           uint8_t regaddr, char *buffer, size_t size)
{
    return sfp_read(exanic, port_number, SFP_EEPROM_ADDR, regaddr, buffer, size);
}

int exanic_sfp_diag_read(struct exanic *exanic, int port_number,
                         uint8_t regaddr, char *buffer, size_t size)
{
    return sfp_read(exanic, port_number, SFP_DIAG_ADDR, regaddr, buffer, size);
}

int exanic_sfp_has_diag_page(struct exanic *exanic, int port_number, bool *has_diag)
{
    char diag_mon_type;
    int ret = 0;

    if ((ret = exanic_sfp_eeprom_read(exanic, port_number,
                                     SFP_DIAG_MON_BYTE, &diag_mon_type, 1)))
    {
        return ret;
    }

    *has_diag = false;
    if ((diag_mon_type & (1 << SFP_DIAG_MON_BIT)) == 0)
        *has_diag = true;

    return 0;
}

int exanic_poweron_port(struct exanic *exanic, unsigned port_number)
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
        if (exanic_i2c_phy_write(exanic, port_number, 0x7F, &reg_val, 1) == -1)
            return -1;
        if (exanic_i2c_phy_write(exanic, port_number, 0x00, init_regs, 12) == -1)
            return -1;
        return exanic_optimize_phy_parameters(exanic, port_number);
    }

    return 0;
}

int exanic_poweroff_port(struct exanic *exanic, unsigned port_number)
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

int exanic_save_feature_cfg(struct exanic *exanic)
{
    volatile uint32_t *registers = exanic_registers(exanic);
    char old, new;

    if (exanic_i2c_eeprom_read(exanic, EEPROM_BRIDGING_CFG, &old, 1) == -1)
        return -1;
    new = (registers[REG_EXANIC_INDEX(REG_EXANIC_FEATURE_CFG)]
            & EXANIC_FEATURE_BRIDGE_MIRROR_MASK);

    if (old == new)
        return 0;

    return exanic_i2c_eeprom_write(exanic, EEPROM_BRIDGING_CFG, &new, 1);
}

int exanic_save_speed(struct exanic *exanic, unsigned port_number,
                            unsigned speed)
{
    uint8_t regaddr = EEPROM_PORT_SPEED + port_number;
    char old, new;

    /* Save port speed setting to EEPROM */
    if (exanic_i2c_eeprom_read(exanic, regaddr, &old, 1) == -1)
        return -1;

    if (speed == SPEED_1000)
        new = PORT_SPEED_1G;
    else
        new = PORT_SPEED_10G;

    if (old == new)
        return 0;

    return exanic_i2c_eeprom_write(exanic, regaddr, &new, 1);
}

int exanic_save_autoneg(struct exanic *exanic, unsigned port_number,
                              bool autoneg)
{
    uint8_t regaddr = EEPROM_PORT_CFG + port_number;
    char old, new;

    /* Save autoneg setting to EEPROM */
    if (exanic_i2c_eeprom_read(exanic, regaddr, &old, 1) == -1)
        return -1;

    if (autoneg)
        new = old | PORT_CFG_AUTONEG;
    else
        new = old & ~PORT_CFG_AUTONEG;

    if (old == new)
        return 0;

    return exanic_i2c_eeprom_write(exanic, regaddr, &new, 1);
}

int exanic_set_speed(struct exanic *exanic, unsigned port_number,
                           unsigned old_speed, unsigned speed)
{
    if (speed == SPEED_100)
    {
        if (!exanic_is_sfp_marvell(exanic, port_number))
            return -1;

        exanic_marvell_enable_fast_ethernet(exanic, port_number);
        return 0;
    }
    else if (old_speed == SPEED_100)
    {
        exanic_marvell_reset(exanic, port_number);
    }
    return 0;
}
