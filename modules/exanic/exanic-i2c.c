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
#include "exanic-i2c.h"
#include "exanic-structs.h"

/* Maximum number of I2C clock cycles to send during bus clear sequence
 * using a very large number here for reliability */
#define I2C_RESET_CYCLES                100

/* ExaNIC eeprom write completion timeout in jiffies */
#define EEPROM_WRITE_TIMEOUT            HZ

/* Fields in the exanic eeprom */

/* Serial number */
#define EXANIC_EEPROM_ADDR_SERIAL       0x00

/* Bridging and mirroring configuration */
#define EXANIC_EEPROM_BRIDGING_CFG      0x40

/* Port speed settings, 1 byte for each port */
#define EXANIC_EEPROM_PORT_SPEED        0x50

#define EXANIC_EEPROM_SPEED_1G          0x01
#define EXANIC_EEPROM_SPEED_10G         0x02

/* For compatibility */
#ifndef min3
#define min3(x, y, z)                   min((typeof(x))min(x, y), z)
#endif

/* x4 and x2 phy chip addresses */
static struct {
    int bus;
    int devaddr;
} x2_x4_ext_phy_i2c[] = {
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

    return -EIO;
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
exanic_xcvr_i2c_adapter(struct exanic *exanic, unsigned port_num)
{
    if (port_num >= exanic->num_ports)
        return NULL;

    return exanic->xcvr_i2c_adapters[port_num];
}

static struct i2c_adapter *
exanic_ext_phy_i2c_adapter(struct exanic *exanic, unsigned port_num)
{
    if (exanic->hw_id != EXANIC_HW_X2 && exanic->hw_id != EXANIC_HW_X4)
        return NULL;

    if (port_num >= exanic->num_ports)
        return NULL;

    return exanic->ext_phy_i2c_adapters[port_num];
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
 * external phy given ethernet interface number */

static int
exanic_i2c_xcvr_bus_number(struct exanic *exanic, int port_num)
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
exanic_i2c_ext_phy_bus_number(struct exanic *exanic, int port_num)
{
    if (exanic->hw_id != EXANIC_HW_X2 && exanic->hw_id != EXANIC_HW_X4)
        return -1;

    return x2_x4_ext_phy_i2c[port_num].bus;
}

/* expect "8-bit" device addresses, i.e. with the r/w bit attached */

static int
__exanic_i2c_read(struct i2c_adapter *adap, uint8_t devaddr,
                  uint8_t regaddr, uint8_t *buffer, size_t size,
                  int (*xfer)(struct i2c_adapter *, struct i2c_msg *, int))
{
    struct i2c_msg msg[2];
    int ret;
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

    ret = xfer(adap, msg, 2);
    if (ret < 0)
        return ret;

    if (ret < 2)
        return -EIO;

    return 0;
}

static int exanic_i2c_read(struct i2c_adapter *adap, uint8_t devaddr,
                           uint8_t regaddr, uint8_t *buffer, size_t size)
{
    return __exanic_i2c_read(adap, devaddr, regaddr, buffer, size,
                             i2c_transfer);
}

/* burst write with no transaction length check */
static int
__exanic_i2c_seq_write(struct i2c_adapter *adap, uint8_t devaddr,
                        uint8_t regaddr, uint8_t *buffer, size_t size,
                        int (*xfer)(struct i2c_adapter *, struct i2c_msg *, int))
{
    struct i2c_msg msg[2];
    int ret;
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

    ret = xfer(adap, msg, 2);
    if (ret < 0)
        return ret;

    if (ret < 2)
        return -EIO;

    return 0;
}

static int
exanic_i2c_seq_write(struct i2c_adapter *adap, uint8_t devaddr,
                      uint8_t regaddr, uint8_t *buffer, size_t size)
{
    return __exanic_i2c_seq_write(adap, devaddr, regaddr, buffer, size,
                                  i2c_transfer);
}

static int exanic_i2c_write(struct i2c_adapter *adap, uint8_t devaddr,
                            uint8_t regaddr, uint8_t *buffer, size_t size)
{
    uint8_t *ptr = buffer;
    size_t rem = size;
    uint8_t curr_addr = regaddr;
    int ret;

    struct exanic_i2c_data *data =
            container_of(adap, struct exanic_i2c_data, adap);

    /* no limit, write whole thing in one go */
    if (data->write_len == 0)
        return exanic_i2c_seq_write(adap, devaddr, regaddr, buffer, size);

    while (rem)
    {
        uint8_t page_offset = curr_addr & (data->page_len - 1);
        size_t page_rem = data->page_len - page_offset;
        size_t wrsize;

        if (data->page_len)
            wrsize = min3(rem, page_rem, data->write_len);
        else
            wrsize = min(rem, data->write_len);

        if ((ret = exanic_i2c_seq_write(adap, devaddr, curr_addr, ptr, wrsize)))
            return ret;

        ptr += wrsize;
        curr_addr += wrsize;
        rem -= wrsize;
    }

    return 0;
}

/* custom i2c algorithm, wraps over i2c_algo_bit */
static int
exanic_i2c_master_xfer(struct i2c_adapter *adap, struct i2c_msg *msgs, int num)
{
    struct i2c_algo_bit_data *algo_data =
        (struct i2c_algo_bit_data *)adap->algo_data;
    struct exanic_i2c_data *exanic_data = algo_data->data;
    struct exanic_i2c_data_qsfp_common *exanic_data_qsfp;
    struct exanic *exanic = exanic_data->exanic;

    int phys_port = 0;
    bool toggle_modsel = false;
    bool page_switch = false;

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

    /* QSFP and QSFPDD specific operations */
    exanic_data_qsfp = (struct exanic_i2c_data_qsfp_common *)exanic_data;
    if (exanic_data->type == EXANIC_I2C_ADAP_QSFP ||
        exanic_data->type == EXANIC_I2C_ADAP_QSFPDD)
    {
        page_switch = exanic_data_qsfp->flags.fields.page_switch;
        toggle_modsel = true;
        phys_port = exanic_data_qsfp->phys_port;
    }

    if (toggle_modsel)
    {
        /* drive modsel low to select module */
        volatile uint32_t *registers = exanic_registers(exanic);
        registers[REG_HW_INDEX(REG_HW_I2C_GPIO)] &=
            ~(1 << (EXANIC_GPIO_MOD0NSEL + phys_port));
        msleep(2);
    }

    ret = exanic_i2c_reset(exanic_data);
    if (ret)
        goto modsel_unassert;

    if (!page_switch)
        goto do_xfer;

    /* select page and bank in the same MODSEL bracket */
    if (exanic_data_qsfp->flags.fields.qsfp)
    {
        ret = __exanic_i2c_seq_write(adap, XCVR_EEPROM_ADDR, QSFP_PAGE_SEL_BYTE,
                                     &exanic_data_qsfp->page, 1,
                                     exanic_data->xfer_wrapped);
    }
    else
    {
        uint8_t page_switch_bytes[] =
            {exanic_data_qsfp->bank, exanic_data_qsfp->page};

        /* CMIS rev 4 requires page and bank select in the same transaction */
        if (exanic_data_qsfp->flags.fields.cmis_4)
            ret = __exanic_i2c_seq_write(adap, XCVR_EEPROM_ADDR, CMIS_BANK_SEL_BYTE,
                                         page_switch_bytes, 2,
                                         exanic_data->xfer_wrapped);
        else
            ret = __exanic_i2c_seq_write(adap, XCVR_EEPROM_ADDR, CMIS_BANK_SEL_BYTE,
                                         &page_switch_bytes[0], 1,
                                         exanic_data->xfer_wrapped) ||
                  __exanic_i2c_seq_write(adap, XCVR_EEPROM_ADDR, CMIS_PAGE_SEL_BYTE,
                                         &page_switch_bytes[1], 1,
                                         exanic_data->xfer_wrapped);
    }

    if (ret)
        goto modsel_unassert;

do_xfer:
    /* perform i2c transfer */
    ret = exanic_data->xfer_wrapped(adap, msgs, num);

modsel_unassert:
    if (toggle_modsel)
    {
        /* drive modsel high to deselect module */
        volatile uint32_t *registers = exanic_registers(exanic);
        registers[REG_HW_INDEX(REG_HW_I2C_GPIO)] |=
            (1 << (EXANIC_GPIO_MOD0NSEL + phys_port));
        msleep(2);
    }

    mutex_unlock(&exanic_data->exanic->i2c_lock);
    return ret;
}

static struct i2c_algorithm exanic_i2c_bit_algo =
{
    .master_xfer = exanic_i2c_master_xfer,
};

static int
exanic_i2c_bus_allocate(struct exanic *exanic, int port,
                        int bus, int type, struct i2c_adapter **radap,
                        bool *new_bus)
{
    struct exanic_i2c_data *data;
    int phys_port = exanic_to_phys_port(exanic, port);
    size_t data_size;

    switch (type)
    {
        case EXANIC_I2C_ADAP_QSFP:
        case EXANIC_I2C_ADAP_QSFPDD:
            data_size = sizeof(struct exanic_i2c_data_qsfp_common);
            goto check_existing_bus;

        default:
            data_size = sizeof(struct exanic_i2c_data);
            goto do_i2c_alloc;
    }

check_existing_bus:
    list_for_each_entry(data, &exanic->i2c_list, link)
    {
        int phys_port_registered;
        if (type != data->type)
            continue;

        phys_port_registered =
            ((struct exanic_i2c_data_qsfp_common *)data)->phys_port;

        if (phys_port_registered == phys_port)
        {
            *radap = &data->adap;
            *new_bus = false;
            return 0;
        }
    }

do_i2c_alloc:
    data = devm_kzalloc(&exanic->pci_dev->dev, data_size, GFP_KERNEL);
    if (!data)
        return -ENOMEM;
    *radap = &data->adap;
    *new_bus = true;
    return 0;
}

static int
exanic_i2c_bus_register(struct exanic *exanic, int port,
                        int bus, int type, bool scl_sense,
                        struct i2c_adapter **radap)
{
    struct exanic_i2c_data *data;
    struct i2c_adapter *adap;
    bool new_bus = false;
    int phys_port = exanic_to_phys_port(exanic, port);

    int ret = exanic_i2c_bus_allocate(exanic, port, bus, type,
                                      radap, &new_bus);
    if (ret || !new_bus)
        return ret;

    adap = *radap;
    data = container_of(adap, struct exanic_i2c_data, adap);

    data->bus_number = bus;
    data->type = type;
    if (type == EXANIC_I2C_ADAP_QSFP || type == EXANIC_I2C_ADAP_QSFPDD)
        ((struct exanic_i2c_data_qsfp_common *)data)->phys_port = phys_port;

    switch (type)
    {
        case EXANIC_I2C_ADAP_QSFP:
        case EXANIC_I2C_ADAP_QSFPDD:
        case EXANIC_I2C_ADAP_SFP:
            snprintf(adap->name, sizeof adap->name,
                     "%s:%d-xcvr", exanic->name, port);
            /* avoid sequential write as much as possible
             * setting write_len to 2 for compatibility with marvell phy */
            data->write_len = 2;
            data->page_len = 128;
            break;

        case EXANIC_I2C_ADAP_EXT_PHY:
            /* no TWI transaction limits
             * see VSC8479 datasheet */
            data->write_len = 0;
            data->page_len = 0;

            snprintf(adap->name, sizeof adap->name,
                     "%s:%d-phy", exanic->name, port);
            break;

        /* ExaNIC EEPROM */
        default:
            /* see 24AA08 datasheet */
            data->write_len = EXANIC_EEPROM_PAGE_SIZE;
            data->page_len = EXANIC_EEPROM_PAGE_SIZE;

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

    /* replace i2c algorithm with wrapper */
    data->xfer_wrapped = adap->algo->master_xfer;
    exanic_i2c_bit_algo.functionality = adap->algo->functionality;
    adap->algo = &exanic_i2c_bit_algo;

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
    bool external_phy = false;
    bool scl_sense = exanic_supports_scl_sense(exanic);
    int busno;
    struct i2c_adapter *bus;
    int xcvr_type;

    mutex_init(&exanic->i2c_lock);
    INIT_LIST_HEAD(&exanic->i2c_list);

    /* older ExaNIC cards have external phy controlled by i2c
     * whereas newer designs use on-chip gigabit transceivers */
    if (exanic->hw_id == EXANIC_HW_X2 || exanic->hw_id == EXANIC_HW_X4)
        external_phy = true;

    /* register all pluggable transceiver busses */
    xcvr_type =
        exanic->hwinfo.port_ff == EXANIC_PORT_QSFP ? EXANIC_I2C_ADAP_QSFP :
        exanic->hwinfo.port_ff == EXANIC_PORT_QSFPDD ? EXANIC_I2C_ADAP_QSFPDD :
        EXANIC_I2C_ADAP_SFP;

    for (i = 0; i < exanic->num_ports; ++i)
    {
        busno = exanic_i2c_xcvr_bus_number(exanic, i);
        ret = exanic_i2c_bus_register(exanic, i, busno,
                                      xcvr_type, scl_sense, &bus);
        if (ret)
        {
            dev_err(&exanic->pci_dev->dev,
                    "Failed to register port %d pluggable transceiver i2c bus\n", i);
            goto err_i2c_bus;
        }

        exanic->xcvr_i2c_adapters[i] = bus;
    }

    /* register all external phy busses */
    if (external_phy)
        for (i = 0; i < exanic->num_ports; ++i)
        {
            busno = exanic_i2c_ext_phy_bus_number(exanic, i);
            ret = exanic_i2c_bus_register(exanic, i, busno,
                                          EXANIC_I2C_ADAP_EXT_PHY, scl_sense, &bus);
            if (ret)
            {
                dev_err(&exanic->pci_dev->dev,
                        "Failed to register port %d PHY chip i2c bus\n", i);
                goto err_i2c_bus;
            }

            exanic->ext_phy_i2c_adapters[i] = bus;
        }

    /* register ExaNIC EEPROM bus */
    busno = exanic->hwinfo.eep_bus;
    ret = exanic_i2c_bus_register(exanic, 0, busno, EXANIC_I2C_ADAP_EEP,
                                  scl_sense, &bus);
    if (ret)
    {
        dev_err(&exanic->pci_dev->dev,
                "Failed to register ExaNIC EEPROM bus\n");
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

/* external functions */

int exanic_get_serial(struct exanic *exanic, unsigned char serial[ETH_ALEN])
{
    return exanic_i2c_eeprom_read(exanic, EXANIC_EEPROM_ADDR_SERIAL,
                                  serial, ETH_ALEN);
}

int exanic_save_feature_cfg(struct exanic *exanic)
{
    volatile uint32_t *registers = exanic_registers(exanic);
    char old, new;
    int ret;

    if ((ret = exanic_i2c_eeprom_read(exanic, EXANIC_EEPROM_BRIDGING_CFG, &old, 1)))
        return ret;
    new = (registers[REG_EXANIC_INDEX(REG_EXANIC_FEATURE_CFG)]
            & EXANIC_FEATURE_BRIDGE_MIRROR_MASK);

    if (old == new)
        return 0;

    return exanic_i2c_eeprom_write(exanic, EXANIC_EEPROM_BRIDGING_CFG, &new, 1);
}

int exanic_save_speed(struct exanic *exanic, unsigned port_number,
                      unsigned speed)
{
    uint8_t regaddr = EXANIC_EEPROM_PORT_SPEED + port_number;
    char old, new;
    int ret;

    /* Save port speed setting to EXANIC_EEPROM */
    if ((ret = exanic_i2c_eeprom_read(exanic, regaddr, &old, 1)))
        return ret;

    if (speed == SPEED_1000)
        new = EXANIC_EEPROM_SPEED_1G;
    else
        new = EXANIC_EEPROM_SPEED_10G;

    if (old == new)
        return 0;

    return exanic_i2c_eeprom_write(exanic, regaddr, &new, 1);
}

int exanic_save_autoneg(struct exanic *exanic, unsigned port_number,
                        bool autoneg)
{
    uint8_t regaddr = EXANIC_EEPROM_PORT_CFG + port_number;
    char old, new;
    int ret;

    /* Save autoneg setting to EXANIC_EEPROM */
    if ((ret = exanic_i2c_eeprom_read(exanic, regaddr, &old, 1)))
        return ret;

    if (autoneg)
        new = old | EXANIC_EEPROM_AUTONEG;
    else
        new = old & ~EXANIC_EEPROM_AUTONEG;

    if (old == new)
        return 0;

    return exanic_i2c_eeprom_write(exanic, regaddr, &new, 1);
}

int exanic_i2c_xcvr_read(struct exanic *exanic, int port_number,
                        uint8_t devaddr, uint8_t regaddr, uint8_t *buffer,
                        size_t size)
{
    struct i2c_adapter *xcvr_adap = exanic_xcvr_i2c_adapter(exanic, port_number);
    if (!xcvr_adap)
        return -ENODEV;
    return exanic_i2c_read(xcvr_adap, devaddr, regaddr, buffer, size);
}

int exanic_i2c_xcvr_write(struct exanic *exanic, int port_number,
                         uint8_t devaddr, uint8_t regaddr, uint8_t *buffer,
                         size_t size)
{
    struct i2c_adapter *xcvr_adap = exanic_xcvr_i2c_adapter(exanic, port_number);
    if (!xcvr_adap)
        return -ENODEV;
    return exanic_i2c_write(xcvr_adap, devaddr, regaddr, buffer, size);
}

int exanic_i2c_xcvr_sff8024_id(struct exanic *exanic, int port, uint8_t *id)
{
    return exanic_i2c_xcvr_read(exanic, port, XCVR_EEPROM_ADDR,
                                SFF_8024_ID_BYTE, id, 1);
}

int exanic_i2c_sfp_has_diag_page(struct exanic *exanic, int port_number, bool *has_diag)
{
    char diag_mon_type;
    int ret = exanic_i2c_xcvr_read(exanic, port_number, XCVR_EEPROM_ADDR,
                                   SFP_DIAG_MON_BYTE, &diag_mon_type, 1);
    if (ret)
        return ret;

    *has_diag = (diag_mon_type & (1 << SFP_DIAG_MON_BIT)) != 0;
    return 0;
}

int exanic_i2c_qsfp_flat_mem(struct exanic *exanic, int port, bool *flat)
{
    char status_byte;
    int ret = exanic_i2c_xcvr_read(exanic, port, XCVR_EEPROM_ADDR,
                                   QSFP_FLAT_MEM_BYTE, &status_byte, 1);
    if (ret)
        return ret;

    *flat = (status_byte & (1 << QSFP_FLAT_MEM_BIT)) != 0;
    return 0;
}

/* reset to page 0 */
static int
exanic_i2c_qsfp_page_rst(struct exanic *exanic, int port)
{
    uint8_t page = 0;
    return exanic_i2c_xcvr_write(exanic, port, XCVR_EEPROM_ADDR,
                                 QSFP_PAGE_SEL_BYTE, &page, 1);
}

int exanic_i2c_qsfp_page_sel(struct exanic *exanic, int port, uint8_t page)
{
    struct exanic_i2c_data *i2c_data;
    struct exanic_i2c_data_qsfp_common *i2c_data_cmis;
    struct i2c_adapter *xcvr_adap;

    xcvr_adap = exanic_xcvr_i2c_adapter(exanic, port);
    if (!xcvr_adap)
        return -ENODEV;

    i2c_data = container_of(xcvr_adap, struct exanic_i2c_data, adap);
    if (i2c_data->type != EXANIC_I2C_ADAP_QSFP &&
        i2c_data->type != EXANIC_I2C_ADAP_QSFPDD)
        return -ENODEV;

    i2c_data_cmis = (struct exanic_i2c_data_qsfp_common *)i2c_data;
    i2c_data_cmis->flags.data = 0;

    /* send i2c transactions now if selecting default page */
    if (page == 0)
        return exanic_i2c_qsfp_page_rst(exanic, port);

    /* record upper page for later transactions */
    i2c_data_cmis->flags.fields.page_switch = 1;
    i2c_data_cmis->flags.fields.qsfp = 1;
    i2c_data_cmis->page = page;
    return 0;
}

int exanic_i2c_cmis_rev(struct exanic *exanic, int port, uint8_t *rev)
{
    uint8_t cmis_rev;
    int err = exanic_i2c_xcvr_read(exanic, port, XCVR_EEPROM_ADDR,
                                   CMIS_REV_COMP_BYTE, &cmis_rev, 1);
    if (err)
        return err;

    *rev = cmis_rev;
    return 0;
}

int exanic_i2c_cmis_flat_mem(struct exanic *exanic, int port, bool *flat)
{
    char status_byte;
    int ret = exanic_i2c_xcvr_read(exanic, port, XCVR_EEPROM_ADDR,
                                   CMIS_FLAT_MEM_BYTE, &status_byte, 1);
    if (ret)
        return ret;

    *flat = (status_byte & (1 << CMIS_FLAT_MEM_BIT)) != 0;
    return 0;
}

/* reset to page 0 bank 0 */
static int
exanic_i2c_cmis_page_rst(struct exanic *exanic, int port, bool cmis_4)
{
    uint8_t page = 0, bank = 0;
    int err;

    /* rev4, bank/page sel take place in the same TWI transaction */
    if (cmis_4)
    {
        uint8_t bytes[] = {bank, page};
        return exanic_i2c_xcvr_write(exanic, port, XCVR_EEPROM_ADDR,
                                     CMIS_BANK_SEL_BYTE, bytes, 2);
    }

    /* separate transactions for bank/page sel */
    err = exanic_i2c_xcvr_write(exanic, port, XCVR_EEPROM_ADDR,
                                CMIS_BANK_SEL_BYTE, &bank, 1);
    if (err)
        return err;

    return exanic_i2c_xcvr_write(exanic, port, XCVR_EEPROM_ADDR,
                                 CMIS_PAGE_SEL_BYTE, &page, 1);
}

int exanic_i2c_cmis_page_sel(struct exanic *exanic, int port,
                             uint8_t bank, uint8_t page)
{
    struct exanic_i2c_data *i2c_data;
    struct exanic_i2c_data_qsfp_common *i2c_data_cmis;
    struct i2c_adapter *xcvr_adap;
    uint8_t cmis_rev;
    bool cmis_4;
    int err;

    xcvr_adap = exanic_xcvr_i2c_adapter(exanic, port);
    if (!xcvr_adap)
        return -ENODEV;

    i2c_data = container_of(xcvr_adap, struct exanic_i2c_data, adap);
    if (i2c_data->type != EXANIC_I2C_ADAP_QSFPDD)
        return -ENODEV;

    i2c_data_cmis = (struct exanic_i2c_data_qsfp_common *)i2c_data;

    err = exanic_i2c_cmis_rev(exanic, port, &cmis_rev);
    if (err)
        return err;

    i2c_data_cmis->flags.data = 0;
    cmis_4 = cmis_rev >= CMIS_REV_BYTE(4, 0);
    /* send i2c transactions now if selecting default bank and page */
    if (bank == 0 && page == 0)
        return exanic_i2c_cmis_page_rst(exanic, port, cmis_4);

    /* record upper page and bank for later transactions */
    i2c_data_cmis->flags.fields.page_switch = 1;
    i2c_data_cmis->flags.fields.cmis_4 = cmis_4;
    i2c_data_cmis->page = page;
    i2c_data_cmis->bank = bank;
    return 0;
}

int exanic_i2c_ext_phy_write(struct exanic *exanic, int phy_number,
                             uint8_t regaddr, uint8_t *buffer, size_t size)
{
    uint8_t slave_addr;
    struct i2c_adapter *phy_adap;
    if (phy_number >=
        sizeof(x2_x4_ext_phy_i2c) / sizeof(x2_x4_ext_phy_i2c[0]))
        return -EINVAL;

    phy_adap = exanic_ext_phy_i2c_adapter(exanic, phy_number);
    if (!phy_adap)
        return -ENODEV;

    slave_addr = x2_x4_ext_phy_i2c[phy_number].devaddr;
    return exanic_i2c_write(phy_adap, slave_addr, regaddr, buffer, size);
}

int exanic_i2c_ext_phy_read(struct exanic *exanic, int phy_number,
                            uint8_t regaddr, uint8_t *buffer, size_t size)
{
    uint8_t slave_addr;
    struct i2c_adapter *phy_adap;
    if (phy_number >=
        sizeof(x2_x4_ext_phy_i2c) / sizeof(x2_x4_ext_phy_i2c[0]))
        return -EINVAL;

    phy_adap = exanic_ext_phy_i2c_adapter(exanic, phy_number);
    if (!phy_adap)
        return -ENODEV;

    slave_addr = x2_x4_ext_phy_i2c[phy_number].devaddr;
    return exanic_i2c_read(phy_adap, slave_addr, regaddr, buffer, size);
}

int exanic_i2c_eeprom_read(struct exanic *exanic, uint8_t regaddr,
                           uint8_t *buffer, size_t size)
{
    uint8_t slave_addr = exanic->hwinfo.eep_addr;
    struct i2c_adapter *eep_adap = exanic_eeprom_i2c_adapter(exanic);
    if (!eep_adap)
        return -ENODEV;
    return exanic_i2c_read(eep_adap, slave_addr, regaddr, buffer, size);
}

int exanic_i2c_eeprom_write(struct exanic *exanic, uint8_t regaddr,
                            uint8_t *buffer, size_t size)
{
    uint8_t slave_addr = exanic->hwinfo.eep_addr;
    struct i2c_adapter *eep_adap = exanic_eeprom_i2c_adapter(exanic);
    unsigned long deadline;
    int ret;

    if (!eep_adap)
        return -ENODEV;

    ret = exanic_i2c_write(eep_adap, slave_addr, regaddr, buffer, size);
    if (ret)
        return ret;

    deadline = jiffies + EEPROM_WRITE_TIMEOUT;
    /* wait for the write cycle to finish */
    while (!time_after(jiffies, deadline))
    {
        char byte;
        udelay(1000);
        if (exanic_i2c_eeprom_read(exanic, 0, &byte, 1) == 0)
            return 0;
    }

    return -EIO;
}
