/**
 * ExaNIC driver
 * Copyright (C) 2011-2019 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/miscdevice.h>
#include <linux/stringify.h>

#include "exanic.h"
#include "exanic-structs.h"
#include "exanic-i2c.h"

/* put exanic sysfs attributes here. add more as needed */

/* serial number */
static ssize_t
exanic_serial_number_show(struct device *dev, struct device_attribute *attr,
                          char *buf)
{
    struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);
    struct exanic *exanic = pci_get_drvdata(pdev);
    ssize_t ret = 0;
    char *ptr = buf;
    int i;

    if (!exanic->serial[0])
        return -EOPNOTSUPP;

    for (i = 0; i < sizeof(exanic->serial); i++)
    {
        int chars = sprintf(ptr, "%02hhX", exanic->serial[i]);
        ptr += chars;
        ret += chars;
    }

    ret += sprintf(ptr, "\n");
    return ret;
}

static DEVICE_ATTR(serial, 0444, exanic_serial_number_show, NULL);

/* external phy tuning options for X2 and X4, used by exanic-config for
 * analogue performance diagnosis and improvement */
struct exanic_ext_phy_attribute
{
    struct device_attribute dev_attr;
    int port;
};

#define EXANIC_EXT_PHY_ATTR(_name, _mode, _show, _store, _port)                 \
    { .dev_attr = __ATTR(_name, _mode, _show, _store),                          \
      .port = _port }

#define EXANIC_EXT_PHY_ATTR_FUNCS(_param)                                       \
    static ssize_t exanic_ext_phy_##_param##_show(struct device *dev,           \
            struct device_attribute *attr, char *buf)                           \
    {                                                                           \
        struct exanic_ext_phy_attribute *pattr =                                \
            container_of(attr, struct exanic_ext_phy_attribute, dev_attr);      \
        int port = pattr->port;                                                 \
        struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);          \
        struct exanic *exanic = pci_get_drvdata(pdev);                          \
        unsigned offset =                                                       \
            exanic_ext_phy_param_offsets[exanic_ext_phy_##_param];              \
        uint8_t byte;                                                           \
                                                                                \
        int ret = exanic_i2c_ext_phy_read(exanic, port, offset, &byte, 1);      \
        if (ret)                                                                \
            return ret;                                                         \
                                                                                \
        return sprintf(buf, "0x%02hhx\n", byte);                                \
    }                                                                           \
    static ssize_t exanic_ext_phy_##_param##_store(struct device *dev,          \
              struct device_attribute *attr, const char *buf,                   \
              size_t count)                                                     \
    {                                                                           \
        struct exanic_ext_phy_attribute *pattr =                                \
            container_of(attr, struct exanic_ext_phy_attribute, dev_attr);      \
        int port = pattr->port;                                                 \
        struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);          \
        struct exanic *exanic = pci_get_drvdata(pdev);                          \
        unsigned offset =                                                       \
            exanic_ext_phy_param_offsets[exanic_ext_phy_##_param];              \
        uint8_t mask = exanic_ext_phy_param_masks[exanic_ext_phy_##_param];     \
        uint8_t byte;                                                           \
        char end;                                                               \
                                                                                \
        int ret = sscanf(buf, "%hhi%c", &byte, &end);                           \
        if (ret < 1)                                                            \
        {                                                                       \
            dev_err(dev, __stringify(_param) " store: cannot parse\n");         \
            return -EINVAL;                                                     \
        }                                                                       \
                                                                                \
        if (ret > 1 && end != '\n')                                             \
        {                                                                       \
            dev_err(dev, __stringify(_param) " store: extra parameters\n");     \
            return -EINVAL;                                                     \
        }                                                                       \
                                                                                \
        if (byte & (~mask))                                                     \
        {                                                                       \
            dev_err(dev, __stringify(_param)                                    \
                        " store: parameter out of range (0 to %u)\n",           \
                        mask);                                                  \
            return -EINVAL;                                                     \
        }                                                                       \
                                                                                \
        ret = exanic_i2c_ext_phy_write(exanic, port, offset, &byte, 1);         \
        if (ret)                                                                \
        {                                                                       \
            dev_err(dev, "failed to write parameter \"" __stringify(_param)     \
                         "\" to external phy\n");                               \
            return ret;                                                         \
        }                                                                       \
                                                                                \
        return count;                                                           \
    }

#define EXANIC_PORT_EXT_PHY_TUNING_ATTR(_port, _item)                           \
    EXANIC_EXT_PHY_ATTR(_item, 0600,                                            \
                        exanic_ext_phy_##_item##_show,                          \
                        exanic_ext_phy_##_item##_store, _port)

#define EXANIC_PORT_EXT_PHY_TUNING_ATTRS(_port)                                 \
    EXANIC_PORT_EXT_PHY_TUNING_ATTR(_port, rx_gain),                            \
    EXANIC_PORT_EXT_PHY_TUNING_ATTR(_port, rx_preemphasis),                     \
    EXANIC_PORT_EXT_PHY_TUNING_ATTR(_port, rx_offset),                          \
    EXANIC_PORT_EXT_PHY_TUNING_ATTR(_port, tx_gain),                            \
    EXANIC_PORT_EXT_PHY_TUNING_ATTR(_port, tx_preemphasis),                     \
    EXANIC_PORT_EXT_PHY_TUNING_ATTR(_port, tx_slewrate)

/* phy parameter offset and mask */
enum
{
    exanic_ext_phy_rx_gain          = 0,
    exanic_ext_phy_rx_preemphasis   = 1,
    exanic_ext_phy_rx_offset        = 2,
    exanic_ext_phy_tx_gain          = 3,
    exanic_ext_phy_tx_preemphasis   = 4,
    exanic_ext_phy_tx_slewrate      = 5,
    exanic_ext_phy_tuning_nparams   = 6
};

/* i2c register addresses of various tuning parameters */
static unsigned exanic_ext_phy_param_offsets[exanic_ext_phy_tuning_nparams] =
{
    [exanic_ext_phy_rx_gain]        = EXANIC_EXT_PHY_RXGAIN_OFFSET,
    [exanic_ext_phy_rx_preemphasis] = EXANIC_EXT_PHY_RXBOOST_OFFSET,
    [exanic_ext_phy_rx_offset]      = EXANIC_EXT_PHY_RXOC_OFFSET,
    [exanic_ext_phy_tx_gain]        = EXANIC_EXT_PHY_TXODSW_OFFSET,
    [exanic_ext_phy_tx_preemphasis] = EXANIC_EXT_PHY_TXODPE_OFFSET,
    [exanic_ext_phy_tx_slewrate]    = EXANIC_EXT_PHY_TXODSLEW_OFFSET,
};

/* bitmasks/max values of various tuning parameters */
static uint8_t exanic_ext_phy_param_masks[exanic_ext_phy_tuning_nparams] =
{
    [exanic_ext_phy_rx_gain]        = EXANIC_EXT_PHY_RXGAIN_MASK,
    [exanic_ext_phy_rx_preemphasis] = EXANIC_EXT_PHY_RXBOOST_MASK,
    [exanic_ext_phy_rx_offset]      = EXANIC_EXT_PHY_RXOC_MASK,
    [exanic_ext_phy_tx_gain]        = EXANIC_EXT_PHY_TXODSW_MASK,
    [exanic_ext_phy_tx_preemphasis] = EXANIC_EXT_PHY_TXODPE_MASK,
    [exanic_ext_phy_tx_slewrate]    = EXANIC_EXT_PHY_TXODSLEW_MASK,
};

/* phy parameter setter/getters */
EXANIC_EXT_PHY_ATTR_FUNCS(rx_gain);
EXANIC_EXT_PHY_ATTR_FUNCS(rx_preemphasis);
EXANIC_EXT_PHY_ATTR_FUNCS(rx_offset);
EXANIC_EXT_PHY_ATTR_FUNCS(tx_gain);
EXANIC_EXT_PHY_ATTR_FUNCS(tx_preemphasis);
EXANIC_EXT_PHY_ATTR_FUNCS(tx_slewrate);

/* X2/X4 phy tuning attributes */
struct exanic_ext_phy_attribute
exanic_ext_phy_tuning_attrs[4][exanic_ext_phy_tuning_nparams] =
{
    {EXANIC_PORT_EXT_PHY_TUNING_ATTRS(0)},
    {EXANIC_PORT_EXT_PHY_TUNING_ATTRS(1)},
    {EXANIC_PORT_EXT_PHY_TUNING_ATTRS(2)},
    {EXANIC_PORT_EXT_PHY_TUNING_ATTRS(3)},
};

/* X2 and X4 external PHY loopback control */
static ssize_t
exanic_ext_phy_lb_show(struct device *dev, struct device_attribute *attr,
                       char *buf)
{
    struct exanic_ext_phy_attribute *pattr =
        container_of(attr, struct exanic_ext_phy_attribute, dev_attr);
    int port = pattr->port;
    struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);
    struct exanic *exanic = pci_get_drvdata(pdev);
    uint8_t byte;

    int ret =
        exanic_i2c_ext_phy_read(exanic, port, EXANIC_EXT_PHY_RXCLK_OFFSET,
                                &byte, 1);
    if (ret)
        return ret;

    if (byte & (1 << EXANIC_EXT_PHY_RXCLK_BIT_DIAG_LB))
        return sprintf(buf, "0\n");
    else
        return sprintf(buf, "1\n");
}

static ssize_t
exanic_ext_phy_lb_store(struct device *dev, struct device_attribute *attr,
                        const char *buf, size_t count)
{
    struct exanic_ext_phy_attribute *pattr =
        container_of(attr, struct exanic_ext_phy_attribute, dev_attr);
    int port = pattr->port;
    struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);
    struct exanic *exanic = pci_get_drvdata(pdev);

    uint8_t byte;
    uint8_t lb_en;
    char end;

    int ret = sscanf(buf, "%hhd%c", &lb_en, &end);
    if (ret < 1)
    {
        dev_err(dev, "lb store: cannot parse\n");
        return -EINVAL;
    }

    if (ret > 1 && end != '\n')
    {
        dev_err(dev, "lb store: extra parameters\n");
        return -EINVAL;
    }

    ret = exanic_i2c_ext_phy_read(exanic, port, EXANIC_EXT_PHY_RXCLK_OFFSET,
                                  &byte, 1);
    if (ret)
        return ret;

    if (!lb_en)
        byte |= (1 << EXANIC_EXT_PHY_RXCLK_BIT_DIAG_LB);
    else
        byte &= ~(1 << EXANIC_EXT_PHY_RXCLK_BIT_DIAG_LB);

    ret = exanic_i2c_ext_phy_write(exanic, port, EXANIC_EXT_PHY_RXCLK_OFFSET,
                                   &byte, 1);
    if (ret)
    {
        dev_err(dev, "failed to write RXCLK register to external phy\n");
        return ret;
    }

    dev_info(dev, "port %d diagnostic loopback %s\n",
                  port, lb_en ? "enabled" : "disabled");
    return count;
}

#define EXANIC_PORT_EXT_PHY_LB_ATTR(_port)                  \
    EXANIC_EXT_PHY_ATTR(loopback, 0600,                     \
                        exanic_ext_phy_lb_show,             \
                        exanic_ext_phy_lb_store, _port)

/* X2/X4 phy loopback attributes */
static struct exanic_ext_phy_attribute exanic_lb_attrs[] =
{
    EXANIC_PORT_EXT_PHY_LB_ATTR(0),
    EXANIC_PORT_EXT_PHY_LB_ATTR(1),
    EXANIC_PORT_EXT_PHY_LB_ATTR(2),
    EXANIC_PORT_EXT_PHY_LB_ATTR(3)
};

struct attribute *exanic_ext_phy_attrs_raw[4][exanic_ext_phy_tuning_nparams + 2] =
{
    {
        &(exanic_ext_phy_tuning_attrs[0][exanic_ext_phy_rx_gain].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[0][exanic_ext_phy_rx_preemphasis].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[0][exanic_ext_phy_rx_offset].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[0][exanic_ext_phy_tx_gain].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[0][exanic_ext_phy_tx_preemphasis].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[0][exanic_ext_phy_tx_slewrate].dev_attr.attr),
        &(exanic_lb_attrs[0].dev_attr.attr),
        NULL
    },

    {
        &(exanic_ext_phy_tuning_attrs[1][exanic_ext_phy_rx_gain].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[1][exanic_ext_phy_rx_preemphasis].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[1][exanic_ext_phy_rx_offset].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[1][exanic_ext_phy_tx_gain].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[1][exanic_ext_phy_tx_preemphasis].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[1][exanic_ext_phy_tx_slewrate].dev_attr.attr),
        &(exanic_lb_attrs[1].dev_attr.attr),
        NULL
    },

    {
        &(exanic_ext_phy_tuning_attrs[2][exanic_ext_phy_rx_gain].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[2][exanic_ext_phy_rx_preemphasis].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[2][exanic_ext_phy_rx_offset].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[2][exanic_ext_phy_tx_gain].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[2][exanic_ext_phy_tx_preemphasis].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[2][exanic_ext_phy_tx_slewrate].dev_attr.attr),
        &(exanic_lb_attrs[2].dev_attr.attr),
        NULL
    },

    {
        &(exanic_ext_phy_tuning_attrs[3][exanic_ext_phy_rx_gain].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[3][exanic_ext_phy_rx_preemphasis].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[3][exanic_ext_phy_rx_offset].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[3][exanic_ext_phy_tx_gain].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[3][exanic_ext_phy_tx_preemphasis].dev_attr.attr),
        &(exanic_ext_phy_tuning_attrs[3][exanic_ext_phy_tx_slewrate].dev_attr.attr),
        &(exanic_lb_attrs[3].dev_attr.attr),
        NULL
    },
};

const struct attribute_group exanic_ext_phy_attr_groups[4] =
{
    {.name = "port0_phy", .attrs = exanic_ext_phy_attrs_raw[0]},
    {.name = "port1_phy", .attrs = exanic_ext_phy_attrs_raw[1]},
    {.name = "port2_phy", .attrs = exanic_ext_phy_attrs_raw[2]},
    {.name = "port3_phy", .attrs = exanic_ext_phy_attrs_raw[3]},
};

int exanic_sysfs_init(struct exanic *exanic)
{
    int ret = device_create_file(&exanic->pci_dev->dev, &dev_attr_serial);
    int i;

    if (exanic->hw_id != EXANIC_HW_X2 && exanic->hw_id != EXANIC_HW_X4)
        return ret;

    /* optionally create external PHY attributes for X2 and X4 */
    for (i = 0; i < exanic->hwinfo.nports; i++)
    {
        ret = sysfs_create_group(&exanic->pci_dev->dev.kobj,
                                 &exanic_ext_phy_attr_groups[i]);
        if (ret)
            return ret;
    }

    return 0;
}

void exanic_sysfs_exit(struct exanic *exanic)
{
    int i = 0;
    device_remove_file(&exanic->pci_dev->dev, &dev_attr_serial);

    if (exanic->hw_id != EXANIC_HW_X2 && exanic->hw_id != EXANIC_HW_X4)
        return;

    /* remove external PHY attributes for X2 and X4 */
    for (i = 0; i < exanic->hwinfo.nports; i++)
        sysfs_remove_group(&exanic->pci_dev->dev.kobj,
                           &exanic_ext_phy_attr_groups[i]);
}
