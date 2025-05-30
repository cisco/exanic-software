/**
 * ExaNIC driver
 * Copyright (C) 2011-2013 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#undef DEBUG
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/miscdevice.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/nodemask.h>
#include <linux/pci.h>
#ifndef PCIE_LINK_STATE_L0S
#include <linux/pci-aspm.h>
#endif
#include <linux/interrupt.h>
#if defined(CONFIG_PCIEAER)
#include <linux/aer.h>
#endif
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/if_arp.h>
#include <linux/vmalloc.h>
#include <asm/byteorder.h>
#include <asm/uaccess.h>

#include "../../libs/exanic/pcie_if.h"
#include "../../libs/exanic/ioctl.h"
#include "exanic.h"
#include "exanic-i2c.h"
#include "exanic-structs.h"

#if defined(__BYTE_ORDER) ? __BYTE_ORDER == __BIG_ENDIAN : defined(__BIG_ENDIAN)
  #error "This ExaNIC driver version does not support big-endian platforms. Please contact support@exablaze.com for assistance."
#endif

static struct pci_device_id exanic_pci_ids[] = {
    { PCI_DEVICE(PCI_VENDOR_ID_EXABLAZE, PCI_DEVICE_ID_EXANIC_X4) },
    { PCI_DEVICE(PCI_VENDOR_ID_EXABLAZE, PCI_DEVICE_ID_EXANIC_X2) },
    { PCI_DEVICE(PCI_VENDOR_ID_EXABLAZE, PCI_DEVICE_ID_EXANIC_X10) },
    { PCI_DEVICE(PCI_VENDOR_ID_EXABLAZE, PCI_DEVICE_ID_EXANIC_X10_GM) },
    { PCI_DEVICE(PCI_VENDOR_ID_EXABLAZE, PCI_DEVICE_ID_EXANIC_X40) },
    { PCI_DEVICE(PCI_VENDOR_ID_EXABLAZE, PCI_DEVICE_ID_EXANIC_X10_HPT) },
    { PCI_DEVICE(PCI_VENDOR_ID_EXABLAZE, PCI_DEVICE_ID_EXANIC_X40_40G) },
    { PCI_DEVICE(PCI_VENDOR_ID_EXABLAZE, PCI_DEVICE_ID_EXANIC_V5P) },
    { PCI_DEVICE(PCI_VENDOR_ID_EXABLAZE, PCI_DEVICE_ID_EXANIC_X25) },
    { PCI_DEVICE(PCI_VENDOR_ID_EXABLAZE, PCI_DEVICE_ID_EXANIC_X100) },
    { PCI_DEVICE(PCI_VENDOR_ID_EXABLAZE, PCI_DEVICE_ID_EXANIC_V9P) },
    { PCI_DEVICE(PCI_VENDOR_ID_EXABLAZE, PCI_DEVICE_ID_EXANIC_V9P_3) },
    { 0, }
};
MODULE_DEVICE_TABLE(pci, exanic_pci_ids);

/**
 * Module command line parameters
 */
#define MACADDR_PARAM_LEN 64
static char exanic_macaddr_param[MACADDR_PARAM_LEN];
module_param_string(macaddr, exanic_macaddr_param, MACADDR_PARAM_LEN, 0);
MODULE_PARM_DESC(macaddr, "MAC address for cards with no EEPROM");

static u8 next_mac_addr[ETH_ALEN] = {
    0x64, 0x3F, 0x5F, 0x00, 0x00, 0x00
};

/* Mirroring support always available on legacy 4-port cards regardless of
 * capability bit */
#define EXANIC_MIRRORING_SUPPORT(exanic) \
                                    ((exanic)->caps & EXANIC_CAP_MIRRORING || \
                                     (exanic)->hw_id == EXANIC_HW_X4)

/* Bridging support always available on older cards regardless of
 * capability bit */
#define EXANIC_BRIDGING_SUPPORT(exanic) \
                                    ((exanic)->caps & EXANIC_CAP_BRIDGING || \
                                     (exanic)->hw_id == EXANIC_HW_X2      || \
                                     (exanic)->hw_id == EXANIC_HW_X4)

/* Breakout firmware available for qsfp and qsfpdd cards */
#define EXANIC_BREAKOUT_SUPPORT(exanic) ((exanic)->hwinfo.port_ff != EXANIC_PORT_SFP)

/**
 * Configure flow hashing for an ExaNIC port.
 */
void exanic_configure_port_hash(struct exanic *exanic, unsigned port,
                                bool enable, unsigned mask, unsigned function)
{
    uint32_t val = 0;

    if (enable)
    {
        exanic->port[port].flow_hashing_enabled = true;
        val |= EXANIC_PORT_HASH_ENABLE;
    }
    else
        exanic->port[port].flow_hashing_enabled = false;

    val |= (mask << EXANIC_PORT_HASH_MASK_SHIFT) &
             EXANIC_PORT_HASH_MASK_MASK;
    val |= (function << EXANIC_PORT_HASH_FUNCTION_SHIFT) &
                        EXANIC_PORT_HASH_FUNCTION_MASK;

    writel(val, exanic->regs_virt +
        REG_PORT_OFFSET(port, REG_PORT_HASH_CONFIG));

}

/**
 * Return true if the port is currently enabled.
 */
bool exanic_port_enabled(struct exanic *exanic, unsigned port_num)
{
    struct exanic_port *port = &exanic->port[port_num];
    return port->enabled;
}

/**
 * Return true if the RX region for the port is in use.
 */
bool exanic_rx_in_use(struct exanic *exanic, unsigned port_num)
{
    unsigned buffer_num;

    /* Check for in-kernel users */
    if (exanic->port[port_num].rx_refcount > 0)
        return true;

    if (exanic->port[port_num].rx_region_virt)
    {
        /* Check if the region is mapped */
        if (page_count(virt_to_page(exanic->port[port_num].rx_region_virt)) > 1)
            return true;
    }

    /* Check for in-use filter buffers */
    for (buffer_num = 0; buffer_num < exanic->max_filter_buffers; buffer_num++)
    {
        if (exanic->port[port_num].filter_buffers[buffer_num].refcount > 0)
            return true;
    }

    return false;
}

/**
 * Return the number of users of a TX feedback region
 */
int exanic_count_tx_feedback_users(struct exanic *exanic)
{
    int i, count = 0;

    /* Check if the region is mapped */
    if (exanic->tx_feedback_virt)
    {
        for (i = 0; i < EXANIC_TX_FEEDBACK_NUM_PAGES; i++)
            /* subtract 1 since we have a mapping */
            count += page_count(virt_to_page(exanic->tx_feedback_virt + i * PAGE_SIZE)) - 1;

        return count;
    }

    return 0;
}

/**
 * Return the number of users of an RX region
 */
int exanic_count_rx_users(struct exanic *exanic)
{
    unsigned buf;
    int i, count = 0;

    for (i = 0; i < exanic->num_ports; i++)
    {
        if (exanic->port[i].rx_region_virt)
            /* subtract 1 since we have a mapping */
            count += page_count(virt_to_page(exanic->port[i].rx_region_virt)) - 1;

        for (buf = 0; buf < exanic->max_filter_buffers; buf++)
            count += exanic->port[i].filter_buffers[buf].refcount;
    }

    return count;
}

/**
 * IRQ handler for exanic RX.
 *
 * Passed a pointer to the exanic structure for the device.
 */
static irqreturn_t exanic_rx_irq_handler(int irq, void *dev_id)
{
    struct exanic *exanic = (struct exanic *)dev_id;
    int i;

    for (i = 0; i < exanic->num_ports; ++i)
        if (exanic->ndev[i])
            exanic_netdev_rx_irq_handler(exanic->ndev[i]);

    return IRQ_HANDLED;
}

/**
 * Periodic checking of exanic link status.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
static void exanic_link_timer_callback(struct timer_list *link_timer)
{
    struct exanic *exanic = container_of(link_timer, struct exanic, link_timer);
#else
static void exanic_link_timer_callback(unsigned long data)
{
    struct exanic *exanic = (struct exanic *)data;
#endif
    int i;
    for (i = 0; i < exanic->num_ports; ++i)
        if (exanic->ndev[i])
            exanic_netdev_check_link(exanic->ndev[i]);

    mod_timer(&exanic->link_timer, jiffies + HZ);
}

/**
 * Allocate a region for a receive buffer.
 *
 * Implement common functionality used by exanic_alloc_rx_dma and
 * exanic_alloc_filter_dma.
 */
static void * exanic_alloc_dma(struct exanic *exanic, int *numa_node,
                        dma_addr_t * rx_region_dma)
{
    struct device *dev = &exanic->pci_dev->dev;
    void *virt_region;

    if (*numa_node != -1)
    {
        if (!node_online(*numa_node))
        {
            dev_err(dev, DRV_NAME
                "%u: Failed to assign invalid node id = %d.\n",
                exanic->id, *numa_node);
            return NULL;
        }

        set_dev_node(dev, *numa_node);
    }
    else
        *numa_node = dev_to_node(dev);

    if (rx_region_dma == NULL)
        return NULL;

    /* Allocate DMA resources. */
    virt_region = dma_alloc_coherent(dev, EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE,
                                     rx_region_dma, GFP_KERNEL
#if !(__HAS_GFP_TYPES_H)
                                  | __GFP_COMP
#endif
                                     );

    /* Fill with 0xFF because generation number starts at 0. */
    if (virt_region)
        memset(virt_region, 0xFF, EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE);

    return virt_region;
}

/**
 * Allocate DMA resources for an exanic port.
 *
 * The allocated memory will be automatically freed when rx_refcount is zero
 * and the last rx mapping goes away.
 *
 * Called with the exanic mutex held.
 */
int exanic_alloc_rx_dma(struct exanic *exanic, unsigned port_num,
                        int numa_node)
{
    struct device *dev = &exanic->pci_dev->dev;
    struct exanic_port *port = &exanic->port[port_num];

    /* The RX DMA region may already be allocated */
    if (port->rx_region_virt != NULL)
        return 0;

    /* Allocate DMA resources. */
    port->rx_region_virt = exanic_alloc_dma(exanic, &numa_node,
                                            &port->rx_region_dma);

    if (!port->rx_region_virt)
    {
        dev_err(dev, DRV_NAME
            "%u: Failed to allocate %u page(s) for RX DMA region.\n",
            exanic->id, EXANIC_RX_DMA_NUM_PAGES);
        return -ENOMEM;
    }
    port->numa_node = numa_node;

    dev_dbg(dev, DRV_NAME
        "%u: Port %u RX region allocated at "
        "virt: 0x%p, dma handle: 0x%pad, size: %lu bytes.\n",
        exanic->id, port_num, port->rx_region_virt,
        &port->rx_region_dma, EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE);
    return 0;
}

/**
 * Allocate DMA resources for a filter buffer on a particular port.
 */
int exanic_alloc_filter_dma(struct exanic *exanic, unsigned port_num,
                            unsigned buffer_num, int numa_node)
{
    struct exanic_port *port = &exanic->port[port_num];
    struct device *dev = &exanic->pci_dev->dev;
    uint32_t dma_cfg;

    if (port_num >= exanic->num_ports)
        return -EINVAL;
    if (buffer_num >= exanic->max_filter_buffers)
        return -EINVAL;
    if (port->filter_buffers[buffer_num].refcount > 0)
    {
        BUG_ON(port->filter_buffers[buffer_num].region_virt == NULL);
        port->filter_buffers[buffer_num].refcount++;
        return 0;
    }

    port->filter_buffers[buffer_num].region_virt =
                exanic_alloc_dma(exanic,
                                 &numa_node,
                                 &port->filter_buffers[buffer_num].region_dma);

    if (!port->filter_buffers[buffer_num].region_virt)
    {
        dev_err(dev, DRV_NAME
            "%u: Failed to allocate %u page(s) for filter DMA region.\n",
            exanic->id, EXANIC_RX_DMA_NUM_PAGES);
        return -ENOMEM;
    }

    port->filter_buffers[buffer_num].numa_node = numa_node;

    /* Tell hardware about the location of the DMA buffer */
    if ((port->filter_buffers[buffer_num].region_dma >> 32) == 0)
        dma_cfg = EXANIC_DMA_ADDR_CFG_32_BIT;
    else
        dma_cfg = EXANIC_DMA_ADDR_CFG_64_BIT;

    writel(port->filter_buffers[buffer_num].region_dma | dma_cfg,
                    exanic->regs_virt +
                    REG_FILTERS_OFFSET(port_num, REG_BUFFER_BASEADDR) +
                    2*buffer_num*sizeof(uint32_t) +
                    sizeof(uint32_t));
    writel(port->filter_buffers[buffer_num].region_dma >> 32, exanic->regs_virt +
                    REG_FILTERS_OFFSET(port_num, REG_BUFFER_BASEADDR) +
                    2*buffer_num*sizeof(uint32_t));

    port->filter_buffers[buffer_num].refcount++;

    dev_dbg(dev, DRV_NAME
        "%u: Port %u filter RX region allocated at "
        "virt: 0x%p, dma handle: 0x%pad, size: %lu bytes.\n",
        exanic->id, port_num, port->filter_buffers[buffer_num].region_virt,
        &port->filter_buffers[buffer_num].region_dma,
        EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE);
    return 0;
}

/**
 * Free DMA resources for an exanic port.  The port must be already disabled.
 *
 * This function is called from exanic_free_ctx when it sees that an rx region
 * is no longer in use.
 *
 * Called with the exanic mutex held.
 */
int exanic_free_rx_dma(struct exanic *exanic, unsigned port_num)
{
    struct exanic_port *port = &exanic->port[port_num];
    struct device *dev = &exanic->pci_dev->dev;

    if (port->rx_region_virt == NULL)
        return 0;

    BUG_ON(port->enabled);
    BUG_ON(exanic_rx_in_use(exanic, port_num));

    dma_free_coherent(dev, EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE,
            port->rx_region_virt, port->rx_region_dma);

    if (port->ate_rx_region_virt != NULL)
        dma_free_coherent(dev, EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE,
                          port->ate_rx_region_virt,
                          port->ate_rx_region_dma);

    port->rx_region_virt = NULL;
    port->rx_region_dma = 0;
    port->ate_rx_region_virt = NULL;
    port->ate_rx_region_dma = 0;

    dev_dbg(dev, DRV_NAME
        "%u: Port %u RX region freed.\n", exanic->id, port_num);
    return 0;
}

/**
 * Free DMA resources for an exanic filter buffer. This function will only free
 * physical resources once all contexts using the port have closed.
 *
 * Called with the exanic mutex held.
 */
int exanic_free_filter_dma(struct exanic *exanic, unsigned port_num,
                       unsigned buffer_num)
{
    struct exanic_port *port = &exanic->port[port_num];
    struct device *dev = &exanic->pci_dev->dev;

    if (port->filter_buffers[buffer_num].region_virt == NULL)
        return 0;
    BUG_ON(port->filter_buffers[buffer_num].refcount == 0);
    if (--port->filter_buffers[buffer_num].refcount != 0)
        return 0;

    /* Make sure we disable all rules related to this buffer first. */
    exanic_remove_rx_filter_assoc(exanic, port_num, buffer_num);

    /* We should disable flow hashing too. */
    exanic_configure_port_hash(exanic, port_num, 0, 0, 0);

    /* Set the DMA address to all zeros. */
    writel(0, exanic->regs_virt +
                REG_FILTERS_OFFSET(port_num, REG_BUFFER_BASEADDR) +
                    2*buffer_num*sizeof(uint32_t) +
                        sizeof(uint32_t));
    writel(0, exanic->regs_virt +
            REG_FILTERS_OFFSET(port_num, REG_BUFFER_BASEADDR) +
                2*buffer_num*sizeof(uint32_t));

    dma_free_coherent(dev, EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE,
            port->filter_buffers[buffer_num].region_virt,
            port->filter_buffers[buffer_num].region_dma);
    port->filter_buffers[buffer_num].region_virt = NULL;
    port->filter_buffers[buffer_num].region_dma = 0;

    dev_dbg(dev, DRV_NAME
        "%u: Port %u, filter buffer %u region freed.\n", exanic->id, port_num,
          buffer_num);
    return 0;
}

/**
 * These bitmasks determine, for each port, which set of feature bits will
 * cause that port to be powered on.
 */
static uint32_t port_feature_bits_4port[EXANIC_MAX_PORTS] =
{
    /* Port 0 */
    EXANIC_FEATURE_MIRROR_RX_0 | EXANIC_FEATURE_MIRROR_TX_0 |
        EXANIC_FEATURE_BRIDGE,

    /* Port 1 */
    EXANIC_FEATURE_MIRROR_RX_1 | EXANIC_FEATURE_MIRROR_TX_1 |
        EXANIC_FEATURE_BRIDGE,

    /* Port 2 */
    EXANIC_FEATURE_MIRROR_RX_2 | EXANIC_FEATURE_MIRROR_TX_2,

    /* Port 3 */
    EXANIC_FEATURE_MIRROR_RX_0 | EXANIC_FEATURE_MIRROR_TX_0 |
        EXANIC_FEATURE_MIRROR_RX_1 | EXANIC_FEATURE_MIRROR_TX_1 |
        EXANIC_FEATURE_MIRROR_RX_2 | EXANIC_FEATURE_MIRROR_TX_2,
};

static uint32_t port_feature_bits_2port[EXANIC_MAX_PORTS] =
{
    /* Port 0 */
    EXANIC_FEATURE_MIRROR_RX_0 | EXANIC_FEATURE_MIRROR_TX_0 |
        EXANIC_FEATURE_BRIDGE,

    /* Port 1 */
    EXANIC_FEATURE_MIRROR_RX_0 | EXANIC_FEATURE_MIRROR_TX_0 |
        EXANIC_FEATURE_BRIDGE
};

/**
 * Check if the port is a special purpose port that must always be powered.
 */
static bool exanic_port_needs_power(struct exanic *exanic, unsigned port_num)
{
    uint32_t cfg = readl(exanic->regs_virt +
                     REG_EXANIC_OFFSET(REG_EXANIC_FEATURE_CFG));

    if (exanic->hwinfo.nports == 2)
    {
        /* 2 port card */
        if (cfg & port_feature_bits_2port[port_num])
            return true;
    }
    else if (exanic->hwinfo.nports == 4)
    {
        /* 4 port card */
        if (cfg & port_feature_bits_4port[port_num])
            return true;
    }

    if (exanic->caps & EXANIC_CAP_EXT_MIRRORING)
    {
        /* Extended mirroring configuration is available */
        uint32_t reg = readl(exanic->regs_virt +
                REG_EXANIC_OFFSET(REG_EXANIC_MIRROR_ENABLE_EXT));
        unsigned out_port = (cfg & EXANIC_FEATURE_MIRROR_OUTPUT_EXT_MASK) >>
                EXANIC_FEATURE_MIRROR_OUTPUT_EXT_SHIFT;

        /* Port is a mirror source */
        if (reg & (3 << (2 * port_num)))
            return true;

        /* Port is the mirror output */
        if (reg != 0 && port_num == out_port)
            return true;
    }

    return false;
}

/**
 * Powers a port up or down (if necessary), updating port->power.
 *
 * Called with the exanic mutex held.
 */
static bool exanic_set_port_power(struct exanic *exanic, unsigned port_num,
                                  bool power)
{
    struct exanic_port *port = &exanic->port[port_num];
    struct device *dev = &exanic->pci_dev->dev;

    if (port->power && !power)
    {
        /* Power off */
        exanic_phyops_poweroff(exanic, port_num);

        port->power = power;
        dev_info(dev, DRV_NAME
            "%u: Port %u powered off.\n", exanic->id, port_num);
        return true;
    }
    else if (!port->power && power)
    {
        /* Power on */
        int err = exanic_phyops_poweron(exanic, port_num);

        /* wait for PHY to power up */
        msleep(100);

        /* update PHY operations associated with port */
        exanic_phyops_init_fptrs(exanic, port_num, true);

        /* perform initial PHY configuration */
        err |= exanic_phyops_init(exanic, port_num);

        if (err == 0)
        {
            port->power = power;
            dev_info(dev, DRV_NAME "%u: Port %u powered on.\n",
                     exanic->id, port_num);
            return true;
        }
        else
        {
            dev_err(dev, DRV_NAME "%u: Port %u power on failed.\n",
                    exanic->id, port_num);
            return false;
        }
    }
    return true;
}

/**
 * Enables a exanic port.  The DMA resources must have been allocated.
 *
 * Called with the exanic mutex held.
 */
int exanic_enable_port(struct exanic *exanic, unsigned port_num)
{
    struct exanic_port *port = &exanic->port[port_num];
    struct device *dev = &exanic->pci_dev->dev;
    uint32_t dma_cfg;

    BUG_ON(port_num >= exanic->num_ports);
    BUG_ON(port->rx_region_virt == NULL);

    /* Power on port */
    if (!exanic_set_port_power(exanic, port_num, true))
        return -EIO;

    /* Tell hardware about the location of the DMA buffer */
    if ((port->rx_region_dma >> 32) == 0)
        dma_cfg = EXANIC_DMA_ADDR_CFG_32_BIT;
    else
        dma_cfg = EXANIC_DMA_ADDR_CFG_64_BIT;

    writel(port->rx_region_dma | dma_cfg, exanic->regs_virt +
        REG_PORT_OFFSET(port_num, REG_PORT_RX_DMA_BASE_ADDR_LO));
    writel(port->rx_region_dma >> 32, exanic->regs_virt +
        REG_PORT_OFFSET(port_num, REG_PORT_RX_DMA_BASE_ADDR_HI));

    /* It is now safe to turn on the port and start receiving packets */
    writel(1, exanic->regs_virt + REG_PORT_OFFSET(port_num, REG_PORT_ENABLED));

    port->enabled = true;
    dev_info(dev, DRV_NAME "%u: Port %u enabled.\n", exanic->id, port_num);
    return 0;
}

/**
 * Disables a exanic port.
 *
 * Called with the exanic mutex held.
 */
int exanic_disable_port(struct exanic *exanic, unsigned port_num)
{
    struct exanic_port *port = &exanic->port[port_num];
    struct device *dev = &exanic->pci_dev->dev;

    /* Check if the port is already disabled. */
    if (!port->enabled)
    {
        /* Make sure the port is really disabled, in case our state is
         * inconsistent with the hardware. */
        writel(0, exanic->regs_virt +
                REG_PORT_OFFSET(port_num, REG_PORT_ENABLED));
        writel(0, exanic->regs_virt +
                REG_PORT_OFFSET(port_num, REG_PORT_IRQ_CONFIG));
        return 0;
    }

    /* Disable interrupts on the port */
    writel(0, exanic->regs_virt +
            REG_PORT_OFFSET(port_num, REG_PORT_IRQ_CONFIG));

    /* Disable RX and stop receiving packets */
    writel(0, exanic->regs_virt + REG_PORT_OFFSET(port_num, REG_PORT_ENABLED));

    /* Turning off RX does not stop a packet currently being transferred,
     * so wait a bit here just in case. */
    udelay(100);

    /* Power off port */
    if (!exanic_port_needs_power(exanic, port_num))
        exanic_set_port_power(exanic, port_num, false);

    port->enabled = false;
    dev_info(dev, DRV_NAME "%u: Port %u disabled%s.\n", exanic->id, port_num,
            port->power ? " but still powered for bridging/mirroring" : "");
    return 0;
}

static LIST_HEAD(exanic_devices);
static DEFINE_SPINLOCK(exanic_devices_lock);

static unsigned int exanic_get_id(void)
{
    struct exanic *exanic;
    unsigned int id = 0;
    bool in_use;

    do
    {
        in_use = false;
        list_for_each_entry(exanic, &exanic_devices, node)
        {
            if (exanic->id == id)
            {
                in_use = true;
                id++;
                break;
            }
        }
    } while (in_use);

    return id;
}

enum { MIN_SUPPORTED_PCIE_IF_VER = 1, MAX_SUPPORTED_PCIE_IF_VER = 1 };


/**
 * Get the MAC address of a port from the registers.
 */
int exanic_get_mac_addr_regs(struct exanic *exanic, unsigned port_num,
                             u8 mac_addr[ETH_ALEN])
{
    uint32_t r = readl(exanic->regs_virt +
                       REG_PORT_OFFSET(port_num, REG_PORT_MAC_ADDR_OUI));
    mac_addr[0] = r & 0xFF;
    mac_addr[1] = r >> 8 & 0xFF;
    mac_addr[2] = r >> 16 & 0xFF;

    r = readl(exanic->regs_virt +
            REG_PORT_OFFSET(port_num, REG_PORT_MAC_ADDR_NIC));
    mac_addr[3] = r & 0xFF;
    mac_addr[4] = r >> 8 & 0xFF;
    mac_addr[5] = r >> 16 & 0xFF;

    return 0;
}

/**
 * Write the MAC address of a port to the registers.
 */
int exanic_set_mac_addr_regs(struct exanic *exanic, unsigned port_num,
                             const u8 mac_addr[ETH_ALEN])
{
    uint32_t r = mac_addr[0] | (mac_addr[1] << 8) | (mac_addr[2] << 16);
    writel(r, exanic->regs_virt +
            REG_PORT_OFFSET(port_num, REG_PORT_MAC_ADDR_OUI));

    r = mac_addr[3] | (mac_addr[4] << 8) | (mac_addr[5] << 16);
    writel(r, exanic->regs_virt +
            REG_PORT_OFFSET(port_num, REG_PORT_MAC_ADDR_NIC));

    return 0;
}

/**
 * Get the register bit mask for the given feature and port.
 * (Legacy mirroring and bridging bits only)
 */
static int exanic_feature_bit(struct exanic *exanic, unsigned port_num,
                              enum exanic_feature feature, uint32_t *bit)
{
    switch (feature)
    {
        case EXANIC_MIRROR_RX:
            if (!EXANIC_MIRRORING_SUPPORT(exanic))
                return -EINVAL;
            if (exanic->hwinfo.nports == 4)
            {
                switch (port_num)
                {
                    case 0:  *bit = EXANIC_FEATURE_MIRROR_RX_0; return 0;
                    case 1:  *bit = EXANIC_FEATURE_MIRROR_RX_1; return 0;
                    case 2:  *bit = EXANIC_FEATURE_MIRROR_RX_2; return 0;
                    default: return -EINVAL;
                }
            }
            else if (exanic->hwinfo.nports == 2)
            {
                switch (port_num)
                {
                    case 0:  *bit = EXANIC_FEATURE_MIRROR_RX_0; return 0;
                    default: return -EINVAL;
                }
            }
            break;

        case EXANIC_MIRROR_TX:
            if (!EXANIC_MIRRORING_SUPPORT(exanic))
                return -EINVAL;
            if (exanic->hwinfo.nports == 4)
            {
                switch (port_num)
                {
                    case 0:  *bit = EXANIC_FEATURE_MIRROR_TX_0; return 0;
                    case 1:  *bit = EXANIC_FEATURE_MIRROR_TX_1; return 0;
                    case 2:  *bit = EXANIC_FEATURE_MIRROR_TX_2; return 0;
                    default: return -EINVAL;
                }
            }
            else if (exanic->hwinfo.nports == 2)
            {
                switch (port_num)
                {
                    case 0:  *bit = EXANIC_FEATURE_MIRROR_TX_0; return 0;
                    default: return -EINVAL;
                }
            }
            break;

        case EXANIC_BRIDGE:
            if (!EXANIC_BRIDGING_SUPPORT(exanic))
                return -EINVAL;
            switch (port_num)
            {
                case 0:  *bit = EXANIC_FEATURE_BRIDGE; return 0;
                case 1:  *bit = EXANIC_FEATURE_BRIDGE; return 0;
                default: return -EINVAL;
            }
            break;

        default:
            return -EINVAL;
    }

    return -EINVAL;
}

/**
 * Get the current state of a feature.
 */
int exanic_get_feature_cfg(struct exanic *exanic, unsigned port_num,
                           enum exanic_feature feature, bool *state)
{
    uint32_t reg, bit;
    int err;

    /* Extended mirroring configuration */
    if ((exanic->caps & EXANIC_CAP_EXT_MIRRORING) &&
            (feature == EXANIC_MIRROR_RX || feature == EXANIC_MIRROR_TX))
    {
        bit = (feature == EXANIC_MIRROR_RX ? 1 : 2) << (2 * port_num);
        reg = readl(exanic->regs_virt +
                REG_EXANIC_OFFSET(REG_EXANIC_MIRROR_ENABLE_EXT));
        *state = ((reg & bit) != 0);
        return 0;
    }

    /* Legacy mirroring and bridging configuration */
    err = exanic_feature_bit(exanic, port_num, feature, &bit);
    if (!err)
    {
        reg = readl(exanic->regs_virt +
                REG_EXANIC_OFFSET(REG_EXANIC_FEATURE_CFG));
        *state = ((reg & bit) != 0);
        return 0;
    }

    /* Set state to false if feature is invalid */
    *state = false;
    return err;
}

/**
 * Set the state of a feature.
 *
 * Called with the exanic mutex held.
 */
int exanic_set_feature_cfg(struct exanic *exanic, unsigned port_num,
                           enum exanic_feature feature, bool state)
{
    struct device *dev = &exanic->pci_dev->dev;
    uint32_t reg, new_reg, bit;
    unsigned i;
    int err = 0;

    if ((exanic->caps & EXANIC_CAP_EXT_MIRRORING) &&
            (feature == EXANIC_MIRROR_RX || feature == EXANIC_MIRROR_TX))
    {
        /* Extended mirroring configuration */
        bit = (feature == EXANIC_MIRROR_RX ? 1 : 2) << (2 * port_num);
        reg = readl(exanic->regs_virt +
                REG_EXANIC_OFFSET(REG_EXANIC_MIRROR_ENABLE_EXT));

        if (state)
            new_reg = reg | bit;
        else
            new_reg = reg & ~bit;

        if (reg == new_reg)
            return 0;

        writel(new_reg, exanic->regs_virt +
            REG_EXANIC_OFFSET(REG_EXANIC_MIRROR_ENABLE_EXT));

        dev_info(dev, DRV_NAME "%u: Port %u %s mirroring %s.\n", exanic->id,
                port_num, feature == EXANIC_MIRROR_RX ? "RX" : "TX",
                state ? "enabled" : "disabled");
    }
    else
    {
        /* Legacy mirroring and bridging configuration */
        err = exanic_feature_bit(exanic, port_num, feature, &bit);
        if (err)
        {
            /* Allow setting unsupported feature bits to false */
            if (!state)
                return 0;
            return err;
        }

        reg = readl(exanic->regs_virt +
                REG_EXANIC_OFFSET(REG_EXANIC_FEATURE_CFG));

        if (state)
            new_reg = reg | bit;
        else
            new_reg = reg & ~bit;

        if (reg == new_reg)
            return 0;

        writel(new_reg, exanic->regs_virt +
                REG_EXANIC_OFFSET(REG_EXANIC_FEATURE_CFG));

        dev_info(dev, DRV_NAME "%u: %s %s.\n",
                exanic->id, exanic_feature_str(bit),
                state ? "enabled" : "disabled");

        /* Save new state to EEPROM */
        exanic_save_feature_cfg(exanic);
    }

    /* Power up/down ports based on the new bridging and mirroring bits */
    for (i = 0; i < exanic->num_ports; i++)
    {
        if (exanic->port[i].enabled || exanic_port_needs_power(exanic, i))
            exanic_set_port_power(exanic, i, true);
        else
            exanic_set_port_power(exanic, i, false);
    }

    return 0;
}

struct exanic *exanic_find_by_minor(unsigned minor)
{
    struct exanic *exanic;

    spin_lock(&exanic_devices_lock);

    list_for_each_entry(exanic, &exanic_devices, node)
        if (exanic->misc_dev.minor == minor)
            goto exit;
    exanic = NULL;
exit:
    spin_unlock(&exanic_devices_lock);

    return exanic;
}

static void inc_mac_addr(u8 addr[ETH_ALEN], int n)
{
    uint32_t nic;

    nic = ((addr[3] << 16) | (addr[4] << 8) | addr[5]) + n;

    addr[3] = nic >> 16 & 0xFF;
    addr[4] = nic >> 8 & 0xFF;
    addr[5] = nic & 0xFF;
}

static int exanic_get_num_ports(struct exanic *exanic)
{
    int port_idx;
    int port_status;
    int port_limit;

    /* get the maximum number of ethernet interfaces
     * neccessary because the extended port registers
     * won't be populated by cards that don't make use
     * of them */
    switch (exanic->hwinfo.port_ff)
    {
        case EXANIC_PORT_SFP:
            port_limit = exanic->hwinfo.nports;
            break;

        case EXANIC_PORT_QSFP:
            port_limit = exanic->hwinfo.nports * 4;
            break;

        case EXANIC_PORT_QSFPDD:
            port_limit = exanic->hwinfo.nports * 8;
            break;

        default: return 0;
    }

    for (port_idx = 0; port_idx < min(EXANIC_MAX_PORTS, port_limit); port_idx++)
    {
        port_status = readl(exanic->regs_virt +
                      REG_PORT_OFFSET(port_idx, REG_PORT_STATUS));
        if (port_status & EXANIC_PORT_NOT_IMPLEMENTED)
            break;
    }
    return port_idx;
}

/**
 * Given bar 0 and bar 2 offset, compute usable devkit register and memory range.
 */
static size_t exanic_devkit_offset_to_size(unsigned int offset)
{
    /* Offset is decoded in firmware by inspecting the prefix
     * therefore the size of a region is equal to 2^(ffs(offset)) */
    unsigned long ffs =
        find_first_bit((const unsigned long *)&offset, sizeof(offset) * 8);

    if (unlikely(ffs == sizeof(offset) * 8))
        return 0;

    return ((size_t)1) << ffs;
}

/**
 * Device initialisation
 *
 * This function initialises the exanic identified by the pci_device_id
 * structure.
 *
 * \return 0 if the exanic was successfully initialised, negative on failure.
 */
static int exanic_probe(struct pci_dev *pdev,
                        const struct pci_device_id *id)
{
    struct exanic *exanic;
    struct device *dev = &pdev->dev;
    int err;
    unsigned port_num;
    const char *hw_id_str;
    const char *function_str;
    uint32_t dma_cfg;
    u8 mac_addr[ETH_ALEN];

    exanic = devm_kzalloc(dev, sizeof(struct exanic), GFP_KERNEL);
    if (exanic == NULL)
        return -ENOMEM;

    /* misc_dev.minor should be initialized before exanic device gets added
     * to the exanic_devices list to avoid unexpected results of
     * exanic_find_by_minor().
     */
    exanic->misc_dev.minor = MISC_DYNAMIC_MINOR;

    /* Assign exanic ID and add the device to the list of exanic devices */
    spin_lock(&exanic_devices_lock);
    exanic->id = exanic_get_id();
    list_add_tail(&exanic->node, &exanic_devices);
    spin_unlock(&exanic_devices_lock);

    snprintf(exanic->name, sizeof(exanic->name), DRV_NAME "%u", exanic->id);
    dev_info(dev, "Probing %s.\n", exanic->name);

    mutex_init(&exanic->mutex);

    /* Disable ASPM */
    pci_disable_link_state(pdev, PCIE_LINK_STATE_L0S | PCIE_LINK_STATE_L1 |
            PCIE_LINK_STATE_CLKPM);

    /* Set up the PCI component */
    err = pci_enable_device_mem(pdev);
    if (err)
    {
        dev_err(dev, "pci_enable_device_mem failed: %d\n", err);
        goto err_pci_enable_dev;
    }

    err = pci_request_regions(pdev, DRV_NAME);

    if (err)
    {
        dev_err(dev, "pci_request_selected_regions_exclusive failed: %d\n",
                err);
        goto err_req_regions;
    }

#if __HAS_PCI_ERR_REPORTING
#if defined(CONFIG_PCIEAER)
    pci_enable_pcie_error_reporting(pdev);
#endif
#endif
    pci_set_master(pdev);
    pci_set_drvdata(pdev, exanic);
    exanic->pci_dev = pdev;

    /* Configure register space */
    if (!(pci_resource_flags(pdev, EXANIC_REGS_BAR) & IORESOURCE_MEM))
    {
        dev_err(dev, "BAR %u is not a memory resource.\n", EXANIC_REGS_BAR);
        err = -EIO;
        goto err_regs_bar_type;
    }

    exanic->regs_size = pci_resource_len(pdev, EXANIC_REGS_BAR);
    if (exanic->regs_size < EXANIC_REGS_NUM_PAGES * PAGE_SIZE)
    {
        dev_err(dev, "BAR %u has size = %zu but expected at least %lu.\n",
            EXANIC_REGS_BAR, exanic->regs_size, EXANIC_REGS_NUM_PAGES * PAGE_SIZE);
        err = -EIO;
        goto err_regs_size;
    }

    exanic->regs_phys = pci_resource_start(pdev, EXANIC_REGS_BAR);
    exanic->regs_virt = ioremap(exanic->regs_phys, exanic->regs_size);
    if (!exanic->regs_virt)
    {
        dev_err(dev, "Registers ioremap failed.\n");
        err = -EIO;
        goto err_regs_ioremap;
    }

    dev_info(dev, "Registers at phys: 0x%pap, virt: 0x%p, size: %zu bytes.\n",
        &exanic->regs_phys, exanic->regs_virt, exanic->regs_size);

    /* Read exanic version information and check that it is supported */
    exanic->pcie_if_ver =
        readl(exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_PCIE_IF_VER));
    exanic->hw_id =
        readl(exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_HW_ID));
    exanic->function_id =
        readl(exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_FUNCTION_ID));
    exanic->caps =
        readl(exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_CAPS));
    exanic_get_hw_info(exanic->hw_id, &exanic->hwinfo);

    if ((exanic->pcie_if_ver < MIN_SUPPORTED_PCIE_IF_VER) ||
        (exanic->pcie_if_ver > MAX_SUPPORTED_PCIE_IF_VER))
    {
        dev_err(dev,
                "Unsupported exanic interface version: %u (min %u, max %u)\n",
                exanic->pcie_if_ver, MIN_SUPPORTED_PCIE_IF_VER,
                MAX_SUPPORTED_PCIE_IF_VER);
        goto err_interface_ver;
    }

    hw_id_str = exanic_hardware_id_str((exanic_hardware_id_t) exanic->hw_id);
    if (hw_id_str == NULL)
    {
        dev_err(dev, "Unsupported hardware type: %u\n", exanic->hw_id);
        goto err_hw_id;
    }

    function_str = exanic_function_id_str((exanic_function_id_t) exanic->function_id);
    if (function_str == NULL)
    {
        dev_err(dev, "Unsupported function type: %u\n", exanic->function_id);
        goto err_function_id;
    }

    /* Make sure card has completed its startup sequence */
    {
        unsigned count = 0;
        while ((readl(exanic->regs_virt + REG_EXANIC_OFFSET(
                REG_EXANIC_FEATURE_CFG)) & EXANIC_STATUS_HW_STARTUP) != 0)
        {
            count++;
            if (count > 5)
            {
                dev_err(dev, "Timed out waiting for ExaNIC startup.\n");
                err = -EIO;
                goto err_timeout;
            }
            msleep(100);
        }
    }

    /* Configure DMA address mask */
    exanic->dma_addr_bits =
        readl(exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_DMA_ADDR_WIDTH));
    if (exanic->dma_addr_bits < 32 || exanic->dma_addr_bits > 64)
    {
        dev_info(dev, "Invalid DMA address width: %u bits, "
                "defaulting to 64 bits.\n", exanic->dma_addr_bits);
        exanic->dma_addr_bits = 64;
    }
    else
    {
        dev_info(dev, "DMA address width: %u bits.\n", exanic->dma_addr_bits);
    }

    err = pci_set_dma_mask(pdev, DMA_BIT_MASK(exanic->dma_addr_bits));
    if (err)
    {
        dev_err(dev, "pci_set_dma_mask failed: %d\n", err);
        goto err_dma_mask;
    }

    err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(exanic->dma_addr_bits));
    if (err)
    {
        dev_err(dev, "pci_set_consistent_dma_mask failed: %d\n", err);
        goto err_dma_mask;
    }

    /* Determine number of ethernet interfaces
     * equal to the number of physical ports unless breakout is possible */
    if (EXANIC_BREAKOUT_SUPPORT(exanic))
        exanic->num_ports = exanic_get_num_ports(exanic);
    else if (exanic->hwinfo.hwid != -1)
        exanic->num_ports = exanic->hwinfo.nports;
    else
        exanic->num_ports = 0;

    /* Configure TX region */
    if (pci_resource_flags(pdev, EXANIC_TX_REGION_BAR) & IORESOURCE_MEM)
    {
        exanic->tx_region_size = pci_resource_len(pdev, EXANIC_TX_REGION_BAR);
        exanic->tx_region_phys = pci_resource_start(pdev, EXANIC_TX_REGION_BAR);
        exanic->tx_region_virt =
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
            ioremap_wc(exanic->tx_region_phys, exanic->tx_region_size);
#else
            ioremap(exanic->tx_region_phys, exanic->tx_region_size);
#endif

        dev_info(dev, "TX region at phys: 0x%pap, size: %zu bytes.\n",
            &exanic->tx_region_phys, exanic->tx_region_size);
    }
    else
    {
        dev_info(dev,
            "TX region not available. (BAR %u is not a memory resource.)\n",
            EXANIC_TX_REGION_BAR);

        exanic->tx_region_size = 0;
        exanic->tx_region_phys = 0;
        exanic->tx_region_virt = NULL;
    }

    bitmap_zero(exanic->tx_region_bitmap, EXANIC_TX_REGION_MAX_NUM_PAGES);

    /* Set up TX feedback region */
    exanic->tx_feedback_virt = dma_alloc_coherent(&exanic->pci_dev->dev,
            EXANIC_TX_FEEDBACK_NUM_PAGES * PAGE_SIZE,
            &exanic->tx_feedback_dma, GFP_KERNEL
#if !(__HAS_GFP_TYPES_H)
            | __GFP_COMP
#endif
            );
    if (!exanic->tx_feedback_virt)
    {
        dev_err(dev, DRV_NAME
            "%u: Failed to allocate %u page(s) for TX feedback region.\n",
            exanic->id, EXANIC_TX_FEEDBACK_NUM_PAGES);
        err = -ENOMEM;
        goto err_tx_feedback_alloc;
    }

    bitmap_zero(exanic->tx_feedback_bitmap, EXANIC_TX_FEEDBACK_NUM_SLOTS);

    if ((exanic->tx_feedback_dma >> 32) == 0)
        dma_cfg = EXANIC_DMA_ADDR_CFG_32_BIT;
    else
        dma_cfg = EXANIC_DMA_ADDR_CFG_64_BIT;

    writel(exanic->tx_feedback_dma | dma_cfg, exanic->regs_virt +
        REG_EXANIC_OFFSET(REG_EXANIC_TX_FEEDBACK_BASE_ADDR_LO));
    writel(exanic->tx_feedback_dma >> 32, exanic->regs_virt +
        REG_EXANIC_OFFSET(REG_EXANIC_TX_FEEDBACK_BASE_ADDR_HI));

    dev_info(dev,
        "TX feedback region at virt: 0x%p, dma handle: 0x%pad, size: %lu bytes.\n",
        exanic->tx_feedback_virt, &exanic->tx_feedback_dma,
        EXANIC_TX_FEEDBACK_NUM_PAGES * PAGE_SIZE);

    /* Set up port information in exanic struct */
    for (port_num = 0; port_num < exanic->num_ports; ++port_num)
    {
        int ate_id = 0;
        exanic->port[port_num].rx_region_virt = NULL;
        exanic->port[port_num].rx_region_dma = 0;
        exanic->port[port_num].rx_refcount = 0;
        if (exanic->tx_region_size > 0)
        {
            exanic->port[port_num].tx_region_usable_offset =
                readl(exanic->regs_virt +
                        REG_PORT_OFFSET(port_num, REG_PORT_TX_REGION_OFFSET));
            exanic->port[port_num].tx_region_usable_size =
                readl(exanic->regs_virt +
                        REG_PORT_OFFSET(port_num, REG_PORT_TX_REGION_SIZE));
        }
        else
        {
            exanic->port[port_num].tx_region_usable_offset = 0;
            exanic->port[port_num].tx_region_usable_size = 0;
        }
        exanic->port[port_num].max_ip_filter_slots = 0;
        exanic->port[port_num].max_mac_filter_slots = 0;
        exanic->port[port_num].num_hash_functions = 0;
        exanic->port[port_num].ip_filter_slots = NULL;
        exanic->port[port_num].mac_filter_slots = NULL;
        exanic->port[port_num].filter_buffers = NULL;
        exanic->port[port_num].has_ate = false;
        for (ate_id = 0; ate_id < EXANIC_ATE_ENGINES_PER_PORT; ++ate_id)
        {
            sema_init(&exanic->port[port_num].ate_lockbox[ate_id],1);
        }
        spin_lock_init(&exanic->port[port_num].filter_lock);
    }

    /* Sanity checks */
    if (exanic->tx_region_size > 0)
    {
        for (port_num = 0; port_num < exanic->num_ports; ++port_num)
        {
            if ((exanic->port[port_num].tx_region_usable_offset +
                        exanic->port[port_num].tx_region_usable_size)
                    > exanic->tx_region_size)
            {
                dev_err(dev,
                        "Invalid usable TX region: "
                        "port: %u, usable_offset: 0x%zx, "
                        "usable_size: 0x%zx, region_end: 0x%zx\n",
                        port_num, exanic->port[port_num].tx_region_usable_offset,
                        exanic->port[port_num].tx_region_usable_size,
                        exanic->tx_region_size);
            }
        }
    }

    /* allocate i2c busses */
    err = exanic_i2c_init(exanic);
    if (err)
    {
        dev_err(dev, "exanic_i2c_init failed: %d\n", err);
        goto err_i2c_init;
    }

    /* initialise sysfs entries */
    err = exanic_sysfs_init(exanic);
    if (err)
    {
        dev_err(dev, "exanic_sysfs_init failed: %d\n", err);
        goto err_sysfs_init;
    }

    /* set up phy ops */
    for (port_num = 0; port_num < exanic->num_ports; ++port_num)
        exanic_phyops_init_fptrs(exanic, port_num, false);

    /* Allocate kernel info page */
    exanic->info_page = vmalloc_user(EXANIC_INFO_NUM_PAGES * PAGE_SIZE);
    if (exanic->info_page == NULL)
    {
        dev_err(dev, "Could not allocate info page");
        goto err_info_page_alloc;
    }

    /* Get serial number in EEPROM */
    {
        int retries;
        int max_retries = 5;
        for (retries = 0; retries < max_retries; retries++)
        {
            if (exanic_get_serial(exanic, exanic->serial,
                                  sizeof(exanic->serial)) == 0)
                break;
            else
                dev_err(dev, "Could not read serial number, retry attempt "
                        "%d of %d.\n", retries + 1, max_retries);
            udelay(1);
        }

        if (retries < max_retries && exanic->serial[0])
            dev_info(dev, "Serial number: %s\n", exanic->serial);
    }

    /* Get MAC address in EEPROM */
    {
        int retries;
        int max_retries = 5;
        for (retries = 0; retries < max_retries; retries++)
        {
            if (exanic_get_mac_addr(exanic, mac_addr) == 0)
                break;
            else
                dev_err(dev, "Could not read MAC address, retry attempt "
                        "%d of %d.\n", retries + 1, max_retries);
            udelay(1);
        }

        if (retries < max_retries)
        {
            dev_info(dev, "MAC address: %pM\n", mac_addr);
            if (!exanic->serial[0])
            {
                /* Using MAC address as serial number */
                snprintf(exanic->serial, sizeof(exanic->serial),
                         "%02X%02X%02X%02X%02X%02X",
                         mac_addr[0], mac_addr[1], mac_addr[2],
                         mac_addr[3], mac_addr[4], mac_addr[5]);
            }

            if (!is_valid_ether_addr(mac_addr))
            {
                dev_err(dev, "MAC address is not valid\n");
                memcpy(mac_addr, next_mac_addr, ETH_ALEN);
            }
        }
        else
        {
            dev_err(dev, "Failed to read MAC address\n");
            memcpy(mac_addr, next_mac_addr, ETH_ALEN);
        }
    }

    /* Assign consecutive MAC addresses to ports */
    for (port_num = 0; port_num < exanic->num_ports; ++port_num)
    {
        exanic_set_mac_addr_regs(exanic, port_num, mac_addr);
        memcpy(exanic->port[port_num].orig_mac_addr, mac_addr, ETH_ALEN);
        inc_mac_addr(mac_addr, 1);
    }

    inc_mac_addr(next_mac_addr, exanic->num_ports);

    /* Set up bridging and mirroring */
    {
        uint32_t reg = readl(exanic->regs_virt +
                REG_EXANIC_OFFSET(REG_EXANIC_FEATURE_CFG));
        uint32_t bit;

        if (reg & EXANIC_FEATURE_AUX_ENABLE)
        {
            /* Copy bridging and mirroring configuration from auxiliary bits */
            reg &= ~EXANIC_FEATURE_BRIDGE_MIRROR_MASK;
            reg |= (reg & EXANIC_FEATURE_AUX_MASK) >> EXANIC_FEATURE_AUX_SHIFT;
            writel(reg, exanic->regs_virt +
                    REG_EXANIC_OFFSET(REG_EXANIC_FEATURE_CFG));
        }

        /* Show current configuration */
        for (bit = 1; bit & EXANIC_FEATURE_BRIDGE_MIRROR_MASK; bit <<= 1)
        {
            if (reg & bit)
                dev_info(dev, DRV_NAME "%u: %s enabled.\n", exanic->id,
                        exanic_feature_str(bit));
        }

        /* Power up ports based on the bridging and mirroring bits */
        for (port_num = 0; port_num < exanic->num_ports; port_num++)
        {
            if (exanic_port_needs_power(exanic, port_num))
                exanic_set_port_power(exanic, port_num, true);
        }

        if (reg & EXANIC_FEATURE_AUX_ENABLE)
        {
            /* Turn off auxiliary enable */
            reg &= ~EXANIC_FEATURE_AUX_ENABLE;
            writel(reg, exanic->regs_virt +
                    REG_EXANIC_OFFSET(REG_EXANIC_FEATURE_CFG));
        }
    }

    /* Extended mirroring support */
    if (exanic->caps & EXANIC_CAP_EXT_MIRRORING)
    {
        uint32_t reg = readl(exanic->regs_virt +
                REG_EXANIC_OFFSET(REG_EXANIC_FEATURE_CFG));
        unsigned out_port = (reg & EXANIC_FEATURE_MIRROR_OUTPUT_EXT_MASK) >>
                EXANIC_FEATURE_MIRROR_OUTPUT_EXT_SHIFT;

        dev_info(dev, DRV_NAME "%u: mirror output port is %u\n",
                exanic->id, out_port);
    }

    /* Configure interrupts */
    if (exanic->caps & EXANIC_CAP_RX_MSI)
    {
        err = pci_enable_msi(pdev);
        if (err)
        {
            dev_err(dev, DRV_NAME "%u: pci_enable_msi failed, err=%d\n",
                    exanic->id, err);
            goto err_interrupts;
        }

        err = request_irq(pdev->irq, exanic_rx_irq_handler, 0, exanic->name,
                exanic);
        if (err)
        {
            dev_err(dev, DRV_NAME "%u: request_irq failed, err=%d\n",
                    exanic->id, err);
            pci_disable_msi(pdev);
            goto err_interrupts;
        }
    }

    /* Configure flow steering. */
    exanic->max_filter_buffers =
        readl(exanic->regs_virt +
                        REG_EXANIC_OFFSET(REG_EXANIC_NUM_FILTER_BUFFERS));

    for (port_num = 0; port_num < exanic->num_ports; ++port_num)
    {
        unsigned port_status = readl(exanic->regs_virt +
                    REG_PORT_OFFSET(port_num, REG_PORT_STATUS));
        if (port_status & EXANIC_PORT_NOT_IMPLEMENTED)
            continue;

        if (exanic->max_filter_buffers == 0)
            break;

        exanic->port[port_num].max_ip_filter_slots =
                        readl(exanic->regs_virt +
                        REG_EXTENDED_PORT_OFFSET(port_num,
                            REG_EXTENDED_PORT_NUM_IP_FILTER_RULES));

        exanic->port[port_num].max_mac_filter_slots =
                        readl(exanic->regs_virt +
                        REG_EXTENDED_PORT_OFFSET(port_num,
                            REG_EXTENDED_PORT_NUM_MAC_FILTER_RULES));

        exanic->port[port_num].num_hash_functions =
                        readl(exanic->regs_virt +
                        REG_EXTENDED_PORT_OFFSET(port_num,
                            REG_EXTENDED_PORT_NUM_HASH_FUNCTIONS));

        exanic->port[port_num].filter_buffers =
            kzalloc(sizeof(struct exanic_filter_buffer) *
                            exanic->max_filter_buffers, GFP_KERNEL);

        if (exanic->port[port_num].filter_buffers == NULL)
        {
            dev_err(dev,
                    "Failed to allocate physical filter buffer array for port %d.\n",
                    port_num);
            err = -ENOMEM;
            goto err_flow_steering;
        }

        if (exanic->port[port_num].max_ip_filter_slots > 0)
        {

            exanic->port[port_num].ip_filter_slots =
                kzalloc(sizeof(struct exanic_ip_filter_slot) *
                                exanic->port[port_num].max_ip_filter_slots, GFP_KERNEL);

            if (exanic->port[port_num].ip_filter_slots == NULL)
            {
                dev_err(dev,
                        "Failed to allocate IP filter slot array for port %d.\n",
                        port_num);
                err = -ENOMEM;
                goto err_flow_steering;
            }
        }

        if (exanic->port[port_num].max_mac_filter_slots > 0)
        {
            exanic->port[port_num].mac_filter_slots =
                kzalloc(sizeof(struct exanic_mac_filter_slot) *
                                exanic->port[port_num].max_mac_filter_slots, GFP_KERNEL);

            if (exanic->port[port_num].mac_filter_slots == NULL)
            {
                dev_err(dev,
                        "Failed to allocate MAC filter slot array for port %d.\n",
                        port_num);
                goto err_flow_steering;
            }
        }
    }

    /* Filter space is in same BAR as register space */
    if (exanic->regs_size > EXANIC_PGOFF_FILTERS * PAGE_SIZE)
    {
        exanic->filters_size = exanic->regs_size - EXANIC_PGOFF_FILTERS * PAGE_SIZE;
        exanic->filters_phys = exanic->regs_phys + EXANIC_PGOFF_FILTERS * PAGE_SIZE;

        dev_info(dev, "Filters at phys: 0x%pap, size: %zu bytes.\n",
            &exanic->filters_phys, exanic->filters_size);
    }
    else
    {
        dev_info(dev, "Filters not available.\n");

        exanic->filters_size = 0;
        exanic->filters_phys = 0;
    }

    /* Set up and map the development kit memory if present. */
    if ((exanic->hwinfo.flags & EXANIC_HW_FLAG_DEVKIT) &&
        exanic->function_id == EXANIC_FUNCTION_DEVKIT)
    {
        exanic->devkit_regs_offset =
            readl(exanic->regs_virt +
                REG_EXANIC_OFFSET(REG_EXANIC_DEVKIT_REGISTERS_OFFSET));
        exanic->devkit_mem_offset =
            readl(exanic->regs_virt +
                REG_EXANIC_OFFSET(REG_EXANIC_DEVKIT_MEMORY_OFFSET));
        if (exanic->devkit_regs_offset > 0 &&
                exanic->devkit_mem_offset > 0)
        {
            /* Configure Devkit register region */
            exanic->devkit_regs_size =
                exanic_devkit_offset_to_size(exanic->devkit_regs_offset);
            exanic->devkit_regs_phys = exanic->regs_phys +
                exanic->devkit_regs_offset;
            exanic->devkit_regs_virt =
                ioremap(exanic->devkit_regs_phys,
                    exanic->devkit_regs_size);
            if (!exanic->devkit_regs_virt)
            {
                dev_err(dev, "Devkit registers ioremap failed.\n");
                err = -EIO;
                goto err_devkit_regs_ioremap;
            }

            dev_info(dev,
                "Devkit regs at phys: 0x%pap, virt: 0x%p, size: %zu bytes.\n",
                &exanic->devkit_regs_phys, exanic->devkit_regs_virt,
                    exanic->devkit_regs_size);

            /* Configure Devkit memory region */
            if (pci_resource_flags(pdev, EXANIC_DEVKIT_MEMORY_REGION_BAR)
                    & IORESOURCE_MEM)
            {
                exanic->devkit_mem_size =
                    exanic_devkit_offset_to_size(exanic->devkit_mem_offset);
                exanic->devkit_mem_phys
                    = pci_resource_start(pdev, EXANIC_DEVKIT_MEMORY_REGION_BAR)
                        + exanic->devkit_mem_offset;
                exanic->devkit_mem_virt =
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
                    ioremap_wc(exanic->devkit_mem_phys, exanic->devkit_mem_size);
#else
                    ioremap(exanic->devkit_mem_phys, exanic->devkit_mem_size);
#endif

                if (!exanic->devkit_mem_virt)
                {
                    dev_err(dev, "Devkit memory ioremap failed.\n");
                    err = -EIO;
                    goto err_devkit_mem_ioremap;
                }
                dev_info(dev, "Devkit memory at phys: 0x%pap, size: %zu bytes.\n",
                    &exanic->devkit_mem_phys, exanic->devkit_mem_size);
            }
            else
            {
                dev_info(dev,
                    "Devkit memory not available. (BAR %u is not a memory resource.)\n",
                    EXANIC_DEVKIT_MEMORY_REGION_BAR);

                exanic->devkit_mem_offset = 0;
                exanic->devkit_mem_phys = 0;
                exanic->devkit_regs_virt = NULL;
            }
        }
    }
    else
    {
        exanic->devkit_regs_offset = 0;
        exanic->devkit_mem_offset = 0;
        exanic->devkit_regs_phys = 0;
        exanic->devkit_mem_phys = 0;
        exanic->devkit_regs_virt = NULL;
        exanic->devkit_mem_virt = NULL;
        exanic->devkit_regs_size = 0;
        exanic->devkit_mem_size = 0;
    }

    /* Set up and map the extended development kit memory if present. */
    if ((exanic->hwinfo.flags & EXANIC_HW_FLAG_DEVKIT) &&
        exanic->function_id == EXANIC_FUNCTION_DEVKIT)
    {
        /* Configure extended Devkit register region */
        if (pci_resource_flags(pdev, EXANIC_DEVKIT_REGISTERS_EX_REGION_BAR) &
                IORESOURCE_MEM)
        {
            exanic->devkit_regs_ex_size =
                pci_resource_len(pdev, EXANIC_DEVKIT_REGISTERS_EX_REGION_BAR);
            exanic->devkit_regs_ex_phys =
                pci_resource_start(pdev, EXANIC_DEVKIT_REGISTERS_EX_REGION_BAR);
            exanic->devkit_regs_ex_virt =
                ioremap(exanic->devkit_regs_ex_phys, exanic->devkit_regs_ex_size);

            if (!exanic->devkit_regs_ex_virt)
            {
                dev_err(dev, "Devkit extended registers ioremap failed.\n");
                err = -EIO;
                goto err_devkit_regs_ex_ioremap;
            }

            dev_info(dev,
                "Devkit extended regs at phys: 0x%pap, virt: 0x%p, size: %zu bytes.\n",
                &exanic->devkit_regs_ex_phys, exanic->devkit_regs_ex_virt,
                    exanic->devkit_regs_ex_size);
        }

        /* Configure extended Devkit memory region */
        if (pci_resource_flags(pdev, EXANIC_DEVKIT_MEMORY_EX_REGION_BAR) &
                IORESOURCE_MEM)
        {
            exanic->devkit_mem_ex_size =
                pci_resource_len(pdev, EXANIC_DEVKIT_MEMORY_EX_REGION_BAR);
            exanic->devkit_mem_ex_phys =
                pci_resource_start(pdev, EXANIC_DEVKIT_MEMORY_EX_REGION_BAR);
            exanic->devkit_mem_ex_virt =
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
                ioremap_wc(exanic->devkit_mem_ex_phys, exanic->devkit_mem_ex_size);
#else
                ioremap(exanic->devkit_mem_ex_phys, exanic->devkit_mem_ex_size);
#endif

            if (!exanic->devkit_mem_ex_virt)
            {
                dev_err(dev, "Devkit extended memory ioremap failed.\n");
                err = -EIO;
                goto err_devkit_mem_ex_ioremap;
            }
            dev_info(dev, "Devkit extended memory at phys: 0x%pap, size: %zu bytes.\n",
                &exanic->devkit_mem_ex_phys, exanic->devkit_mem_ex_size);
        }
    }
    else
    {
        exanic->devkit_regs_ex_virt = NULL;
        exanic->devkit_regs_ex_phys = 0;
        exanic->devkit_regs_ex_size = 0;
        exanic->devkit_mem_ex_virt = NULL;
        exanic->devkit_mem_ex_phys = 0;
        exanic->devkit_mem_ex_size = 0;
    }

    /* Fill in ATE information */
    if (exanic->caps & EXANIC_CAP_ATE)
    {
        uint32_t ate_status = readl(exanic->regs_virt +
                REG_EXANIC_OFFSET(REG_EXANIC_PORTS_ATE_STATUS));

        for (port_num = 0; port_num < exanic->num_ports; ++port_num)
        {
            exanic->port[port_num].has_ate =
                (ate_status & (1 << port_num)) ? true : false;
        }
    }


    /* Register ethernet interface */
    if (exanic->function_id == EXANIC_FUNCTION_NIC ||
        exanic->function_id == EXANIC_FUNCTION_FIREWALL ||
        exanic->function_id == EXANIC_FUNCTION_PTP_GM ||
        exanic->function_id == EXANIC_FUNCTION_DEVKIT)
    {
        for (port_num = 0; port_num < exanic->num_ports; ++port_num)
        {
            unsigned port_status = readl(exanic->regs_virt +
                    REG_PORT_OFFSET(port_num, REG_PORT_STATUS));

            if (port_status & EXANIC_PORT_NOT_IMPLEMENTED)
                continue;

            err = exanic_netdev_alloc(exanic, port_num,
                    &exanic->ndev[port_num]);
            if (err)
            {
                dev_err(dev,
                        "Failed to register ethernet interface for port %d.\n",
                        port_num);
                goto err_netdev;
            }
        }
    }

    /* Register PTP hardware clock */
#if defined(CONFIG_PTP_1588_CLOCK) || defined(CONFIG_PTP_1588_CLOCK_MODULE)
    exanic_ptp_init(exanic);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
    timer_setup(&exanic->link_timer, exanic_link_timer_callback, 0);
#else
    /* Set up timer to poll link status */
    setup_timer(&exanic->link_timer, exanic_link_timer_callback,
            (unsigned long)exanic);
#endif
    mod_timer(&exanic->link_timer, jiffies + HZ);

    /* Register device (misc_dev.minor already initialized) */
    exanic->misc_dev.name = exanic->name;
    exanic->misc_dev.fops = &exanic_fops;
    err = misc_register(&exanic->misc_dev);
    if (err)
    {
        dev_err(dev, "misc_register failed: %d\n", err);
        goto err_miscdev;
    }

    dev_info(dev, "Finished probing %s (minor = %u):\n",
        exanic->name, exanic->misc_dev.minor);
    dev_info(dev, "  ExaNIC interface version = %u\n",
        exanic->pcie_if_ver);
    dev_info(dev, "  Hardware ID = %s\n", hw_id_str);
    dev_info(dev, "  Function = %s\n", function_str);
    if ((exanic->function_id == EXANIC_FUNCTION_NIC ||
            exanic->function_id == EXANIC_FUNCTION_PTP_GM ||
                exanic->function_id == EXANIC_FUNCTION_DEVKIT) &&
                exanic->tx_region_size > 0)
    {
        dev_dbg(dev, "  TX engines:\n");
        for (port_num = 0; port_num < exanic->num_ports; ++port_num)
        {
            unsigned t;
            unsigned types = readl(exanic->regs_virt +
                REG_PORT_OFFSET(port_num, REG_PORT_TX_SUPPORTED_TYPES));
            unsigned port_status = readl(exanic->regs_virt +
                REG_PORT_OFFSET(port_num, REG_PORT_STATUS));
            if (port_status & (EXANIC_PORT_NOT_IMPLEMENTED |
                        EXANIC_PORT_TX_UNSUPPORTED))
                continue;
            dev_dbg(dev, "    Port %u:\n", port_num);
            dev_dbg(dev, "      TX region usable offset = 0x%08zx\n",
                    exanic->port[port_num].tx_region_usable_offset);
            dev_dbg(dev, "      TX region usable size = 0x%04zx\n",
                    exanic->port[port_num].tx_region_usable_size);
            dev_dbg(dev, "      Supported type(s) = 0x%04x:\n", types);
            for (t = 1; types != 0; types >>= 1, t <<= 1)
            {
                if (types & 1)
                {
                    const char *type_id_str = exanic_tx_type_id_str(t);
                    dev_dbg(dev, "        - %s\n",
                            type_id_str ? type_id_str : "unknown");
                }
            }
        }
    }

    return 0;

err_miscdev:
err_netdev:
    for (port_num = 0; port_num < exanic->num_ports; ++port_num)
        exanic_netdev_free(exanic->ndev[port_num]);
    iounmap(exanic->devkit_mem_ex_virt);
err_devkit_mem_ex_ioremap:
    iounmap(exanic->devkit_regs_ex_virt);
err_devkit_regs_ex_ioremap:
    iounmap(exanic->devkit_mem_virt);
err_devkit_mem_ioremap:
    iounmap(exanic->devkit_regs_virt);
err_devkit_regs_ioremap:
err_flow_steering:
    for (port_num = 0; port_num < exanic->num_ports; ++port_num)
    {
        if(exanic->port[port_num].mac_filter_slots != NULL)
            kfree(exanic->port[port_num].mac_filter_slots);
        if(exanic->port[port_num].ip_filter_slots != NULL)
            kfree(exanic->port[port_num].ip_filter_slots);
        if(exanic->port[port_num].filter_buffers != NULL)
            kfree(exanic->port[port_num].filter_buffers);
    }
    if (exanic->caps & EXANIC_CAP_RX_MSI)
    {
        free_irq(pdev->irq, exanic);
        pci_disable_msi(pdev);
    }
err_interrupts:
    vfree(exanic->info_page);
err_info_page_alloc:
    exanic_sysfs_exit(exanic);
err_sysfs_init:
    exanic_i2c_exit(exanic);
err_i2c_init:
    dma_free_coherent(&exanic->pci_dev->dev,
            EXANIC_TX_FEEDBACK_NUM_PAGES * PAGE_SIZE,
            exanic->tx_feedback_virt, exanic->tx_feedback_dma);
err_tx_feedback_alloc:
    if (exanic->tx_region_virt != NULL)
        iounmap(exanic->tx_region_virt);
err_dma_mask:
err_timeout:
err_function_id:
err_hw_id:
err_interface_ver:

    /* Minimal support for unsupported cards, to allow firmware update. */

    /* Register device (misc_dev.minor already initialized) */
    exanic->misc_dev.name = exanic->name;
    exanic->misc_dev.fops = &exanic_fops;
    exanic->unsupported = true;
    exanic->num_ports = 0;
    err = misc_register(&exanic->misc_dev);
    if (!err)
    {
        dev_info(dev, "Finished probing %s (minor = %u):\n",
            exanic->name, exanic->misc_dev.minor);
        dev_info(dev, "  Error encountered during probe, minimal support enabled\n");
        return 0;
    }
    else
        dev_err(dev, "misc_register failed: %d\n", err);

    /* If we get here, no device file was created and we need to error out */

    iounmap(exanic->regs_virt);
err_regs_ioremap:
err_regs_size:
err_regs_bar_type:
#if __HAS_PCI_ERR_REPORTING
#if defined(CONFIG_PCIEAER)
    pci_disable_pcie_error_reporting(pdev);
#endif
#endif
    pci_release_regions(pdev);
err_req_regions:
    pci_disable_device(pdev);
err_pci_enable_dev:
    spin_lock(&exanic_devices_lock);
    list_del(&exanic->node);
    spin_unlock(&exanic_devices_lock);
    return err;
}

/**
 * Device removal
 *
 * This function is called by the PCI subsystem to inform the driver to release
 * a exanic.  This could be due to a hotplug event, or because the driver is
 * about to be unloaded.
 *
 * Bridging and mirroring settings persist after the unload, and ports are not
 * powered down if bridging or mirroring requires them.
 */
static void exanic_remove(struct pci_dev *pdev)
{
    struct exanic *exanic = pci_get_drvdata(pdev);
    struct device *dev = &pdev->dev;
    int i, j;

    dev_info(dev, "Removing exanic%u.\n", exanic->id);

    spin_lock(&exanic_devices_lock);
    list_del(&exanic->node);
    spin_unlock(&exanic_devices_lock);

    if (!exanic->unsupported)
        del_timer_sync(&exanic->link_timer);

#if defined(CONFIG_PTP_1588_CLOCK) || defined(CONFIG_PTP_1588_CLOCK_MODULE)
    exanic_ptp_remove(exanic);
#endif

    for (i = 0; i < exanic->num_ports; ++i)
        exanic_netdev_free(exanic->ndev[i]);

    for (i = 0; i < exanic->num_ports; ++i)
    {
        for (j = 0; j < exanic->port[i].max_ip_filter_slots; j++)
        {
            exanic_remove_ip_filter(exanic, i, j);
        }

        for (j = 0; j < exanic->port[i].max_mac_filter_slots; j++)
        {
            exanic_remove_mac_filter(exanic, i, j);
        }

        if(exanic->port[i].mac_filter_slots != NULL)
            kfree(exanic->port[i].mac_filter_slots);
        if(exanic->port[i].ip_filter_slots != NULL)
            kfree(exanic->port[i].ip_filter_slots);
        if(exanic->port[i].filter_buffers != NULL)
            kfree(exanic->port[i].filter_buffers);
    }

    for (i = 0; i < exanic->num_ports; ++i)
        exanic_disable_port(exanic, i);

    for (i = 0; i < exanic->num_ports; ++i)
        exanic_free_rx_dma(exanic, i);

    if (!exanic->unsupported
        && (exanic->caps & EXANIC_CAP_RX_MSI))
    {
        free_irq(pdev->irq, exanic);
        pci_disable_msi(pdev);
    }

    if (exanic->info_page != NULL)
        vfree(exanic->info_page);

    if (exanic->devkit_mem_virt != NULL)
        iounmap(exanic->devkit_mem_virt);

    if (exanic->devkit_regs_virt != NULL)
        iounmap(exanic->devkit_regs_virt);

    if (exanic->devkit_mem_ex_virt != NULL)
        iounmap(exanic->devkit_mem_ex_virt);

    if (exanic->devkit_regs_ex_virt != NULL)
        iounmap(exanic->devkit_regs_ex_virt);

    if (exanic->tx_feedback_virt != NULL)
        dma_free_coherent(&exanic->pci_dev->dev,
                          EXANIC_TX_FEEDBACK_NUM_PAGES * PAGE_SIZE,
                          exanic->tx_feedback_virt, exanic->tx_feedback_dma);
    if (exanic->tx_region_virt != NULL)
        iounmap(exanic->tx_region_virt);

    if (!exanic->unsupported)
    {
        exanic_sysfs_exit(exanic);
        exanic_i2c_exit(exanic);
    }

    misc_deregister(&exanic->misc_dev);

    /* If a card reset has been requested post remove, trigger that just before
     * unmapping registers. The card will reset after a short delay (~200ms). */
    if (exanic->reset_on_remove)
    {
        dev_info(dev, "Triggering reset of exanic%u.\n", exanic->id);
        writel(1, exanic->regs_virt + REG_HW_OFFSET(REG_HW_RELOAD_RESET_FPGA));
    }

    if (exanic->regs_virt != NULL)
        iounmap(exanic->regs_virt);

#if __HAS_PCI_ERR_REPORTING
#if defined(CONFIG_PCIEAER)
    pci_disable_pcie_error_reporting(pdev);
#endif
#endif
    pci_release_regions(pdev);
    pci_disable_device(pdev);
}

/**
 * Device shutdown
 *
 * This hooks into reboot_notifier_list (kernel/sys.c) and is used to put the
 * card into a sane state for reboot.
 */
static void exanic_shutdown(struct pci_dev *pdev)
{
    struct exanic *exanic = pci_get_drvdata(pdev);
    struct device *dev = &pdev->dev;
    int i;

    dev_info(dev, "Shutting down exanic%u.\n", exanic->id);

    /* Disable all ports to stop DMA */
    for (i = 0; i < exanic->num_ports; ++i)
    {
        writel(0, exanic->regs_virt + REG_PORT_OFFSET(i, REG_PORT_ENABLED));
        writel(0, exanic->regs_virt + REG_PORT_OFFSET(i, REG_PORT_IRQ_CONFIG));
    }
}

static struct pci_driver exanic_driver = {
    .name       = DRV_NAME,
    .id_table   = exanic_pci_ids,
    .probe      = exanic_probe,
    .remove     = exanic_remove,
    .shutdown   = exanic_shutdown
};


/**
 * Driver initialisation
 *
 * This function is called when the driver is loaded.
 */
static int __init exanic_init(void)
{
    int err;

    pr_info("ExaNIC network driver (ver " DRV_VERSION ") loaded.\n");

    if (exanic_macaddr_param[0])
    {
        u8 a[6];

        if (sscanf(exanic_macaddr_param, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                    &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]) != 6)
        {
            pr_err("Could not parse MAC address \"%s\".",
                    exanic_macaddr_param);
            return -EINVAL;
        }

        memcpy(next_mac_addr, a, ETH_ALEN);
    }

    err = pci_register_driver(&exanic_driver);
    if (err)
    {
        pr_info("Failed to register PCI driver.\n");
        goto err_pci_register_driver;
    }

    return 0;

err_pci_register_driver:
    return err;
}
module_init(exanic_init);

/**
 * Driver cleanup
 *
 * This function is called when the driver is unloaded.
 */
static void __exit exanic_exit(void)
{
    pci_unregister_driver(&exanic_driver);
    pr_info("ExaNIC network driver (ver " DRV_VERSION ") unloaded.\n");
}
module_exit(exanic_exit);

MODULE_AUTHOR("Exablaze team <support@exablaze.com>");
MODULE_DESCRIPTION("ExaNIC network driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
/* MODULE_SUPPORTED_SUPPORTED device has been removed since kernel version 5.12 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
MODULE_SUPPORTED_DEVICE(DRV_NAME);
#endif
