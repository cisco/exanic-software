/**
 * ExaNIC PHY level operations
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
#include "../../libs/exanic/hw_info.h"
#include "exanic.h"
#include "exanic-i2c.h"
#include "exanic-phyops.h"
#include "exanic-phyops-cmis.h"
#include "exanic-structs.h"

typedef struct
{
    /* mapping between ExaNIC capability bits and ethtool link modes */
    uint32_t capability;
    const uint8_t* link_modes;
} exa_caps_ethtool_modes_mapping_t;

#define CAP_ETHTOOL_LINK_MODES_TABLE_END (255)
#define CAP_ETHTOOL_LINK_MODES_TABLE_ENTRY(cap, ...) \
    const uint8_t supported_modes_##cap##_ [] = {__VA_ARGS__, CAP_ETHTOOL_LINK_MODES_TABLE_END}; \
    exa_caps_ethtool_modes_mapping_t _##cap##_link_modes_entry = \
    { \
        .capability = cap, \
        .link_modes = supported_modes_##cap##_, \
    }

#define ADD_ETHTOOL_LINKMODES_PER_CAPABILITY(cap) \
    &_##cap##_link_modes_entry,


CAP_ETHTOOL_LINK_MODES_TABLE_ENTRY(EXANIC_CAP_100M, _ETHTOOL_LINK_MODE_100baseT_Full_BIT, _ETHTOOL_LINK_MODE_10baseT_Full_BIT);

CAP_ETHTOOL_LINK_MODES_TABLE_ENTRY(EXANIC_CAP_1G, _ETHTOOL_LINK_MODE_1000baseT_Full_BIT, _ETHTOOL_LINK_MODE_1000baseKX_Full_BIT);

CAP_ETHTOOL_LINK_MODES_TABLE_ENTRY(EXANIC_CAP_10G, _ETHTOOL_LINK_MODE_10000baseKR_Full_BIT);

CAP_ETHTOOL_LINK_MODES_TABLE_ENTRY(EXANIC_CAP_40G,
        _ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT,
        _ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT,
        _ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT);

CAP_ETHTOOL_LINK_MODES_TABLE_ENTRY(EXANIC_CAP_25G, _ETHTOOL_LINK_MODE_25000baseKR_Full_BIT, _ETHTOOL_LINK_MODE_25000baseCR_Full_BIT);
CAP_ETHTOOL_LINK_MODES_TABLE_ENTRY(EXANIC_CAP_25G_S, _ETHTOOL_LINK_MODE_25000baseKR_Full_BIT, _ETHTOOL_LINK_MODE_25000baseCR_Full_BIT);


static const exa_caps_ethtool_modes_mapping_t* caps2ethtool_modes [] =
{
    ADD_ETHTOOL_LINKMODES_PER_CAPABILITY(EXANIC_CAP_100M)
    ADD_ETHTOOL_LINKMODES_PER_CAPABILITY(EXANIC_CAP_1G)
    ADD_ETHTOOL_LINKMODES_PER_CAPABILITY(EXANIC_CAP_10G)
    ADD_ETHTOOL_LINKMODES_PER_CAPABILITY(EXANIC_CAP_25G)
    ADD_ETHTOOL_LINKMODES_PER_CAPABILITY(EXANIC_CAP_25G_S)
    ADD_ETHTOOL_LINKMODES_PER_CAPABILITY(EXANIC_CAP_40G)
    NULL
};

static const unsigned int lp_techs_to_ethtoolmode [] =
{
    [TECH_ABILITY_1000BASE_KX] =   _ETHTOOL_LINK_MODE_1000baseKX_Full_BIT,
    [TECH_ABILITY_10GBASE_KX4] =   _ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT,
    [TECH_ABILITY_10GBASE_KR] =    _ETHTOOL_LINK_MODE_10000baseKR_Full_BIT,
    [TECH_ABILITY_40GBASE_KR4] =   _ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT,
    [TECH_ABILITY_40GBASE_CR4] =   _ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT,
    [TECH_ABILITY_100GBASE_CR10] = _ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT,
    [TECH_ABILITY_100GBASE_KP4] =  _ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT,
    [TECH_ABILITY_100GBASE_KR4] =  _ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT,
    [TECH_ABILITY_100GBASE_CR4] =  _ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT,
    [TECH_ABILITY_25GBASE_KR_S] =  _ETHTOOL_LINK_MODE_25000baseCR_Full_BIT,
    [TECH_ABILITY_25GBASE_KR] =    _ETHTOOL_LINK_MODE_25000baseCR_Full_BIT,
};

/* Decode SFF-8024 identification byte to determine pluggable transceiver type */
#define SFF_8024_ID_SFP(id)             ((id) == 0x03)
#define SFF_8024_ID_QSFP(id)            ((id) == 0x0C || (id) == (0x0D) ||\
                                         (id) == 0x11)
#define SFF_8024_ID_QSFPDD(id)          ((id) == 0x18)

/* Define QSFP types and page lengths if not already defined */
#ifndef ETH_MODULE_SFF_8436
#define ETH_MODULE_SFF_8436             0x4
#endif

#ifndef ETH_MODULE_SFF_8436_LEN
#define ETH_MODULE_SFF_8436_LEN         256
#endif

#ifndef ETH_MODULE_SFF_8436_MAX_LEN
#define ETH_MODULE_SFF_8436_MAX_LEN     640
#endif

/* Provisional get_module_eeprom memory map for QSFP-DD
 * defined for the purpose of exanic userspace utils
 *
 *  0-127   : lower page 00h
 *  128-255 : upper page 00h
 *  256-383 : upper page 01h
 *  384-511 : upper page 10h
 *  512-639 : upper page 11h
 *
 * TODO: migrate to new scheme once kernel support for CMIS
 *       is available */

#define ETH_MODULE_CMIS_QSFPDD          0x800000dd

/* flat memory size for QSFP-DD (lower 00h and upper 00h) */
#define ETH_MODULE_CMIS_QSFPDD_LEN      256
#define ETH_MODULE_CMIS_QSFPDD_MAX_LEN  640

static bool exanic_speed_capable(uint32_t caps, uint32_t speed)
{
    return ((speed == SPEED_100 && (caps & EXANIC_CAP_100M)) ||
            (speed == SPEED_1000 && (caps & EXANIC_CAP_1G)) ||
            (speed == SPEED_10000 && (caps & EXANIC_CAP_10G)) ||
            (speed == SPEED_25000 && ((caps & EXANIC_CAP_25G) || (caps & EXANIC_CAP_25G_S))) ||
            (speed == SPEED_40000 && (caps & EXANIC_CAP_40G)));
}

/* returns whether a port is connected to the pluggable transceiver
 * e.g. with a 4 to 1 adapter in a QSFP port, only port 0 is connected */
static bool
exanic_xcvr_connected(struct exanic *exanic, int port, uint8_t sff8024_id)
{
    int port_width = exanic_phyops_if_width(exanic);
    int lane_start = exanic_phyops_if_lane_index(exanic, port, port_width);
    int xcvr_width = exanic_phyops_xcvr_width(sff8024_id);

    if (port_width == -1 || lane_start == -1 || xcvr_width == -1)
        return false;

    return lane_start + port_width <= xcvr_width;
}

static void
exanic_phyops_marvell_reset(struct exanic *exanic, unsigned port_number)
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

static int
exanic_phyops_marvell_enable_fast_ethernet(struct exanic *exanic, unsigned port_number)
{
    int err;
    /* Per Finisar AN-2036 */
    uint16_t data;
    uint8_t *ptr = (uint8_t *)&data;

    data = htons(0x0000);
    if ((err = exanic_i2c_xcvr_write(exanic, port_number, 0xAC, 0x16, ptr, 2)))
        return err;

    /* Extended PHY Specific Status Register */
    if ((err = exanic_i2c_xcvr_read(exanic, port_number, 0xAC, 0x1B, ptr, 2)))
        return err;
    /* "SGMII without clock with SGMII auto-neg to copper" */
    data = (data & ~htons(0x000F)) | htons(0x0004);
    if ((err = exanic_i2c_xcvr_write(exanic, port_number, 0xAC, 0x1B, ptr, 2)))
        return err;

    /* Control Register (Copper) */
    if ((err = exanic_i2c_xcvr_read(exanic, port_number, 0xAC, 0x00, ptr, 2)))
        return err;
    /* Reset bit */
    data |= htons(0x8000);
    if ((err = exanic_i2c_xcvr_write(exanic, port_number, 0xAC, 0x00, ptr, 2)))
        return err;

    /* 1000BASE-T Control Register */
    if ((err = exanic_i2c_xcvr_read(exanic, port_number, 0xAC, 0x09, ptr, 2)))
        return err;
    /* Do not advertise 1000BASE-T */
    data &= ~htons(0x0300);
    if ((err = exanic_i2c_xcvr_write(exanic, port_number, 0xAC, 0x09, ptr, 2)))
        return err;

    /* Auto-Negotiation Advertisement Register (Copper) */
    if ((err = exanic_i2c_xcvr_read(exanic, port_number, 0xAC, 0x04, ptr, 2)))
        return err;
    /* Advertise 100BASE-TX Full-Duplex and Half-Duplex */
    data = (data & ~htons(0x03E0)) | htons(0x0180);
    if ((err = exanic_i2c_xcvr_write(exanic, port_number, 0xAC, 0x04, ptr, 2)))
        return err;

    /* Control Register (Copper) */
    if ((err = exanic_i2c_xcvr_read(exanic, port_number, 0xAC, 0x00, ptr, 2)))
        return err;
    /* 100Mbps */
    data = (data & ~htons(0x2040)) | htons(0x2000);
    /* Reset bit */
    data |= htons(0x8000);
    /* Full-duplex */
    data |= htons(0x0100);
    /* Enable autonegotiation */
    data |= htons(0x1000);
    if ((err = exanic_i2c_xcvr_write(exanic, port_number, 0xAC, 0x00, ptr, 2)))
        return err;

    /* LED Control Register */
    if ((err = exanic_i2c_xcvr_read(exanic, port_number, 0xAC, 0x18, ptr, 2)))
        return err;
    /* LED_Link = 001 (use LED_LINK1000 pin as global link indicator) */
    data = (data & htons(0x0038)) | htons(0x0008);
    if ((err = exanic_i2c_xcvr_write(exanic, port_number, 0xAC, 0x18, ptr, 2)))
        return err;


    dev_info(&exanic->pci_dev->dev,
             "%s:%d: 100BASE-TX mode enabled\n",
             exanic->name, port_number);
    return 0;
}

static int
exanic_phyops_is_sfp_marvell(struct exanic *exanic, unsigned port_number)
{
    uint16_t data = 0;
    uint8_t *ptr = (uint8_t *)&data;

    /* PHY Identifier */
    int err = exanic_i2c_xcvr_read(exanic, port_number, 0xAC, 0x02, ptr, 2);
    if (err || data != htons(0x0141))
        return 0;

    /* PHY Identifier */
    err = exanic_i2c_xcvr_read(exanic, port_number, 0xAC, 0x03, ptr, 2);
    if (err || (data & htons(0xFFF0)) != htons(0x0CC0))
        return 0;

    return 1;
}

static int
exanic_phyops_x2_x4_optimise(struct exanic *exanic, unsigned int port_number)
{
    /* conservative default parameters */
    uint8_t rx_param[] = { 0x50, 0x14, 0x00 };
    uint8_t tx_param[] = { 0x04, 0x0C, 0x05 };
    uint8_t cable_type, cable_length;

    /* optimise parameters based on cable type and length */
    int ret = exanic_i2c_xcvr_read(exanic, port_number, XCVR_EEPROM_ADDR, 8,
                                   &cable_type, 1);
    if (ret || (cable_type & 4) == 0)
        goto default_params;

    ret = exanic_i2c_xcvr_read(exanic, port_number, XCVR_EEPROM_ADDR, 18,
                               &cable_length, 1);
    if (ret == 0 && cable_length < 5)
    {
        /* short passive cable */
        /* apply some extra analog gain and pre-boost settings */
        rx_param[0] = 0x58 + 8*cable_length;
        rx_param[1] = 0x16 + 2*cable_length;
        tx_param[1] = 0x0E + 2*cable_length;
        dev_info(exanic_dev(exanic),
                 DRV_NAME "%u: Port %u detected passive cable (%um).\n",
                 exanic->id, port_number, cable_length);
    }
    else
    {
        /* very long passive cable >= 5m */
        /* apply most aggressive analog gain and pre-boost settings */
        rx_param[0] = 0x7F;
        rx_param[1] = 0x1E;
        tx_param[1] = 0x16;
        dev_info(exanic_dev(exanic),
                 DRV_NAME "%u: Port %u detected passive cable (long).\n",
                 exanic->id, port_number);
    }

default_params:

    if ((ret = exanic_i2c_ext_phy_write(exanic, port_number,
                                        EXANIC_EXT_PHY_RXGAIN_OFFSET,
                                        rx_param, 3)))
        return ret;
    if ((ret = exanic_i2c_ext_phy_write(exanic, port_number,
                                        EXANIC_EXT_PHY_TXODSW_OFFSET,
                                        tx_param, 3)))
        return ret;

    return 0;
}

static int
exanic_phyops_marvell_set_speed(struct exanic *exanic, int port_number,
                                uint32_t old_speed, uint32_t speed)
{
    if (speed == SPEED_100)
    {
        if (!exanic_phyops_is_sfp_marvell(exanic, port_number))
            return -EOPNOTSUPP;

        return exanic_phyops_marvell_enable_fast_ethernet(exanic, port_number);
    }
    else if (old_speed == SPEED_100)
        exanic_phyops_marvell_reset(exanic, port_number);

    return 0;
}

#ifdef ETHTOOL_GMODULEINFO
/* common get_module_eeprom implementation for QSFP and QSFP-DD */
static int
exanic_phyops_get_module_eeprom_paged(struct exanic *exanic, int port,
                                      struct ethtool_eeprom *eep, u8 *data,
                                      bool cmis)
{
    size_t offset = eep->offset, len = eep->len;
    size_t page_boundary = 0, bytes_rem = len;

    int page_index = 0;
    uint8_t qsfp_pages[] = {0, 1, 2, 3};
    uint8_t cmis_pages[] = {0, 1, 0x10, 0x11};

    u8 *ptr = data;
    int err = 0;

    size_t page_size = cmis ? ETH_MODULE_CMIS_QSFPDD_LEN :
                              ETH_MODULE_SFF_8436_LEN;
    size_t maxlen = cmis ? ETH_MODULE_CMIS_QSFPDD_MAX_LEN :
                           ETH_MODULE_SFF_8436_MAX_LEN;
    if (offset + len > maxlen)
        return -EINVAL;

    if (len == 0)
        return -EINVAL;

    while (bytes_rem)
    {
        /* read the lower and upper pages in one go for page_index 0,
         * otherwise read the upper page only */
        size_t curr_page_len = page_index ? (page_size / 2): page_size;
        size_t page_offset;
        size_t bytes_read;
        uint8_t page_reg = cmis ?
                            cmis_pages[page_index % sizeof cmis_pages] :
                            qsfp_pages[page_index % sizeof qsfp_pages];

        if (offset >= page_boundary + curr_page_len)
            goto turn_page;

        /* write page (and bank) registers */
        err = cmis ?
            exanic_i2c_cmis_page_sel(exanic, port, 0, page_reg) :
            exanic_i2c_qsfp_page_sel(exanic, port, page_reg);
        if (err)
            goto page0_sel;

        page_offset = offset - page_boundary;
        bytes_read = min(bytes_rem, curr_page_len - page_offset);

        /* apply upper page offset */
        if (page_index)
            page_offset += page_size / 2;

        err = exanic_i2c_xcvr_read(exanic, port, XCVR_EEPROM_ADDR,
                                   page_offset, ptr, bytes_read);
        if (err)
            goto page0_sel;

        bytes_rem -= bytes_read;
        ptr += bytes_read;
        offset += bytes_read;

turn_page:
        page_boundary += curr_page_len;
        page_index++;
    }

page0_sel:
    if (cmis)
        exanic_i2c_cmis_page_sel(exanic, port, 0, 0);
    else
        exanic_i2c_qsfp_page_sel(exanic, port, 0);

    return err;
}
#endif /* ETHTOOL_GMODULEINFO */

/* generic poweron function */
static int __exanic_phyops_poweron(struct exanic *exanic, int port)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    uint32_t reg = readl(&regs[REG_HW_INDEX(REG_HW_POWERDOWN)]);

    /* Turn on the SFP TX */
    reg |= (1 << (EXANIC_SFP_TXDIS0 + port));
    writel(reg, &regs[REG_HW_INDEX(REG_HW_POWERDOWN)]);

    return 0;
}

/* generic poweroff function */
static void __exanic_phyops_poweroff(struct exanic *exanic, int port)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    uint32_t reg = readl(&regs[REG_HW_INDEX(REG_HW_POWERDOWN)]);

    /* Turn off the SFP TX */
    reg &= ~(1 << (EXANIC_SFP_TXDIS0 + port));
    writel(reg, &regs[REG_HW_INDEX(REG_HW_POWERDOWN)]);
}

static int set_25g_autoneg_link_modes(struct exanic *exanic, int port,
                                      const exanic_phyops_configs_t *configs,
                                      uint32_t cap_mask)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    uint32_t caps = exanic->caps & cap_mask;
    uint32_t autoneg_caps = readl(&regs[REG_EXTENDED_PORT_INDEX(port, REG_EXTENDED_PORT_AN_ABILITY)]);
    autoneg_caps &= ~EXANIC_AUTONEG_ABILITY_MASK;

    if (LINK_CONFIGS_GET_ADVERTISING(configs))
    {
        /* Advertise only the modes which are requested by ethtool */
        int i;
        const unsigned int* ptr = lp_techs_to_ethtoolmode;
        bool matches = false;
        for (i = 0; i < (sizeof(lp_techs_to_ethtoolmode) / sizeof(lp_techs_to_ethtoolmode[0])); i++)
        {
            unsigned long int val = (1ULL << ptr[i]);
            if (LINK_CONFIGS_GET_ADVERTISING(configs) & val)
            {
                autoneg_caps |= (1 << i);
                matches = true;
            }
        }

        if (!matches)
            return -EOPNOTSUPP;
    }
    else
    {
        uint32_t speed = LINK_CONFIGS_GET_SPEED(configs);
        if (speed)
        {
            /* Advertise only the requested speed */
            if (speed == SPEED_25000 && IS_25G_SUPPORTED(caps))
            {
                if (caps & EXANIC_CAP_25G)
                    autoneg_caps |= AUTONEG_TECH_ABILITY_25G_BASE_KR;
                if (caps & EXANIC_CAP_25G_S)
                    autoneg_caps |= AUTONEG_TECH_ABILITY_25G_BASE_KR_S;
            }
            else if (speed == SPEED_10000 && (caps & EXANIC_CAP_10G))
            {
                autoneg_caps |= AUTONEG_TECH_ABILITY_10G_BASE_KR;
            }
        }
        else
        {

            /* If no specific modes are provided and no specific requested speed,
             * advertise all available modes */
            if (caps & EXANIC_CAP_10G)
                autoneg_caps |= AUTONEG_TECH_ABILITY_10G_BASE_KR;
            if (caps & EXANIC_CAP_25G)
                autoneg_caps |= AUTONEG_TECH_ABILITY_25G_BASE_KR;
            if (caps & EXANIC_CAP_25G_S)
                autoneg_caps |= AUTONEG_TECH_ABILITY_25G_BASE_KR_S;
        }
    }
    writel(autoneg_caps, &regs[REG_EXTENDED_PORT_INDEX(port, REG_EXTENDED_PORT_AN_ABILITY)]);
    return 0;
}

/* common set_configs implementation
 * cap_mask: bitmask applied to ExaNIC capability register */
static int
__exanic_phyops_set_configs_ex(struct exanic *exanic, int port,
                               const exanic_phyops_configs_t *configs,
                               uint32_t cap_mask,
                               int (*__phy_set_speed)(struct exanic *, int,
                                                      uint32_t, uint32_t))
{
    volatile uint32_t *regs = exanic_registers(exanic);
    uint32_t port_flags, speed_reg, speed, caps;
    bool autoneg_enable;
    bool force_set_speed = false;

    caps = exanic->caps & cap_mask;
    speed = LINK_CONFIGS_GET_SPEED(configs);
    autoneg_enable = LINK_CONFIGS_GET(configs, autoneg);

    if (IS_25G_SUPPORTED(caps) && autoneg_enable)
    {
        int ret = set_25g_autoneg_link_modes(exanic, port, configs, cap_mask);
        if (ret)
            return ret;
    }

    speed_reg = readl(&regs[REG_PORT_INDEX(port, REG_PORT_SPEED)]);
    port_flags = readl(&regs[REG_PORT_INDEX(port, REG_PORT_FLAGS)]);

    if (IS_25G_SUPPORTED(caps) && (port_flags & EXANIC_PORT_FLAG_AUTONEG_ENABLE))
    {
        /* When autoneg is on, the speed register only reflects the currently
         * operating speed not the underlying requested speed, so we may still
         * need to set the speed even if speed_reg == speed. */
        force_set_speed = true;
    }

    if ((speed != 0) && ((speed_reg != speed) || force_set_speed))
    {
        if (!exanic_speed_capable(caps, speed))
            return -EINVAL;

        /* configure FPGA-side data rate */
        writel(speed, &regs[REG_PORT_INDEX(port, REG_PORT_SPEED)]);

        /* configure PHY data rate if applicable */
        if (__phy_set_speed)
        {
            int ret = __phy_set_speed(exanic, port, port_flags, speed);
            if (ret)
            {
                dev_err(&exanic->pci_dev->dev,
                        "%s:%d: failed to configure PHY speed: %d\n",
                        exanic->name, port, ret);
                return ret;
            }
        }

        /* save speed to EEPROM */
        exanic_save_speed(exanic, port, speed);
    }

    if (autoneg_enable)
        port_flags |= EXANIC_PORT_FLAG_AUTONEG_ENABLE;
    else
        port_flags &= ~EXANIC_PORT_FLAG_AUTONEG_ENABLE;

    writel(port_flags, &regs[REG_PORT_INDEX(port, REG_PORT_FLAGS)]);

    /* save autoneg config to EEPROM */
    exanic_save_autoneg(exanic, port, autoneg_enable);

    return 0;
}

/* generic link setting setter */
static int
__exanic_phyops_set_configs(struct exanic *exanic, int port,
                            const exanic_phyops_configs_t *configs)
{
    return __exanic_phyops_set_configs_ex(exanic, port, configs,
                                          ~0, NULL);
}

static void add_ethtool_modes(const exa_caps_ethtool_modes_mapping_t* entry_ptr,
			exanic_phyops_configs_t *configs)
{
    const uint8_t* lm_ptr = entry_ptr->link_modes;
    /* Only add modes which exanic device supports */
    while(*lm_ptr != CAP_ETHTOOL_LINK_MODES_TABLE_END)
        LINK_CONFIGS_SET_SUPPORTED_BIT(configs, *lm_ptr++);
}

static void
get_25G_autoneg_info(struct exanic *exanic, int port,
                            exanic_phyops_configs_t *configs)
{
    volatile uint32_t *regs = exanic_registers(exanic);

    /* get link partner advertised techs when there is a link and
     * we are operating in autoneg mode and autoneg has been done */
    uint32_t autoneg_lp_ability = readl(&regs[REG_EXTENDED_PORT_INDEX(port, REG_EXTENDED_PORT_AN_LP_ABILITY)]);
    uint32_t autoneg_status = readl(&regs[REG_EXTENDED_PORT_INDEX(port, REG_EXTENDED_PORT_AN_STATUS)]);
    uint32_t autoneg_ability = readl(&regs[REG_EXTENDED_PORT_INDEX(port, REG_EXTENDED_PORT_AN_ABILITY)]);
    uint32_t autoneg_lp_tech_ability = LINK_PARTNER_TECHS(autoneg_lp_ability);
    unsigned int i = 0;

    uint32_t autoneg_caps = AUTONEG_CAPS(autoneg_ability);

    /* Return which technologies we are advertising */
    for_each_set_bit(i, (const unsigned long*)&autoneg_caps, EXANIC_AUTONEG_LINK_PARTNER_TECH_ABILITY_BIT_FIELD_SIZE)
        LINK_CONFIGS_SET_ADVERTISING_BIT(configs, lp_techs_to_ethtoolmode[i]);

    /* Return which technologies link-partner is advertising */
    for_each_set_bit(i, (const unsigned long*)&autoneg_lp_tech_ability, EXANIC_AUTONEG_LINK_PARTNER_TECH_ABILITY_BIT_FIELD_SIZE)
        LINK_CONFIGS_SET_LP_ADVERTISING_BIT(configs, lp_techs_to_ethtoolmode[i]);

    /* Check whether link-partner supports auto-neg and if so, set the corresponding ethtool mode bit */
    if (autoneg_status & EXANIC_PORT_AUTONEG_FLAGS_LINK_PARTNER_IS_AUTONEG)
        LINK_CONFIGS_SET_LP_ADVERTISING_BIT(configs, _ETHTOOL_LINK_MODE_Autoneg_BIT);

#ifdef ETHTOOL_SFECPARAM
    /* Show which FEC modes link partner advertises */
    if (autoneg_lp_ability & FEC_CAPABILITY_RS_FEC)
        LINK_CONFIGS_SET_LP_ADVERTISING(configs, FEC_RS);

    if (autoneg_lp_ability & FEC_CAPABILITY_BASER)
        LINK_CONFIGS_SET_LP_ADVERTISING(configs, FEC_BASER);

    LINK_CONFIGS_SET_LP_ADVERTISING(configs, FEC_NONE);

    /* Show which mode exanic advertises */
    if (autoneg_ability & FEC_CAPABILITY_BASER)
        LINK_CONFIGS_SET_ADVERTISING(configs, FEC_BASER);
    else if (autoneg_ability & FEC_CAPABILITY_RS_FEC)
        LINK_CONFIGS_SET_ADVERTISING(configs, FEC_RS);
    else
        LINK_CONFIGS_SET_ADVERTISING(configs, FEC_NONE);
#endif
}

/* generic link setting getter */
static int
__exanic_phyops_get_configs(struct exanic *exanic, int port,
                            exanic_phyops_configs_t *configs)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    uint32_t port_flags, speed_reg;
    const exa_caps_ethtool_modes_mapping_t** mptr = caps2ethtool_modes;

    LINK_CONFIGS_ZERO(configs);
    LINK_CONFIGS_SET_SUPPORTED(configs, FIBRE);

    while(*mptr)
    {
        /* For every capability bit set, return supported link modes */
        if (exanic->caps & (*mptr)->capability)
            add_ethtool_modes(*mptr, configs);
        mptr++;
    }

    port_flags = readl(&regs[REG_PORT_INDEX(port, REG_PORT_FLAGS)]);
    if (IS_25G_SUPPORTED(exanic->caps) && (port_flags & EXANIC_PORT_FLAG_AUTONEG_ENABLE))
        get_25G_autoneg_info(exanic, port, configs);

    speed_reg = readl(&regs[REG_PORT_INDEX(port, REG_PORT_SPEED)]);
    LINK_CONFIGS_SET_SPEED(configs, speed_reg);
    LINK_CONFIGS_SET(configs, duplex, DUPLEX_FULL);

    LINK_CONFIGS_SET(configs, port, PORT_FIBRE);

    if (IS_25G_SUPPORTED(exanic->caps))
        LINK_CONFIGS_SET_SUPPORTED(configs, Autoneg);

    if (port_flags & EXANIC_PORT_FLAG_AUTONEG_ENABLE)
        LINK_CONFIGS_SET_ADVERTISING(configs, Autoneg);

    if (port_flags & EXANIC_PORT_FLAG_AUTONEG_ENABLE)
        LINK_CONFIGS_SET(configs, autoneg, AUTONEG_ENABLE);
    else
        LINK_CONFIGS_SET(configs, autoneg, AUTONEG_DISABLE);

#ifdef ETHTOOL_SFECPARAM
    /* Show which FEC modes are potentially supported by exanic */
    if (exanic->caps & EXANIC_CAP_25G)
        LINK_CONFIGS_SET_SUPPORTED(configs, FEC_RS);
    if (exanic->caps & (EXANIC_CAP_25G|EXANIC_CAP_25G_S))
        LINK_CONFIGS_SET_SUPPORTED(configs, FEC_BASER);
    LINK_CONFIGS_SET_SUPPORTED(configs, FEC_NONE);
#endif

    return 0;
}

#ifdef ETHTOOL_SFECPARAM
static int
__exanic_phyops_set_fecparam(struct exanic *exanic, int port, const exanic_phyops_fecparams_t* fp)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    uint32_t port_flags;

    if (!IS_25G_SUPPORTED(exanic->caps))
        return -EOPNOTSUPP;

    port_flags = readl(&regs[REG_PORT_INDEX(port, REG_PORT_FLAGS)]);
    if (port_flags & EXANIC_PORT_FLAG_AUTONEG_ENABLE)
    {
        uint32_t autoneg_caps = readl(&regs[REG_EXTENDED_PORT_INDEX(port, REG_EXTENDED_PORT_AN_ABILITY)]);
        autoneg_caps &= ~(EXANIC_AUTONEG_FEC_CAPABILITY_MASK);

        if (fp->fec & ETHTOOL_FEC_RS)
            autoneg_caps |= FEC_CAPABILITY_RS_FEC;
        else if (fp->fec & ETHTOOL_FEC_BASER)
            autoneg_caps |= FEC_CAPABILITY_BASER;

        writel(autoneg_caps, &regs[REG_EXTENDED_PORT_INDEX(port, REG_EXTENDED_PORT_AN_ABILITY)]);

        /* restart autoneg */
        writel(EXANIC_PORT_AUTONEG_RESTART, &regs[REG_EXTENDED_PORT_INDEX(port, REG_EXTENDED_PORT_AN_CONTROL)]);
        writel(0, &regs[REG_EXTENDED_PORT_INDEX(port, REG_EXTENDED_PORT_AN_CONTROL)]);
    }
    else
    {
        port_flags &= ~(EXANIC_PORT_FLAG_FORCE_FEC_MASK);
        if (fp->fec & ETHTOOL_FEC_RS)
            port_flags |= EXANIC_PORT_FLAG_FORCE_RS_FEC;
        else if (fp->fec & ETHTOOL_FEC_BASER)
            port_flags |= EXANIC_PORT_FLAG_FORCE_BASER_FEC;

        writel(port_flags, &regs[REG_PORT_INDEX(port, REG_PORT_FLAGS)]);
    }
    return 0;
}

/* generic get FEC settings */
static int
__exanic_phyops_get_fecparam(struct exanic *exanic, int port, exanic_phyops_fecparams_t* fp)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    uint32_t speed;

    if (!IS_25G_SUPPORTED(exanic->caps))
    {
        /* FEC is only supported on 25G firmware */
        fp->fec = ETHTOOL_FEC_NONE;
        fp->active_fec = ETHTOOL_FEC_NONE;
        return 0;
    }

    /* return which one we support depending on the capabilities (25G or 25G_S) */
    fp->fec = EXANIC_SUPPORTED_ETHTOOL_FECS(exanic->caps);

    /* we also support no FEC */
    fp->fec |= ETHTOOL_FEC_OFF;

    /* set active initially to off */
    fp->active_fec = ETHTOOL_FEC_OFF;

    speed = readl(&regs[REG_PORT_INDEX(port, REG_PORT_SPEED)]);
    if (speed == SPEED_25000)
    {
        uint32_t port_flags = readl(&regs[REG_PORT_INDEX(port, REG_PORT_FLAGS)]);
        uint32_t port_status = readl(&regs[REG_PORT_INDEX(port, REG_PORT_STATUS)]);
        bool link_is_up = port_status & EXANIC_PORT_STATUS_LINK;
        bool autoneg_is_on = port_flags & EXANIC_PORT_FLAG_AUTONEG_ENABLE;

        if (autoneg_is_on && link_is_up)
        {
            /* When autoneg is on and the link is up, get fec_active value from resolved bits */
            uint32_t autoneg_status = readl(&regs[REG_EXTENDED_PORT_INDEX(port, REG_EXTENDED_PORT_AN_STATUS)]);
            if (autoneg_status & EXANIC_PORT_AUTONEG_FLAGS_RESOLVED_BASER_FEC)
                fp->active_fec = ETHTOOL_FEC_BASER;
            else if (autoneg_status & EXANIC_PORT_AUTONEG_FLAGS_RESOLVED_RS_FEC)
                fp->active_fec = ETHTOOL_FEC_RS;
            else
                fp->active_fec = ETHTOOL_FEC_OFF;
        }
        else if (!autoneg_is_on && link_is_up)
        {
            /* if auto-neg is off and link is up, we will get active from the force FEC bits */
            if (port_flags & EXANIC_PORT_FLAG_FORCE_RS_FEC)
                fp->active_fec = ETHTOOL_FEC_RS;
            else if (port_flags & EXANIC_PORT_FLAG_FORCE_BASER_FEC)
                fp->active_fec = ETHTOOL_FEC_BASER;
            else
                fp->active_fec = ETHTOOL_FEC_OFF;
        }
        else
        {
            /* if link is down, just set to off */
            fp->active_fec = ETHTOOL_FEC_OFF;
        }
    }
    return 0;
}
#endif /* ETHTOOL_SFECPARAM */

static int __exanic_phyops_restart_autoneg(struct exanic *exanic, int port)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    uint32_t reg;

    if (!IS_25G_SUPPORTED(exanic->caps))
        return -EOPNOTSUPP;

    reg = readl(&regs[REG_PORT_INDEX(port, REG_PORT_FLAGS)]);

    /* if autoneg is enabled, restart it */
    if (reg & EXANIC_PORT_FLAG_AUTONEG_ENABLE)
    {
        writel(EXANIC_PORT_AUTONEG_RESTART, &regs[REG_EXTENDED_PORT_INDEX(port, REG_EXTENDED_PORT_AN_CONTROL)]);
        writel(0, &regs[REG_EXTENDED_PORT_INDEX(port, REG_EXTENDED_PORT_AN_CONTROL)]);
    }
    return 0;
}

/* generic link status getter */
static uint32_t
__exanic_phyops_get_link_status(struct exanic *exanic, int port)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    uint32_t reg = readl(&regs[REG_PORT_INDEX(port, REG_PORT_STATUS)]);
    return !!(reg & EXANIC_PORT_STATUS_LINK);
}

#ifdef ETHTOOL_GMODULEINFO
/* get_module_eeprom implementation for SFP */
static int
__exanic_phyops_get_module_eeprom_sfp(struct exanic *exanic, int port,
                                      struct ethtool_eeprom *eep, u8 *data)
{
    size_t offset = eep->offset, len = eep->len;
    size_t bytes_read = 0;
    int err;
    u8 *ptr = data;

    if (offset + len > ETH_MODULE_SFF_8472_LEN)
        return -EINVAL;

    if (len == 0)
        return -EINVAL;

    if (offset >= ETH_MODULE_SFF_8079_LEN)
        goto read_a2h;

    /* read page A0h */
    bytes_read = min(len, ETH_MODULE_SFF_8079_LEN - offset);
    err = exanic_i2c_xcvr_read(exanic, port, XCVR_EEPROM_ADDR,
                               (uint8_t)offset, ptr, bytes_read);
    if (err)
        return err;

    if (len == bytes_read)
        return 0;

    len -= bytes_read;
    ptr += bytes_read;
    offset += bytes_read;

read_a2h:
    /* read page A2h */
    return exanic_i2c_xcvr_read(exanic, port, SFP_DIAG_ADDR,
                                offset - ETH_MODULE_SFF_8079_LEN,
                                ptr, len);
}
#endif /* ETHTOOL_GMODULEINFO */

/* power on function for ExaNIC X2 and X4 */
static int __exanic_phyops_poweron_x2_x4(struct exanic *exanic, int port)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    int ret = 0;

    uint8_t reg_val = 0;
    char init_regs[12] = {
        0xFF, 0xFB, 0xFF, 0xFB, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x15, 0xE5, 0x3F
    };

    uint32_t reg = readl(&regs[REG_HW_INDEX(REG_HW_POWERDOWN)]);

    /* turn on the external PHY */
    reg &= ~(1 << port);
    writel(reg, &regs[REG_HW_INDEX(REG_HW_POWERDOWN)]);

    /* turn on SFP TX */
    reg |= (1 << (EXANIC_SFP_TXDIS0 + port));
    writel(reg, &regs[REG_HW_INDEX(REG_HW_POWERDOWN)]);

    /* Initialise the PHY */
    reg_val = 0;
    ret = exanic_i2c_ext_phy_write(exanic, port,
                                   EXANIC_EXT_PHY_RESET_OFFSET,
                                   &reg_val, 1);
    if (ret)
        return ret;

    ret = exanic_i2c_ext_phy_write(exanic, port, 0x00, init_regs, 12);
    if (ret)
        return ret;

    return exanic_phyops_x2_x4_optimise(exanic, port);
}

/* power off function for ExaNIC X2 and X4 */
static void __exanic_phyops_poweroff_x2_x4(struct exanic *exanic, int port)
{
    volatile uint32_t *regs = exanic_registers(exanic);

    uint32_t reg = readl(&regs[REG_HW_INDEX(REG_HW_POWERDOWN)]);
    /* turn off SFP TX */
    reg &= ~(1 << (EXANIC_SFP_TXDIS0 + port));
    /* turn off the external PHY */
    reg |= (1 << port);
    writel(reg, &regs[REG_HW_INDEX(REG_HW_POWERDOWN)]);
}

/* initialisation function for marvell PHY */
static int __exanic_phyops_init_marvell(struct exanic *exanic, int port)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    uint32_t speed_reg = readl(&regs[REG_PORT_INDEX(port, REG_PORT_SPEED)]);

    if (speed_reg == SPEED_100)
        return exanic_phyops_marvell_set_speed(exanic, port, 0, SPEED_100);

    return 0;
}

/* link setting setter for marvell PHY */
static int
__exanic_phyops_set_configs_marvell(struct exanic *exanic, int port,
                                    const exanic_phyops_configs_t *configs)
{
    /* marvell 1000BASE-T phy, only 100M and 1G supported */
    return __exanic_phyops_set_configs_ex(exanic, port, configs,
                                          EXANIC_CAP_100M | EXANIC_CAP_1G,
                                          exanic_phyops_marvell_set_speed);
}

/* enable/disable tx */
static int
exanic_phyops_qsfp_set_tx_disable(struct exanic *exanic, int port, bool disable)
{
    int port_width = exanic_phyops_if_width(exanic);
    int lane_start = exanic_phyops_if_lane_index(exanic, port, port_width);
    uint8_t tx_disable_byte = 0;
    int i, j;

    int err = exanic_i2c_xcvr_read(exanic, port, XCVR_EEPROM_ADDR,
                                   QSFP_TX_DISABLE_BYTE, &tx_disable_byte, 1);
    if (err)
    {
        dev_err(&exanic->pci_dev->dev,
                "%s:%d Failed to read TX disable byte: %d\n",
                exanic->name, port, err);
        return err;
    }

    for (j = 0, i = lane_start; j < port_width; i++, j++)
    {
        if (disable)
            tx_disable_byte |= (1 << i);
        else
            tx_disable_byte &= ~(1 << i);
    }

    err = exanic_i2c_xcvr_write(exanic, port, XCVR_EEPROM_ADDR,
                                QSFP_TX_DISABLE_BYTE, &tx_disable_byte, 1);
    if (err)
    {
        dev_err(&exanic->pci_dev->dev,
                "%s:%d Failed to write TX disable byte: %d\n",
                exanic->name, port, err);
    }
    return err;
}

/* power off function for QSFP */
static void __exanic_phyops_poweroff_qsfp(struct exanic *exanic, int port)
{
    exanic_phyops_qsfp_set_tx_disable(exanic, port, true);
    __exanic_phyops_poweroff(exanic, port);
}

/* initialisation function for QSFP */
static int __exanic_phyops_init_qsfp(struct exanic *exanic, int port)
{
    exanic_phyops_qsfp_set_tx_disable(exanic, port, false);
    return 0;
}

#ifdef ETHTOOL_GMODULEINFO
/* get_module_eeprom implementation for QSFP */
static int
__exanic_phyops_get_module_eeprom_qsfp(struct exanic *exanic, int port,
                                       struct ethtool_eeprom *eep, u8 *data)
{
    return exanic_phyops_get_module_eeprom_paged(exanic, port, eep, data, false);
}
#endif /* ETHTOOL_GMODULEINFO */

/* power off function for QSFP-DD */
static void __exanic_phyops_poweroff_cmis(struct exanic *exanic, int port)
{
    exanic_phyops_cmis_powerdown(exanic, port);
    __exanic_phyops_poweroff(exanic, port);
}

/* initialisation function for QSFP-DD */
static int __exanic_phyops_init_cmis(struct exanic *exanic, int port)
{
    exanic_phyops_cmis_init(exanic, port);
    return 0;
}

/* link setting setter for QSFP-DD */
static int
__exanic_phyops_set_configs_cmis(struct exanic *exanic, int port,
                                 const exanic_phyops_configs_t *configs)
{
    return __exanic_phyops_set_configs_ex(exanic, port, configs,
                                          ~0,
                                          exanic_phyops_cmis_set_speed);
}

#ifdef ETHTOOL_GMODULEINFO
/* get_module_eeprom implementation for QSFP-DD */
static int
__exanic_phyops_get_module_eeprom_cmis(struct exanic *exanic, int port,
                                       struct ethtool_eeprom *eep, u8 *data)
{
    return exanic_phyops_get_module_eeprom_paged(exanic, port, eep, data, true);
}
#endif /* ETHTOOL_GMODULEINFO */

#ifdef ETHTOOL_GMODULEINFO
/* common get_module_info implementation */
static int
__exanic_phyops_get_module_info(struct exanic *exanic, int port,
                                struct ethtool_modinfo *minfo)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    uint32_t reg;
    uint8_t sff8024_id;
    bool xcvr_connected;
    int err;

    /* check that a pluggable transceiver is plugged in */
    reg = readl(&regs[REG_PORT_INDEX(port, REG_PORT_STATUS)]);
    if ((reg & EXANIC_PORT_STATUS_SFP) == 0)
        return -EOPNOTSUPP;

    err = exanic_i2c_xcvr_sff8024_id(exanic, port, &sff8024_id);
    if (err)
        return err;

    /* check that the port is connected to the pluggable transceiver */
    xcvr_connected = exanic_xcvr_connected(exanic, port, sff8024_id);
    if (!xcvr_connected)
        return -EOPNOTSUPP;

    /* SFP port or SFP module in adapter */
    if (SFF_8024_ID_SFP(sff8024_id))
    {
        bool has_diag = false;
        err = exanic_i2c_sfp_has_diag_page(exanic, port, &has_diag);
        if (err)
            return err;

        minfo->type = has_diag ? ETH_MODULE_SFF_8472 :
                                 ETH_MODULE_SFF_8079;
        minfo->eeprom_len = has_diag ? ETH_MODULE_SFF_8472_LEN :
                                       ETH_MODULE_SFF_8079_LEN;
        exanic->port[port].phy_ops.get_module_eeprom =
            __exanic_phyops_get_module_eeprom_sfp;
        return 0;
    }

    /* QSFP port or QSFP module in QSFP-DD port */
    if (SFF_8024_ID_QSFP(sff8024_id))
    {
        bool flat = true;
        err = exanic_i2c_qsfp_flat_mem(exanic, port, &flat);
        if (err)
            return err;

        minfo->type = ETH_MODULE_SFF_8436;
        minfo->eeprom_len = flat ? ETH_MODULE_SFF_8436_LEN :
                                   ETH_MODULE_SFF_8436_MAX_LEN;
        exanic->port[port].phy_ops.get_module_eeprom =
            __exanic_phyops_get_module_eeprom_qsfp;
        return 0;
    }

    if (SFF_8024_ID_QSFPDD(sff8024_id))
    {
        bool flat = true;
        err = exanic_i2c_cmis_flat_mem(exanic, port, &flat);
        if (err)
            return err;

        minfo->type = ETH_MODULE_CMIS_QSFPDD;
        minfo->eeprom_len = flat ? ETH_MODULE_CMIS_QSFPDD_LEN :
                                   ETH_MODULE_CMIS_QSFPDD_MAX_LEN;
        exanic->port[port].phy_ops.get_module_eeprom =
            __exanic_phyops_get_module_eeprom_cmis;
        return 0;
    }

    return -EOPNOTSUPP;
}
#endif /* ETHTOOL_GMODULEINFO */

void exanic_phyops_init_fptrs(struct exanic *exanic, int port_no, bool power)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    struct exanic_port *port = &exanic->port[port_no];
    uint8_t sff8024_id;
    bool xcvr_present = false, xcvr_connected = false,
         sfp_marvell = false;
    bool x2_x4 = (exanic->hw_id == EXANIC_HW_X2 || exanic->hw_id == EXANIC_HW_X4);
    int err;

    /* port has not yet been powered up, cannot query PHY type because
     * there is no power. fill in the poweron function and initialise PHY
     * operations later */
    if (!power)
    {
        port->phy_ops.poweron = x2_x4 ? __exanic_phyops_poweron_x2_x4 :
                                        __exanic_phyops_poweron;
        return;
    }

    /* check that a pluggable transceiver is plugged in */
    xcvr_present = (readl(&regs[REG_PORT_INDEX(port_no, REG_PORT_STATUS)]) &
                    EXANIC_PORT_STATUS_SFP) != 0;
    if (!xcvr_present)
        goto generic_phyops;

    err = exanic_i2c_xcvr_sff8024_id(exanic, port_no, &sff8024_id);
    if (err)
        goto generic_phyops;

    /* check that the port is connected to the pluggable transceiver */
    xcvr_connected = exanic_xcvr_connected(exanic, port_no, sff8024_id);
    if (!xcvr_connected)
        goto generic_phyops;

    sfp_marvell = exanic_phyops_is_sfp_marvell(exanic, port_no);
    if (SFF_8024_ID_SFP(sff8024_id))
        goto sfp_phyops;

    if (SFF_8024_ID_QSFPDD(sff8024_id))
        goto cmis_phyops;

    if (SFF_8024_ID_QSFP(sff8024_id))
        goto qsfp_phyops;

/* get_module_info is always filled in so up-to-date module eeprom
 * info is returned to userspace */
generic_phyops:
    port->phy_ops =
    (struct exanic_phy_ops)
    {
        /* X2 and X4 require bringing external PHY in and out of reset */
        .poweron = x2_x4 ? __exanic_phyops_poweron_x2_x4 : __exanic_phyops_poweron,
        .poweroff = x2_x4 ? __exanic_phyops_poweroff_x2_x4 : __exanic_phyops_poweroff,
        .init = NULL,

        .get_configs = __exanic_phyops_get_configs,
        .set_configs = __exanic_phyops_set_configs,
#ifdef ETHTOOL_SFECPARAM
        .get_fecparam = __exanic_phyops_get_fecparam,
        .set_fecparam = __exanic_phyops_set_fecparam,
#endif /* ETHTOOL_SFECPARAM */
        .get_link_status = __exanic_phyops_get_link_status,
#ifdef ETHTOOL_GMODULEINFO
        .get_module_info = __exanic_phyops_get_module_info,
        .get_module_eeprom = NULL,
#endif /* ETHTOOL_GMODULEINFO */
        .restart_autoneg = __exanic_phyops_restart_autoneg
    };

    dev_info(&exanic->pci_dev->dev,
             "%s:%d: generic PHY operations initialised\n",
             exanic->name, port_no);
    return;

sfp_phyops:
    port->phy_ops =
    (struct exanic_phy_ops)
    {
        /* X2 and X4 require bringing external PHY in and out of reset */
        .poweron = x2_x4 ? __exanic_phyops_poweron_x2_x4 : __exanic_phyops_poweron,
        .poweroff = x2_x4 ? __exanic_phyops_poweroff_x2_x4 : __exanic_phyops_poweroff,
        .init = sfp_marvell ? __exanic_phyops_init_marvell : NULL,

        .get_configs = __exanic_phyops_get_configs,
        .set_configs = sfp_marvell ? __exanic_phyops_set_configs_marvell:
                                     __exanic_phyops_set_configs,
#ifdef ETHTOOL_SFECPARAM
        .get_fecparam = __exanic_phyops_get_fecparam,
        .set_fecparam = __exanic_phyops_set_fecparam,
#endif /* ETHTOOL_SFECPARAM */
        .get_link_status = __exanic_phyops_get_link_status,
#ifdef ETHTOOL_GMODULEINFO
        .get_module_info = __exanic_phyops_get_module_info,
        .get_module_eeprom = NULL,
#endif /* ETHTOOL_GMODULEINFO */
        .restart_autoneg = __exanic_phyops_restart_autoneg
    };

    dev_info(&exanic->pci_dev->dev,
             "%s:%d: SFP PHY operations initialised\n",
             exanic->name, port_no);
    return;

qsfp_phyops:
    port->phy_ops =
    (struct exanic_phy_ops)
    {
        .poweron = __exanic_phyops_poweron,
        .poweroff = __exanic_phyops_poweroff_qsfp,
        .init = __exanic_phyops_init_qsfp,

        .get_configs = __exanic_phyops_get_configs,
        .set_configs = __exanic_phyops_set_configs,
#ifdef ETHTOOL_SFECPARAM
        .get_fecparam = __exanic_phyops_get_fecparam,
        .set_fecparam = __exanic_phyops_set_fecparam,
#endif /* ETHTOOL_SFECPARAM */
        .get_link_status = __exanic_phyops_get_link_status,
#ifdef ETHTOOL_GMODULEINFO
        .get_module_info = __exanic_phyops_get_module_info,
        .get_module_eeprom = NULL,
#endif /* ETHTOOL_GMODULEINFO */
        .restart_autoneg = __exanic_phyops_restart_autoneg
    };

    dev_info(&exanic->pci_dev->dev,
             "%s:%d: QSFP PHY operations initialised\n",
             exanic->name, port_no);
    return;

cmis_phyops:
    port->phy_ops =
    (struct exanic_phy_ops)
    {
        .poweron = __exanic_phyops_poweron,
        .poweroff = __exanic_phyops_poweroff_cmis,
        .init = __exanic_phyops_init_cmis,

        .get_configs = __exanic_phyops_get_configs,
        .set_configs = __exanic_phyops_set_configs_cmis,
#ifdef ETHTOOL_SFECPARAM
        .get_fecparam = __exanic_phyops_get_fecparam,
        .set_fecparam = __exanic_phyops_set_fecparam,
#endif /* ETHTOOL_SFECPARAM */
        .get_link_status = __exanic_phyops_get_link_status,
#ifdef ETHTOOL_GMODULEINFO
        .get_module_info = __exanic_phyops_get_module_info,
        .get_module_eeprom = NULL,
#endif /* ETHTOOL_GMODULEINFO */
        .restart_autoneg = __exanic_phyops_restart_autoneg
    };

    dev_info(&exanic->pci_dev->dev,
             "%s:%d: QSFP-DD PHY operations initialised\n",
             exanic->name, port_no);
    return;
}

/* return the number of lanes that make up an interface */
int exanic_phyops_if_width(struct exanic *exanic)
{
    switch (exanic->hwinfo.port_ff)
    {
        /* only single-lane interfaces are possible */
        case EXANIC_PORT_SFP:
            return 1;

        /* 40G or 4*10G/1G */
        case EXANIC_PORT_QSFP:
            if (exanic->num_ports == exanic->hwinfo.nports)
                return 4;
            return 1;

        /* 2*40G or 8*10G/1G */
        case EXANIC_PORT_QSFPDD:
            if (exanic->num_ports == exanic->hwinfo.nports * 2)
                return 4;

            if (exanic->num_ports == exanic->hwinfo.nports * 8)
                return 1;

        default: break;
    }
    return -1;
}

/* return the starting lane number of interface */
int exanic_phyops_if_lane_index(struct exanic *exanic, int port, int width)
{
    int phys_width = 0;
    switch (exanic->hwinfo.port_ff)
    {
        case EXANIC_PORT_SFP:
            phys_width = 1;
            break;

        case EXANIC_PORT_QSFP:
            phys_width = 4;
            break;

        case EXANIC_PORT_QSFPDD:
            phys_width = 8;
            break;

        default: break;
    }

    if (!phys_width)
        return -1;

    return (port * width) % phys_width;
}

/* return the number of lanes given transceiver type */
int exanic_phyops_xcvr_width(int sff8024_id)
{
    if (SFF_8024_ID_SFP(sff8024_id))
        return 1;

    if (SFF_8024_ID_QSFP(sff8024_id))
        return 4;

    if (SFF_8024_ID_QSFPDD(sff8024_id))
        return 8;

    return -1;
}

/* wrappers over struct exanic_phy_ops */

int exanic_phyops_poweron(struct exanic *exanic, int port)
{
    if (exanic->port[port].phy_ops.poweron)
        return exanic->port[port].phy_ops.poweron(exanic, port);
    return -EOPNOTSUPP;
}

void exanic_phyops_poweroff(struct exanic *exanic, int port)
{
    if (exanic->port[port].phy_ops.poweroff)
        exanic->port[port].phy_ops.poweroff(exanic, port);
}

int exanic_phyops_init(struct exanic *exanic, int port)
{
    if (exanic->port[port].phy_ops.init)
        return exanic->port[port].phy_ops.init(exanic, port);
    return 0;
}

int exanic_phyops_get_configs(struct exanic *exanic, int port,
                              exanic_phyops_configs_t *c)
{
    if (exanic->port[port].phy_ops.get_configs)
        return exanic->port[port].phy_ops.get_configs(exanic, port, c);
    return -EOPNOTSUPP;
}

int exanic_phyops_set_configs(struct exanic *exanic, int port,
                              const exanic_phyops_configs_t *s)
{
    if (exanic->port[port].phy_ops.set_configs)
        return exanic->port[port].phy_ops.set_configs(exanic, port, s);
    return -EOPNOTSUPP;
}

#ifdef ETHTOOL_SFECPARAM
int exanic_phyops_get_fecparam(struct exanic *exanic, int port,
                              struct ethtool_fecparam *fp)
{
    if (exanic->port[port].phy_ops.get_fecparam)
        return exanic->port[port].phy_ops.get_fecparam(exanic, port, fp);
    return -EOPNOTSUPP;
}

int exanic_phyops_set_fecparam(struct exanic *exanic, int port,
                               struct ethtool_fecparam *fp)
{
    if (exanic->port[port].phy_ops.set_fecparam)
        return exanic->port[port].phy_ops.set_fecparam(exanic, port, fp);
    return -EOPNOTSUPP;
}
#endif /* ETHTOOL_SFECPARAM */

int exanic_phyops_restart_autoneg(struct exanic *exanic, int port)
{
    if (exanic->port[port].phy_ops.restart_autoneg)
        return exanic->port[port].phy_ops.restart_autoneg(exanic, port);
    return -EOPNOTSUPP;
}

int exanic_phyops_get_link_status(struct exanic *exanic, int port, uint32_t *link)
{
    if (!exanic->port[port].phy_ops.get_link_status)
        return -EOPNOTSUPP;
    *link = exanic->port[port].phy_ops.get_link_status(exanic, port);
    return 0;
}

#ifdef ETHTOOL_GMODULEINFO
int exanic_phyops_get_module_info(struct exanic *exanic, int port,
                                  struct ethtool_modinfo *emi)
{
    if (exanic->port[port].phy_ops.get_module_info)
        return exanic->port[port].phy_ops.get_module_info(exanic, port, emi);
    return -EOPNOTSUPP;
}

int exanic_phyops_get_module_eeprom(struct exanic *exanic, int port,
                                    struct ethtool_eeprom *eee, uint8_t *data)
{
    if (exanic->port[port].phy_ops.get_module_eeprom)
        return exanic->port[port].phy_ops.get_module_eeprom(exanic, port, eee, data);
    return -EOPNOTSUPP;
}
#endif /* ETHTOOL_GMODULEINFO */
