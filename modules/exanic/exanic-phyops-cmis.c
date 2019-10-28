/**
 * ExaNIC PHY level operations for CMIS QSFP-DD rev 3.0 compliant modules
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

/* maximum number of applications advertised */
#define EXANIC_CMIS_APP_MAX                 8

/* host and media lane count from the lane count byte */
#define HOST_LANE_COUNT(lane_count)         ((lane_count) >> 4)
#define MEDIA_LANE_COUNT(lane_count)        ((lane_count) & 0xf)

/* CMIS application advertisement bytes that live in the lower page */
struct exanic_cmis_app_adv_lower
{
    /* host and line side standards */
    uint8_t host_interface_code;
    uint8_t media_interface_code;
    /* number of host and media lanes */
    uint8_t lane_counts;
    /* possible starting lanes on host sides */
    uint8_t host_lane_assignment;
} __attribute__((packed));

/* Application advertisement is cached until the port is
 * powered down and back up */
struct exanic_phyops_cmis_data
{
    int num_apps;
    struct exanic_cmis_app_adv_lower apps[EXANIC_CMIS_APP_MAX];
    /* media lane assignment byte lives in the upper page */
    uint8_t media_lane_assignment[EXANIC_CMIS_APP_MAX];
};

/* CMIS datapath */
struct exanic_cmis_data_path
{
    int apsel;
    int host_lane_count, host_lane;
    int media_lane_count, media_lane;
    bool disable_cdrs;
};

/* list of CMIS host interface types supported by ExaNIC products */
static struct
{
    uint8_t code;
    const char *name;
    uint32_t speed;
} exanic_cmis_supported_host[] = {
    {0x01, "1000BASE-CX", SPEED_1000 },
    {0x04, "SFI"        , SPEED_10000},
    {0x07, "XLPPI"      , SPEED_40000},
    {0x17, "40GBASE-CR4", SPEED_40000},
    /* add more as needed */
    {0xff}
};

static bool
__cmis_app_supported(uint8_t code, const char **name, uint32_t *speed)
{
    int i;
    for (i = 0; exanic_cmis_supported_host[i].code != 0xff; i++)
    {
        if (code == exanic_cmis_supported_host[i].code)
        {
            if (speed)
                *speed = exanic_cmis_supported_host[i].speed;
            if (name)
                *name = exanic_cmis_supported_host[i].name;
            return true;
        }
    }
    return false;
}

/* 0xff for host interface code indicates end of application array
 * however some modules do not set it correctly. for those modules,
 * end of array is indicated by all advertisement fields being 0 */
static bool __cmis_app_valid(struct exanic_cmis_app_adv_lower *app)
{
    if (app->host_interface_code == 0xff)
        return false;

    return (app->host_interface_code || app->media_interface_code ||
            app->lane_counts || app->host_lane_assignment);
}

/* put together a datapath configuration given data rate,
 * starting lane and lane count */
static void
__cmis_make_datapath(struct exanic *exanic, int port,
                     int lane_start, int width, uint32_t speed,
                     struct exanic_cmis_data_path *dpath)
{
    int i;
    struct exanic_phyops_cmis_data *data =
        exanic->port[port].phy_ops.data;
    /* compute lane group number for media lane calculation */
    uint8_t lane_group = lane_start / width;

    dpath->host_lane = lane_start;
    dpath->host_lane_count = width;

    for (i = 0; i < data->num_apps; i++)
    {
        struct exanic_cmis_app_adv_lower *app = &data->apps[i];
        uint32_t app_speed = 0;

        if (!__cmis_app_supported(app->host_interface_code, NULL, &app_speed))
            continue;

        if (speed != app_speed)
            continue;

        if (width != HOST_LANE_COUNT(app->lane_counts))
            continue;

        if (!(app->host_lane_assignment & (1 << lane_start)))
            continue;

        dpath->apsel = i + 1;
        dpath->media_lane_count = MEDIA_LANE_COUNT(app->lane_counts);
        dpath->media_lane = lane_group * dpath->media_lane_count;
        dpath->disable_cdrs = false;

        dev_info(&exanic->pci_dev->dev,
                 "%s:%d: selecting application %d\n",
                 exanic->name, port, i + 1);
        return;
    }

    /* no application found, select default application */
    dpath->apsel = 1;
    dpath->media_lane = dpath->host_lane;
    dpath->media_lane_count = dpath->host_lane_count;

    /* if the default application is for an unsupported data rate,
     * forcibly disable module CDRs.
     * Otherwise, the module CDRs may corrupt the data, e.g. when running
     * 10G over a module that is designed for 25G */
    dpath->disable_cdrs =
        !__cmis_app_supported(data->apps[0].host_interface_code, NULL, NULL);

    dev_info(&exanic->pci_dev->dev,
             "%s:%d: selecting default CMIS application%s\n",
             exanic->name, port,
             dpath->disable_cdrs ? " with CDR bypass" : "");
}

/* check for cached application advertisement
 * allocate new cache if absent */
static int
exanic_phyops_cmis_app_adv_read(struct exanic *exanic, int port)
{
    struct exanic_phyops_cmis_data *new_data;
    int num_apps;
    int ret;

    if (likely(exanic->port[port].phy_ops.data))
        return 0;

    new_data = devm_kzalloc(&exanic->pci_dev->dev,
                            sizeof *new_data, GFP_KERNEL);
    if (!new_data)
        return -ENOMEM;

    /* read all applications */
    ret = exanic_i2c_xcvr_read(exanic, port, XCVR_EEPROM_ADDR,
                               CMIS_APP_ADV_BYTE,
                               (uint8_t *)&new_data->apps,
                               EXANIC_CMIS_APP_MAX *
                               sizeof(struct exanic_cmis_app_adv_lower));
    if (ret)
        goto err_apps_read;

    ret = exanic_i2c_cmis_page_sel(exanic, port, 0, 1);
    if (ret)
        goto err_apps_read;

    ret = exanic_i2c_xcvr_read(exanic, port, XCVR_EEPROM_ADDR,
                               CMIS_MEDIA_LANE_BYTE,
                               &new_data->media_lane_assignment[0],
                               EXANIC_CMIS_APP_MAX);
    if (ret)
        goto page0_sel;

    /* look for end-marker in application advertisement bytes */
    for (num_apps = 0; num_apps < EXANIC_CMIS_APP_MAX; num_apps++)
        if (!__cmis_app_valid(&new_data->apps[num_apps]))
            break;

    /* ??? nothing is advertised ??? */
    if (num_apps == 0)
    {
        dev_err(&exanic->pci_dev->dev,
                "%s:%d: CMIS module advertises no valid applications\n",
                exanic->name, port);

        ret = -EOPNOTSUPP;
        goto page0_sel;
    }

    new_data->num_apps = num_apps;
    exanic->port[port].phy_ops.data = new_data;
    exanic_i2c_cmis_page_sel(exanic, port, 0, 0);

    return 0;

page0_sel:
    exanic_i2c_cmis_page_sel(exanic, port, 0, 0);
err_apps_read:
    devm_kfree(&exanic->pci_dev->dev, new_data);
    return ret;
}

static void
exanic_phyops_cmis_app_adv_invalidate(struct exanic *exanic, int port)
{
    if (unlikely(!exanic->port[port].phy_ops.data))
        return;

    devm_kfree(&exanic->pci_dev->dev,
               exanic->port[port].phy_ops.data);
    exanic->port[port].phy_ops.data = NULL;
}

static int
exanic_phyops_cmis_set_datapath_pwr(struct exanic *exanic, int port,
                                    uint8_t host_lane_mask,
                                    bool pwr)
{
    bool flat_mem = false;
    uint8_t curr_lane_mask = 0;

    int ret = exanic_i2c_cmis_flat_mem(exanic, port, &flat_mem);
    if (ret)
        return ret;

    if (flat_mem)
        return 0;

    ret = exanic_i2c_cmis_page_sel(exanic, port, 0, 0x10);
    if (ret)
        return ret;

    ret = exanic_i2c_xcvr_read(exanic, port, XCVR_EEPROM_ADDR,
                               CMIS_DPATH_PWR_CTRL_BYTE,
                               &curr_lane_mask, 1);
    if (ret)
        goto page0_sel;

    if (pwr)
        curr_lane_mask |= host_lane_mask;
    else
        curr_lane_mask &= ~host_lane_mask;

    ret = exanic_i2c_xcvr_write(exanic, port, XCVR_EEPROM_ADDR,
                                CMIS_DPATH_PWR_CTRL_BYTE,
                                &curr_lane_mask, 1);
page0_sel:
    exanic_i2c_cmis_page_sel(exanic, port, 0, 0);
    return ret;
}

static int
exanic_phyops_cmis_set_tx_enable(struct exanic *exanic, int port,
                                 uint8_t media_lane_mask,
                                 bool enable)
{
    bool flat_mem = false;
    uint8_t curr_lane_mask = 0;

    int ret = exanic_i2c_cmis_flat_mem(exanic, port, &flat_mem);
    if (ret)
        return ret;

    if (flat_mem)
        return 0;

    ret = exanic_i2c_cmis_page_sel(exanic, port, 0, 0x10);
    if (ret)
        return ret;

    ret = exanic_i2c_xcvr_read(exanic, port, XCVR_EEPROM_ADDR,
                               CMIS_TX_DISABLE_BYTE,
                               &curr_lane_mask, 1);
    if (ret)
        goto page0_sel;

    if (enable)
        curr_lane_mask &= ~media_lane_mask;
    else
        curr_lane_mask |= media_lane_mask;

    ret = exanic_i2c_xcvr_write(exanic, port, XCVR_EEPROM_ADDR,
                                CMIS_TX_DISABLE_BYTE,
                                &curr_lane_mask, 1);
page0_sel:
    exanic_i2c_cmis_page_sel(exanic, port, 0, 0);
    return ret;
}

static int
exanic_phyops_cmis_cdr_bypass(struct exanic *exanic, int port,
                              uint8_t host_lane_mask)
{
    uint8_t tx_cdr_ctrl, rx_cdr_ctrl;
    bool disabling_cdrs = false;

    int ret = exanic_i2c_cmis_page_sel(exanic, port, 0, 0x10);
    if (ret)
        return ret;

    ret = exanic_i2c_xcvr_read(exanic, port, XCVR_EEPROM_ADDR,
                               CMIS_CTRL_SET_0_TX_CDR_CTRL_BYTE,
                               &tx_cdr_ctrl, 1);
    if (ret)
        goto page0_sel;

    ret = exanic_i2c_xcvr_read(exanic, port, XCVR_EEPROM_ADDR,
                               CMIS_CTRL_SET_0_RX_CDR_CTRL_BYTE,
                               &rx_cdr_ctrl, 1);
    if (ret)
        goto page0_sel;

    /* turn off TX and RX module CDRs for all specified host lanes */
    if (tx_cdr_ctrl & host_lane_mask)
    {
        tx_cdr_ctrl &= ~host_lane_mask;
        ret = exanic_i2c_xcvr_write(exanic, port, XCVR_EEPROM_ADDR,
                                    CMIS_CTRL_SET_0_TX_CDR_CTRL_BYTE,
                                    &tx_cdr_ctrl, 1);
        if (ret)
            goto page0_sel;

        disabling_cdrs = true;
    }

    if (rx_cdr_ctrl & host_lane_mask)
    {
        rx_cdr_ctrl &= ~host_lane_mask;
        ret = exanic_i2c_xcvr_write(exanic, port, XCVR_EEPROM_ADDR,
                                    CMIS_CTRL_SET_0_RX_CDR_CTRL_BYTE,
                                    &rx_cdr_ctrl, 1);
        if (ret)
            goto page0_sel;

        disabling_cdrs = true;
    }

    if (disabling_cdrs)
        dev_info(&exanic->pci_dev->dev,
                 "%s:%d: Disabling module CDRs\n",
                 exanic->name, port);

page0_sel:
    exanic_i2c_cmis_page_sel(exanic, port, 0, 0);
    return ret;
}

static int
exanic_phyops_cmis_datapath_init(struct exanic *exanic, int port,
                                 struct exanic_cmis_data_path *dpath,
                                 uint8_t host_lane_mask,
                                 uint8_t explicit)
{
    int i, j;

    /* select page 10h */
    int ret = exanic_i2c_cmis_page_sel(exanic, port, 0, 0x10);
    if (ret)
        return ret;

    /* write to staged set 0 */
    for (i = 0, j = dpath->host_lane; i < dpath->host_lane_count; i++, j++)
    {
        uint8_t val = ((dpath->apsel << 4) | (dpath->host_lane << 1) | explicit);
        ret = exanic_i2c_xcvr_write(exanic, port, XCVR_EEPROM_ADDR,
                                    CMIS_CTRL_SET_0_APSEL_BYTE + j,
                                    &val, 1);
        if (ret)
            goto page0_sel;
    }

    /* trigger init */
    ret = exanic_i2c_xcvr_write(exanic, port, XCVR_EEPROM_ADDR,
                                CMIS_CTRL_SET_0_APPLY_INIT_BYTE,
                                &host_lane_mask, 1);
    if (ret)
        goto page0_sel;

page0_sel:
    exanic_i2c_cmis_page_sel(exanic, port, 0, 0);
    return ret;
}

static int
exanic_phyops_cmis_configure(struct exanic *exanic, int port, uint32_t speed,
                             bool enable)
{
    int width = exanic_phyops_if_width(exanic);
    int lane_start = exanic_phyops_if_lane_index(exanic, port, width);
    struct exanic_cmis_data_path dpath;
    uint8_t host_lane_mask = 0, media_lane_mask = 0;
    int i, j;

    /* refresh application cache if needed */
    int ret = exanic_phyops_cmis_app_adv_read(exanic, port);
    if (ret)
        return ret;

    __cmis_make_datapath(exanic, port, lane_start, width, speed, &dpath);
    for (i = 0, j = dpath.host_lane; i < dpath.host_lane_count; i++, j++)
        host_lane_mask |= (1 << j);

    for (i = 0, j = dpath.media_lane; i < dpath.media_lane_count; i++, j++)
        media_lane_mask |= (1 << j);

    if (enable)
    {
        uint8_t explicit_control = 0;
        if (dpath.disable_cdrs)
        {
            /* need explicit control to bypass module CDRs */
            explicit_control = 1;
            ret = exanic_phyops_cmis_cdr_bypass(exanic, port, host_lane_mask);
            if (ret)
                return ret;
        }

        ret = exanic_phyops_cmis_datapath_init(exanic, port, &dpath,
                                               host_lane_mask,
                                               explicit_control);
        if (ret)
            return ret;
    }

    ret = exanic_phyops_cmis_set_datapath_pwr(exanic, port,
                                              host_lane_mask,
                                              enable);
    if (ret)
        return ret;

    ret = exanic_phyops_cmis_set_tx_enable(exanic, port,
                                           media_lane_mask,
                                           enable);
    if (ret)
        return ret;

    dev_info(&exanic->pci_dev->dev,
             "%s:%d: CMIS datapath %s\n",
             exanic->name, port, enable ? "enabled" : "disabled");

    return 0;
}

/* all the extern functions below are called with the exanic mutex held */

int exanic_phyops_cmis_init(struct exanic *exanic, int port)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    uint32_t speed = readl(&regs[REG_PORT_INDEX(port, REG_PORT_SPEED)]);
    /* invalidate application cache */
    exanic_phyops_cmis_app_adv_invalidate(exanic, port);
    return exanic_phyops_cmis_configure(exanic, port, speed, true);
}

void exanic_phyops_cmis_powerdown(struct exanic *exanic, int port)
{
    volatile uint32_t *regs = exanic_registers(exanic);
    uint32_t speed = readl(&regs[REG_PORT_INDEX(port, REG_PORT_SPEED)]);
    exanic_phyops_cmis_configure(exanic, port, speed, false);
}

int exanic_phyops_cmis_set_speed(struct exanic *exanic, int port,
                                 uint32_t old_speed, uint32_t speed)
{
    return exanic_phyops_cmis_configure(exanic, port, speed,
                                        exanic->port[port].power);
}
