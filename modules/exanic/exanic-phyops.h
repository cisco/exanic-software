/**
 * PHY level operations for ExaNIC cards
 * Copyright (C) 2011-2019 Exablaze Pty Ltd and its licensors
 */

#ifndef _EXANIC_PHYOPS_H_
#define _EXANIC_PHYOPS_H_

#include <linux/version.h>

/* kernel version compatibility macros */

#ifndef SUPPORTED_1000baseKX_Full
#define SUPPORTED_1000baseKX_Full	(1 << 17)
#endif
#ifndef SUPPORTED_10000baseKR_Full
#define SUPPORTED_10000baseKR_Full	(1 << 19)
#endif
#ifndef SUPPORTED_40000baseCR4_Full
#define SUPPORTED_40000baseCR4_Full	(1 << 24)
#endif
#ifndef SUPPORTED_40000baseSR4_Full
#define SUPPORTED_40000baseSR4_Full	(1 << 25)
#endif
#ifndef SUPPORTED_40000baseLR4_Full
#define SUPPORTED_40000baseLR4_Full	(1 << 26)
#endif
#ifndef SPEED_40000
#define SPEED_40000 40000
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)

#define LINK_CONFIGS_ZERO(configs) \
        ethtool_link_ksettings_zero_link_mode(configs, supported)

#define LINK_CONFIGS_SET_SUPPORTED(configs, _item) \
        ethtool_link_ksettings_add_link_mode(configs, supported, _item)

#define LINK_CONFIGS_SET(configs, _item, val) \
        configs->base._item = (val)

#define LINK_CONFIGS_SET_SPEED(configs, val) \
        LINK_CONFIGS_SET(configs, speed, val)

#define LINK_CONFIGS_GET(configs, _item) \
        (configs->base._item)

#define LINK_CONFIGS_GET_SPEED(configs) \
        LINK_CONFIGS_GET(configs, speed)

typedef struct ethtool_link_ksettings exanic_phyops_configs_t;

#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0) */

#define LINK_CONFIGS_ZERO(configs)

#define LINK_CONFIGS_SET_SUPPORTED(setting, _item) \
        configs->supported |= SUPPORTED_##_item

#define LINK_CONFIGS_SET(configs, _item, val) \
        configs->_item = (val)

#define LINK_CONFIGS_SET_SPEED(configs, val) \
        ethtool_cmd_speed_set(configs, val)

#define LINK_CONFIGS_GET(configs, _item) \
        (configs->_item)

#define LINK_CONFIGS_GET_SPEED(configs) \
        ethtool_cmd_speed(configs)

typedef struct ethtool_cmd exanic_phyops_configs_t;

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0) */

struct exanic;
struct exanic_phy_ops
{
    void *data;

    /* power on the port, called with exanic mutex held */
    int (*poweron)(struct exanic *exanic, int port);

    /* power off the port, called with exanic mutex held */
    void (*poweroff)(struct exanic *exanic, int port);

    /* apply initial configs, called with exanic mutex held */
    int (*init)(struct exanic *exanic, int port);

    /* ethtool interface implementations */
    int (*get_configs)(struct exanic *exanic, int port,
                       exanic_phyops_configs_t *configs);
    /* called with exanic mutex held */
    int (*set_configs)(struct exanic *exanic, int port,
                       const exanic_phyops_configs_t *configs);

    uint32_t (*get_link_status)(struct exanic *exanic, int port);

#ifdef ETHTOOL_GMODULEINFO
    /* called with exanic mutex held */
    int (*get_module_info)(struct exanic *exanic, int port,
                           struct ethtool_modinfo *);
    int (*get_module_eeprom)(struct exanic *exanic, int port,
                             struct ethtool_eeprom *, uint8_t *);
#endif /* ETHTOOL_GMODULEINFO */
};

/* associate a list of phy operations with port, called either at device
 * probe time or when power is first applied, with the exanic mutex held
 * power: whether power has been applied */
void exanic_phyops_init_fptrs(struct exanic *exanic, int port, bool power);

/* return the number of lanes that make up an interface */
int exanic_phyops_if_width(struct exanic *exanic);

/* return the starting lane number of interface */
int exanic_phyops_if_lane_index(struct exanic *exanic, int port, int width);

/* return the number of lanes given transceiver type */
int exanic_phyops_xcvr_width(int sff8024_id);

/* wrappers over struct exanic_phy_ops */
int exanic_phyops_poweron(struct exanic *exanic, int port);
void exanic_phyops_poweroff(struct exanic *exanic, int port);
int exanic_phyops_init(struct exanic *exanic, int port);
int exanic_phyops_get_configs(struct exanic *exanic, int port,
                              exanic_phyops_configs_t *);
int exanic_phyops_set_configs(struct exanic *exanic, int port,
                              const exanic_phyops_configs_t *);
int exanic_phyops_get_link_status(struct exanic *exanic, int port, uint32_t *link);

#ifdef ETHTOOL_GMODULEINFO
int exanic_phyops_get_module_info(struct exanic *exanic, int port,
                                  struct ethtool_modinfo *);
int exanic_phyops_get_module_eeprom(struct exanic *exanic, int port,
                                    struct ethtool_eeprom *, uint8_t *);
#endif /* ETHTOOL_GMODULEINFO */

#endif /* _EXANIC_PHYOPS_H_ */
