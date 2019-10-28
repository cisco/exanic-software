/**
 * PHY level operations for ExaNIC cards
 * Copyright (C) 2011-2019 Exablaze Pty Ltd and its licensors
 */

#ifndef _EXANIC_PHYOPS_H_
#define _EXANIC_PHYOPS_H_

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
typedef struct ethtool_link_ksettings exanic_phyops_configs_t;
#else
typedef struct ethtool_cmd exanic_phyops_configs_t;
#endif

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

    /* called with exanic mutex held */
    int (*get_module_info)(struct exanic *exanic, int port,
                           struct ethtool_modinfo *);
    int (*get_module_eeprom)(struct exanic *exanic, int port,
                             struct ethtool_eeprom *, uint8_t *);
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
int exanic_phyops_get_module_info(struct exanic *exanic, int port,
                                  struct ethtool_modinfo *);
int exanic_phyops_get_module_eeprom(struct exanic *exanic, int port,
                                    struct ethtool_eeprom *, uint8_t *);
#endif /* _EXANIC_PHYOPS_H_ */
