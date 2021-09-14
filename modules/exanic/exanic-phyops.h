/**
 * PHY level operations for ExaNIC cards
 * Copyright (C) 2011-2019 Exablaze Pty Ltd and its licensors
 */

#ifndef _EXANIC_PHYOPS_H_
#define _EXANIC_PHYOPS_H_

#include <linux/version.h>
#include <linux/ethtool.h> /* for ETHTOOL_* defines */

/* ETHTOOL_LINK_MODE_* constants are part of an enum in the kernel
 * headers, it is difficult to test which bits are defined in any
 * given kernel version so they are defined locally here. */
#define _ETHTOOL_LINK_MODE_10baseT_Full_BIT       (1)
#define _ETHTOOL_LINK_MODE_100baseT_Full_BIT      (3)
#define _ETHTOOL_LINK_MODE_1000baseT_Full_BIT     (5)
#define _ETHTOOL_LINK_MODE_Autoneg_BIT            (6)
#define _ETHTOOL_LINK_MODE_1000baseKX_Full_BIT    (17)
#define _ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT  (18)
#define _ETHTOOL_LINK_MODE_10000baseKR_Full_BIT   (19)
#define _ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT  (23)
#define _ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT  (24)
#define _ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT  (25)
#define _ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT  (26)
#define _ETHTOOL_LINK_MODE_25000baseCR_Full_BIT   (31)
#define _ETHTOOL_LINK_MODE_25000baseKR_Full_BIT   (32)
#define _ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT (36)
#define _ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT (38)

#ifndef SPEED_25000
#define SPEED_25000 25000
#endif
#ifndef SPEED_40000
#define SPEED_40000 40000
#endif

#ifdef ETHTOOL_GLINKSETTINGS

#define LINK_CONFIGS_ZERO(configs) \
        ethtool_link_ksettings_zero_link_mode(configs, supported); \
        ethtool_link_ksettings_zero_link_mode(configs, advertising); \
        ethtool_link_ksettings_zero_link_mode(configs, lp_advertising);

#define LINK_CONFIGS_SET_SUPPORTED(configs, _item) \
        ethtool_link_ksettings_add_link_mode(configs, supported, _item)

#define LINK_CONFIGS_SET_ADVERTISING(configs, _item) \
        ethtool_link_ksettings_add_link_mode(configs, advertising, _item)

#define LINK_CONFIGS_SET_SUPPORTED_BIT(configs, bit_num) \
        __set_bit(bit_num, configs->link_modes.supported)

#define LINK_CONFIGS_SET_ADVERTISING_BIT(configs, bit_num) \
        __set_bit(bit_num, configs->link_modes.advertising)

#define LINK_CONFIGS_SET_LP_ADVERTISING(configs, _item) \
        ethtool_link_ksettings_add_link_mode(configs, lp_advertising, _item)

#define LINK_CONFIGS_SET_LP_ADVERTISING_BIT(configs, bit_num) \
        __set_bit(bit_num, configs->link_modes.lp_advertising)

#define LINK_CONFIGS_SET(configs, _item, val) \
        (configs)->base._item = (val)

#define LINK_CONFIGS_SET_SPEED(configs, val) \
        LINK_CONFIGS_SET(configs, speed, val)

#define LINK_CONFIGS_GET(configs, _item) \
        ((configs)->base._item)

#define LINK_CONFIGS_GET_ADVERTISING(configs) \
        ((configs)->link_modes.advertising[0])

#define LINK_CONFIGS_GET_SPEED(configs) \
        LINK_CONFIGS_GET(configs, speed)

typedef struct ethtool_link_ksettings exanic_phyops_configs_t;
typedef struct ethtool_fecparam     exanic_phyops_fecparams_t;

#else /* ETHTOOL_GLINKSETTINGS */

#define LINK_CONFIGS_ZERO(configs) \
        (configs)->supported = 0; \
        (configs)->advertising = 0; \
        (configs)->lp_advertising = 0;

#define LINK_CONFIGS_SET_SUPPORTED(setting, _item) \
        (configs)->supported |= SUPPORTED_##_item

#define LINK_CONFIGS_SET_ADVERTISING(setting, _item) \
        (configs)->advertising |= SUPPORTED_##_item

#define LINK_CONFIGS_SET_SUPPORTED_BIT(configs, bit_num) \
        do \
        { \
            if (bit_num < 32) \
                (configs)->supported |= (1 << bit_num); \
        }while(0)

#define LINK_CONFIGS_SET_ADVERTISING_BIT(configs, bit_num) \
        do \
        { \
            if (bit_num < 32) \
                (configs)->advertising |= (1 << bit_num); \
        }while(0)

#define LINK_CONFIGS_SET_LP_ADVERTISING(configs, _item) \
        (configs)->lp_advertising |= SUPPORTED_##_item

#define LINK_CONFIGS_SET_LP_ADVERTISING_BIT(configs, bit_num) \
        do \
        { \
            if (bit_num < 32) \
                (configs)->lp_advertising |= (1 << bit_num); \
        }while(0)


#define LINK_CONFIGS_SET(configs, _item, val) \
        (configs)->_item = (val)

#define LINK_CONFIGS_SET_SPEED(configs, val) \
        ethtool_cmd_speed_set(configs, val)

#define LINK_CONFIGS_GET(configs, _item) \
        ((configs)->_item)

#define LINK_CONFIGS_GET_ADVERTISING(configs) \
        ((configs)->advertising)


#define LINK_CONFIGS_GET_SPEED(configs) \
        ethtool_cmd_speed((exanic_phyops_configs_t *)(configs))

typedef struct ethtool_cmd exanic_phyops_configs_t;

#endif /* ETHTOOL_GLINKSETTINGS */

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

#ifdef ETHTOOL_SFECPARAM
    /* fecparams management operations */
    int (*set_fecparam)(struct exanic *exanic, int port,
                       const exanic_phyops_fecparams_t* fp);

    int (*get_fecparam)(struct exanic *exanic, int port,
                       exanic_phyops_fecparams_t *fp);
#endif /* ETHTOOL_SFECPARAM */

    uint32_t (*get_link_status)(struct exanic *exanic, int port);

#ifdef ETHTOOL_GMODULEINFO
    /* called with exanic mutex held */
    int (*get_module_info)(struct exanic *exanic, int port,
                           struct ethtool_modinfo *);
    int (*get_module_eeprom)(struct exanic *exanic, int port,
                             struct ethtool_eeprom *, uint8_t *);
#endif /* ETHTOOL_GMODULEINFO */

    int (*restart_autoneg)(struct exanic *exanic, int port);
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

#ifdef ETHTOOL_SFECPARAM
int exanic_phyops_get_fecparam(struct exanic *exanic, int port,
                               struct ethtool_fecparam *fp);
int exanic_phyops_set_fecparam(struct exanic *exanic, int port, struct ethtool_fecparam *fp);
#endif /* ETHTOOL_SFECPARAM */

int exanic_phyops_restart_autoneg(struct exanic *exanic, int port);

#ifdef ETHTOOL_GMODULEINFO
int exanic_phyops_get_module_info(struct exanic *exanic, int port,
                                  struct ethtool_modinfo *);
int exanic_phyops_get_module_eeprom(struct exanic *exanic, int port,
                                    struct ethtool_eeprom *, uint8_t *);
#endif /* ETHTOOL_GMODULEINFO */

#endif /* _EXANIC_PHYOPS_H_ */
