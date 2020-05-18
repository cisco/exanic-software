/**
 * ExaNIC Link Aggregation driver
 * Copyright (C) 2011-2020 Exablaze Pty Ltd and its licensors
 */

/** @file RTNL_link_ops wrapper for changelink().
 */
#define pr_fmt(fmt) "exasock-bonding: " fmt

#include <linux/netlink.h>
#include <net/bonding.h>

#include "exasock-bonding-priv.h"

int
exabond_rtnl_changelink(struct net_device *bond_dev, struct nlattr *tb[],
                        struct nlattr *data[]
#ifdef __RTNL_LINK_OPS_HAVE_EXTACK
                        , struct netlink_ext_ack *extack
#endif
                        )
{
    struct exabond_master *exa_master;
    int ret;

    if (!data)
        return 0;

    exa_master = exabond_ifaces_find_by_name(netdev_name(bond_dev));
    BUG_ON(exa_master == NULL);

    /* Slave devices can only be added if they are already
     * in active-backup mode. So just enforce immutability.
     */
    if (data[IFLA_BOND_MODE])
    {
        pr_warn("%s: Silently ignoring attempt to change bond mode via "
                "IFLA_BOND_MODE because this driver only supports "
                "active-backup mode(=%d).\n",
                netdev_name(bond_dev), BOND_MODE_ACTIVEBACKUP);

#ifdef __RTNL_LINK_OPS_HAVE_EXTACK
        NL_SET_ERR_MSG(extack, "Illegal to change bond mode while under "
                       "exasock-management. See kernel log.");
#endif

        return -ENOTSUPP;
    }

    ret = exa_master->orig_rtnl_link_ops->changelink(bond_dev,
                                                     tb, data
#ifdef __RTNL_LINK_OPS_HAVE_EXTACK
                                                     , extack
#endif
                                                     );

    if (data[IFLA_BOND_ACTIVE_SLAVE] || data[IFLA_BOND_PRIMARY]
        || data[IFLA_BOND_PRIMARY_RESELECT])
    {
        /* Update groupinfo if active slave changed. */
        mutex_lock(&exa_master->mutex);
        if (exabond_master_groupinfo_flags_have_changed(exa_master))
            exabond_master_groupinfo_update(exa_master);
        mutex_unlock(&exa_master->mutex);
    }

    return ret;
}
