/**
 * ExaNIC Link Aggregation driver
 * Copyright (C) 2011-2020 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) "exasock-bonding: " fmt

#include <linux/kernel.h>
#include <net/bonding.h>
#include "exasock-bonding-priv.h"

#define EXABOND_MONITOR_DEFAULT_INTERVAL_MS (200)

#define work_struct_to_exabond_master(_work_struct) \
    container_of(to_delayed_work(_work_struct), struct exabond_master, monitor)

static void
exabond_master_monitor_update_interval(struct exabond_master *m)
{
    struct bonding *bonding_master;
    int arp_interval, mii_interval;

    /* Find out what the monitor delays used by bonding.ko for the mii and arp
     * monitors are. Choose the lesser of them and run out monitor at that rate.
     */
    bonding_master = netdev_priv(m->net_device);

    arp_interval = (bonding_master->params.arp_targets[0])
        ? bonding_master->params.arp_interval
        : 0;

    mii_interval = bonding_master->params.miimon;

    if (arp_interval == 0 && mii_interval == 0)
    {
        WARN_ONCE(1, "%s: Bond is using neither ARP nor MII monitor. "
                  "Using default internal interval %dms. "
                  "Very *strongly* recommend setting miimon option for your bond because "
                  "currently there is no link down event signaled by exanic.ko.\n",
                  netdev_name(m->net_device), EXABOND_MONITOR_DEFAULT_INTERVAL_MS);

        m->monitor_interval_ms = EXABOND_MONITOR_DEFAULT_INTERVAL_MS;
        return;
    }

    if (arp_interval == 0)
        arp_interval = EXABOND_MONITOR_DEFAULT_INTERVAL_MS;

    if (mii_interval == 0)
        mii_interval = EXABOND_MONITOR_DEFAULT_INTERVAL_MS;

    m->monitor_interval_ms = (arp_interval < mii_interval)
        ? arp_interval
        : mii_interval;
}

static void
exabond_master_monitor(struct work_struct *_work)
{
    struct exabond_master *m = work_struct_to_exabond_master(_work);

    /* EXPLANATION:
     *
     * In the bonding.ko driver, bonding masters have 2 main monitoring
     * services which periodically scan the links in a bonding group to
     * see if there is a need for failover: the mii_monitor and
     * the arp_monitor.
     *
     * There is no clean way to trap/catch a failover event triggered by
     * one of these monitors, and they all return `void` (just like this
     * very function here).
     *
     * So, we have to just set up a monitoring thread ourselves which will
     * poll at the same rate as the bonding.ko driver's rate, and update
     * the necessary metadata if a failover event occurs; this is
     * necessary because it is not otherwise possible to insert hooks to catch
     * such events.
     */
    if (exabond_master_groupinfo_flags_have_changed(m))
    {
        if (printk_ratelimit())
            pr_info("%s-monitor: changes detected! Groupinfo updated!\n",
                    netdev_name(m->net_device));

        mutex_lock(&m->mutex);
        exabond_master_groupinfo_update(m);
        mutex_unlock(&m->mutex);
    }

    /* That's it, nothing else to do. */
    exabond_master_monitor_update_interval(m);
    schedule_delayed_work(&m->monitor, msecs_to_jiffies(m->monitor_interval_ms));
}

int
exabond_master_monitor_init(struct exabond_master *m)
{
    exabond_master_monitor_update_interval(m);
    pr_info("%s: Detected monitor rate to be %ld ms\n",
            netdev_name(m->net_device), m->monitor_interval_ms);
    INIT_DELAYED_WORK(&m->monitor, exabond_master_monitor);
    return schedule_delayed_work(&m->monitor, msecs_to_jiffies(m->monitor_interval_ms));
}

void
exabond_master_monitor_destroy(struct exabond_master *m)
{
    cancel_delayed_work_sync(&m->monitor);
}
