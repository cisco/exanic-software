/**
 * ExaNIC Link Aggregation driver
 * Copyright (C) 2011-2020 Exablaze Pty Ltd and its licensors
 */

/**	EXPLANATION:
 * This driver is a derivative of the Linux bonding driver, which is meant to
 * specifically manage LAG (Link Aggregation Groups) of exanic devices.
 *
 * In summary, this driver maintains some metadata about the set of exanic
 * devices contained in each bonding group. A single instance of "exabond"
 * is a single LAG.
 *
 * Calling mmap() on an exabond instance will share the LAG metadata for that
 * instance with the caller. This metadata includes things like the membership
 * of the LAG and so on, and it also includes a synchronization protocol to
 * enable the caller to poll and receive notifications for when the membership
 * of the LAG has changed.
 */
#ifndef _EXABOND_PRIVATE_H
#define _EXABOND_PRIVATE_H

#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <net/rtnetlink.h>
#include "../../libs/exasock/kernel/exasock-bonding.h"

#define EXABOND_DEV_NAME_SZ (IFNAMSIZ * 2)

typedef ssize_t (sysfs_dev_attr_store_fn_t)(struct device *d,
                                            struct device_attribute *attr,
                                            const char *buf, size_t count);

struct exabond_info
{
    sysfs_dev_attr_store_fn_t *orig_sysfs_attr_mode_store;
    sysfs_dev_attr_store_fn_t *orig_sysfs_attr_slaves_store;
    sysfs_dev_attr_store_fn_t *orig_sysfs_attr_active_slave_store;
    sysfs_dev_attr_store_fn_t *orig_sysfs_attr_primary_store;
    sysfs_dev_attr_store_fn_t *orig_sysfs_attr_primary_reselect_store;

    spinlock_t lock;
    /* List of bonding driver `exabond_master` instances. */
    struct list_head ifaces;
    struct module *bonding_ko_ref;
};

struct exabond_master
{
    char devname[EXABOND_DEV_NAME_SZ];
    struct miscdevice miscdev;
    struct list_head sibling_ifaces;

    /* Read comments in exabond_netdev_replace_ops() to understand why we
     * need to duplicate `exabond_netdev_ops` for each bond group.
     */
    const struct net_device_ops *orig_netdev_ops;
    const struct rtnl_link_ops *orig_rtnl_link_ops;
    struct net_device_ops exabond_netdev_ops;
    struct rtnl_link_ops exabond_rtnl_link_ops;

    struct net_device *net_device;

    /* This lock protects the `groupinfo` metadata.
     *
     * The reason this is a mutex and not a spinlock is because
     * ndo_add_slave is called while this lock is held, and since
     * ndo_add_slave is a long running operation, we should
     * block contenders instead of making them spin on a
     * long-running/blocking operation.
     */
    struct mutex mutex;
    struct exabond_master_groupinfo *groupinfo;

    struct delayed_work monitor;
    unsigned long monitor_interval_ms;
};

#if __HAS_BONDING_KO_HEADER
int exabond_init(struct exabond_info *e);
void exabond_destroy(struct exabond_info *e);
#else
static inline int exabond_init(struct exabond_info *e)
{
    pr_info("exasock-bonding: Not supported on this kernel.\n");
    return 0;
}

static inline void exabond_destroy(struct exabond_info *e)
{
}
#endif

extern struct file_operations exabond_dev_fops;

void exabond_master_groupinfo_update(struct exabond_master *m);
bool exabond_master_groupinfo_flags_have_changed(struct exabond_master *m);


int exabond_master_groupinfo_init(struct exabond_master_groupinfo *g);
void exabond_master_groupinfo_destroy(struct exabond_master_groupinfo *g);

int exabond_master_init(struct exabond_master *m, struct net_device *nd);
void exabond_master_destroy(struct exabond_master *m);

int exabond_master_dev_create(struct exabond_master *m);
void exabond_master_dev_destroy(struct exabond_master *m);

/* Driver state singleton decl */
extern struct exabond_info exabond;

int exabond_sysfs_init(struct exabond_info *e);
int exabond_sysfs_destroy(struct exabond_info *e);

int exabond_master_monitor_init(struct exabond_master *m);
void exabond_master_monitor_destroy(struct exabond_master *m);

struct exabond_master *exabond_ifaces_begin_managing(const char *iface_name,
                                                     bool *already_exists);

bool exabond_ifaces_stop_managing_and_destroy(const char *iface_name);

struct exabond_master *exabond_ifaces_find_by_name(const char *iface_name);
struct exabond_master *exabond_ifaces_find_by_major_minor(int maj, int min);

ssize_t exabond_sysfs_devattr_mode_store(struct device *d,
                                         struct device_attribute *attr,
                                         const char *buf, size_t count);

ssize_t exabond_sysfs_devattr_slaves_store(struct device *d,
                                           struct device_attribute *attr,
                                           const char *buf, size_t count);

ssize_t exabond_sysfs_devattr_active_slave_store(struct device *d,
                                                 struct device_attribute *attr,
                                                 const char *buf, size_t count);

ssize_t exabond_sysfs_devattr_primary_store(struct device *d,
                                            struct device_attribute *attr,
                                            const char *buf, size_t count);

ssize_t exabond_sysfs_devattr_primary_reselect_store(struct device *d,
                                                     struct device_attribute *attr,
                                                     const char *buf, size_t count);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
#define __RTNL_LINK_OPS_HAVE_EXTACK
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 14) && defined(CONFIG_SUSE_KERNEL)
/* Backported by SuSE */
#define __RTNL_LINK_OPS_HAVE_EXTACK
#endif

int exabond_rtnl_changelink(struct net_device *bond_dev,
                            struct nlattr *tb[],
                            struct nlattr *data[]
#ifdef __RTNL_LINK_OPS_HAVE_EXTACK
                            , struct netlink_ext_ack *extack
#endif
                            );

struct net_device *exabond_ifaces_find_netdev_by_name(const char *iface_name);

int exabond_ndo_do_ioctl(struct net_device *bond_dev,
                         struct ifreq *ifr, int cmd);

static inline bool
exabond_netif_is_bond_master(const struct net_device *nd)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    return netif_is_bond_master((struct net_device *)nd);
#else
    return (nd->flags & IFF_MASTER)
        && (nd->priv_flags & IFF_BONDING);
#endif
}

struct bonding;
bool exabond_bond_contains_netdev(struct bonding *bond_master,
                                  const struct net_device *nd);

#endif /* _EXABOND_PRIVATE_H */
