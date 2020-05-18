/**
 * ExaNIC Link Aggregation driver
 * Copyright (C) 2011-2020 Exablaze Pty Ltd and its licensors
 */
#define pr_fmt(fmt) "exasock-bonding: " fmt

#include <linux/version.h>
#include <linux/string.h>
#include <linux/if.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/mutex.h>
#include <net/bonding.h>

#include "exasock-bonding-priv.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) \
    && LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0) \
    && !__HAS_NETDEV_CLASS_CREATE_FILE_NS
static const void *
exabond_get_sysfs_namespace(struct class *cls,
                            const struct class_attribute *attr)
{
    /* This will need to be augmented if we wish to support net namespacing
     * outside of init_net on kernels < 3.13.
     */
    return &init_net;
}
#endif

static ssize_t
exabond_masters_show(struct class *c,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
                     struct class_attribute *cattr,
#endif
                     char *buf)
{
    ssize_t outstrlen=0;
    unsigned long irqf;
    struct exabond_master *cur;

    BUG_ON(spin_is_locked(&exabond.lock));
    spin_lock_irqsave(&exabond.lock, irqf);

    list_for_each_entry(cur, &exabond.ifaces, sibling_ifaces)
    {
        size_t slen;

        BUG_ON(cur->net_device == NULL);
        slen = snprintf(&buf[outstrlen],
                        PAGE_SIZE - outstrlen,
                        "%s ", netdev_name(cur->net_device));

        /* We appended a space (' ') after it */
        BUG_ON(slen - 1 >= IFNAMSIZ);

        /* Not enough buffer space left. */
        if (slen > PAGE_SIZE - outstrlen)
            break;

        outstrlen += slen;
    }

    spin_unlock_irqrestore(&exabond.lock, irqf);
    BUG_ON(spin_is_locked(&exabond.lock));

    if (outstrlen > 0)
        buf[outstrlen - 1] = '\n';

    return outstrlen;
}

static ssize_t
exabond_masters_store(struct class *c,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
                      struct class_attribute *cattr,
#endif
                      const char *buf, size_t count)
{
    char command;
    struct exabond_master *master;
    bool already_managed;
    char iface_name[IFNAMSIZ];

    // Add +1 chars to account for the '+'/'-' sign.
    if (count >= IFNAMSIZ + 1) {
        return -ENOSTR;
    }
    if (count < 2) {
        return -ENOMSG;
    }

    command = buf[0];
    sscanf(&buf[1], "%16s", iface_name);

    switch (command)
    {
    case '+':
        master = exabond_ifaces_begin_managing(iface_name,
                                               &already_managed);
        if (master == NULL)
            return -ENOENT;

        if (already_managed)
        {
            pr_warn("Iface %s is already being managed.\n",
                    iface_name);
        }
        else
        {
            pr_info("Now managing bond %s.\n",
                    iface_name);
        }

        break;

    case '-':
        if (!exabond_ifaces_stop_managing_and_destroy(iface_name))
        {
            pr_err("Iface %s was not under "
                   "management to begin with.\n",
                   iface_name);
        }
        else
        {
            pr_info("Iface %s no longer being managed\n",
                    iface_name);
        }

        break;

    default:
        pr_warn("First char in input string must "
                "be '+' or '-' to add or remove a bonding master, "
                "respectively\n");

        return -ENOMSG;
    }

    return count;
}

static CLASS_ATTR_RW(exabond_masters);

static inline int
exabond_sysfs_attr_store_sanitychk_and_get_master(const struct device *d,
                                                  struct net_device **out_master_dev,
                                                  struct exabond_master **out_exa_master,
                                                  sysfs_dev_attr_store_fn_t *orig_fn)
{
    /* It could happen that our state machine gets messed up somewhere and
     * our wrapper sysfs ops get left inside of the bonding driver's sysfs
     * ops struct, after we release all devices. Unlikely situation, but
     * worth checking for, if only to warn the user of a bug.
     */
    if (orig_fn == NULL)
    {
        unsigned long irqf;
        bool is_empty;

        spin_lock_irqsave(&exabond.lock, irqf);
        is_empty = list_empty(&exabond.ifaces);
        spin_unlock_irqrestore(&exabond.lock, irqf);

        pr_err("This driver is under the "
               "impression that it is not currently managing any bond "
               "groups. Yet the bonding driver's sysfs ops have been "
               "replaced with our ops, and they were not restored. "
               "This should never happen. Bond list status is '%s' "
               "(it should be empty).\n",
               ((is_empty) ? "empty" : "not-empty"));
        BUG();
    }

    *out_master_dev = to_net_dev(d);
    *out_exa_master = exabond_ifaces_find_by_name(netdev_name(*out_master_dev));
    return (*out_exa_master == NULL)
        ? -ENOENT
        : 0;
}

/** This is a wrapper function around the sysfs attribute exported by the
 * Linux "bonding" driver.
 *
 * When the user attempts to add or remove a net_device from one of the
 * bonding groups that we are currently managing, we intercept said attempt
 * using this function.
 *
 * We then do some checks to ensure that it is safe to allow the new slave
 * to be added (such as, we ensure that the new slave is an ExaNIC, etc)
 * and then chain-call the "bonding" driver's original `store()` routine
 * if the checks are successful.
 *
 * The difference between this function and `exabond_masters_store()` above
 * is that `exabond_masters_store()` adds a new MASTER to be managed by THIS
 * driver, whereas this function checks whether a new SLAVE being added to one
 * of the masters ALREADY being managed by us, should be permitted.
 */
ssize_t
exabond_sysfs_devattr_slaves_store(struct device *d,
                                   struct device_attribute *attr,
                                   const char *buf, size_t count)
{
    struct net_device *new_slave_dev, *master_dev;
    struct exabond_master *exa_master;
    struct net *netns;
    char command, iface_name[IFNAMSIZ];
    ssize_t ret;
    struct ifreq ifr;

    ret = exabond_sysfs_attr_store_sanitychk_and_get_master(d,
                                                            &master_dev,
                                                            &exa_master,
                                                            exabond.orig_sysfs_attr_slaves_store);
    if (ret != 0)
    {
        /* Since we replaced the bonding driver's sysfs ops (all bonding groups
         * share the same sysfs ops), we'll also be getting all of the sysfs
         * invocations on attributes of bonding groups that we are *not*
         * currently managing.
         *
         * If this sysfs request is for such a device which isn't managed by us,
         * pass the call through to the bonding driver's original sysfs ops
         * function.
         */
        return exabond.orig_sysfs_attr_slaves_store(d, attr, buf, count);
    }

    // Add +1 chars to account for the '+'/'-' sign.
    if (count >= IFNAMSIZ + 1) {
        return -ENOSTR;
    }
    if (count < 2) {
        return -ENOMSG;
    }

    command = buf[0];
    if (command != '+' && command != '-')
        return -ENOMSG;

    sscanf(&buf[1], "%16s", iface_name);

    if (!dev_valid_name(iface_name))
        return -ENODEV;

    netns = dev_net(master_dev);
    if (netns == NULL)
        return -EACCES;

    new_slave_dev = __dev_get_by_name(netns, iface_name);
    if (new_slave_dev == NULL)
    {
        pr_warn("master %s: Attempt to add or "
                "remove slave %s which isn't known to NAPI.\n",
                netdev_name(master_dev), iface_name);

        return -ENODEV;
    }

    strcpy(ifr.ifr_slave, iface_name);

    if (command == '+')
    {
        /* Just reuse `exabond_ndo_do_ioctl` instead of calling into
         * `orig_sysfs_attr_slaves_store`.
         *
         * LOCKING NOTES:
         * RTNL lock must be acquired for bond_enslave/release, but
         * only on the SYSFS path. The IOCTL and ndo_add/del_slave
         * paths are locked by Linux before we are invoked.
         */
        rtnl_lock();
        ret = exabond_ndo_do_ioctl(master_dev, &ifr,
                                   SIOCBONDENSLAVE);
        rtnl_unlock();
    }
    else /* command == '-' */
    {
        if (!exabond_bond_contains_netdev(netdev_priv(master_dev),
                                          new_slave_dev))
        {
            pr_err("master %s: Attempt to "
                   "remove dev %s, when it wasn't in the bond "
                   "group to begin with.\n",
                   netdev_name(master_dev),
                   netdev_name(new_slave_dev));

            return -ENOENT;
        }

        /* Reuse `exabond_ndo_do_ioctl` */
        rtnl_lock();
        ret = exabond_ndo_do_ioctl(master_dev, &ifr,
                                   SIOCBONDRELEASE);
        rtnl_unlock();
    }

    /* We don't have to explicitly update the groupinfo for active/primary
     * device here, because that's done inside of ndo_[add|del]_slave.
     */
    if (ret != 0)
        return ret;

    return count;
}

ssize_t
exabond_sysfs_devattr_mode_store(struct device *d,
                                 struct device_attribute *attr,
                                 const char *buf, size_t count)
{
    struct net_device *master_dev;
    struct exabond_master *exa_master;
    int ret;

    ret = exabond_sysfs_attr_store_sanitychk_and_get_master(d,
                                                            &master_dev,
                                                            &exa_master,
                                                            exabond.orig_sysfs_attr_active_slave_store);
    if (ret != 0)
    {
        BUG_ON(exabond.orig_sysfs_attr_mode_store == NULL);
        return exabond.orig_sysfs_attr_mode_store(d,
                                                  attr, buf, count);
    }

    /* We required the user to set the bond into `active-backup` mode
     * before we would take it under management, so from here we just need
     * to reject any attempt to change its mode.
     */
    pr_warn("%s: Silently ignoring attempt to change bond mode "
            "because this driver only supports active-backup mode(=%d).\n",
            netdev_name(master_dev), BOND_MODE_ACTIVEBACKUP);

    return -ENOTSUPP;
}

ssize_t
exabond_sysfs_devattr_active_slave_store(struct device *d,
                                         struct device_attribute *attr,
                                         const char *buf, size_t count)
{
    struct net_device *master_dev;
    struct exabond_master *exa_master;
    int ret;

    ret = exabond_sysfs_attr_store_sanitychk_and_get_master(d,
                                                            &master_dev,
                                                            &exa_master,
                                                            exabond.orig_sysfs_attr_active_slave_store);

    /* Unconditionally call into the `bonding` driver to have it change
     * the active child. Then detect and propagate the new active child
     * to userspace if the bond is under management by this driver.
     */
    ret = exabond.orig_sysfs_attr_active_slave_store(d,
                                                     attr, buf, count);

    if (exa_master == NULL)
        return ret;

    /* Update groupinfo if active slave changed. */
    mutex_lock(&exa_master->mutex);
    if (exabond_master_groupinfo_flags_have_changed(exa_master))
        exabond_master_groupinfo_update(exa_master);
    mutex_unlock(&exa_master->mutex);
    return ret;
}

ssize_t
exabond_sysfs_devattr_primary_store(struct device *d,
                                    struct device_attribute *attr,
                                    const char *buf, size_t count)
{
    struct net_device *master_dev;
    struct exabond_master *exa_master;
    int ret;

    ret = exabond_sysfs_attr_store_sanitychk_and_get_master(d,
                                                            &master_dev,
                                                            &exa_master,
                                                            exabond.orig_sysfs_attr_primary_store);

    /* Same: unconditional call into `bonding.ko` and then detect
     * changes and propagate if the master is under management.
     */
    ret = exabond.orig_sysfs_attr_primary_store(d,
                                                attr, buf, count);

    if (exa_master == NULL)
        return ret;

    /* Update groupinfo if active slave changed. */
    mutex_lock(&exa_master->mutex);
    if (exabond_master_groupinfo_flags_have_changed(exa_master))
        exabond_master_groupinfo_update(exa_master);
    mutex_unlock(&exa_master->mutex);
    return ret;
}

ssize_t
exabond_sysfs_devattr_primary_reselect_store(struct device *d,
                                             struct device_attribute *attr,
                                             const char *buf, size_t count)
{
    struct net_device *master_dev;
    struct exabond_master *exa_master;
    int ret;

    ret = exabond_sysfs_attr_store_sanitychk_and_get_master(d,
                                                            &master_dev,
                                                            &exa_master,
                                                            exabond.orig_sysfs_attr_primary_reselect_store);

    /* Same: unconditional call into `bonding.ko` and then detect
     * changes and propagate if the master is under management.
     */
    ret = exabond.orig_sysfs_attr_primary_reselect_store(d,
                                                         attr, buf, count);

    if (exa_master == NULL)
        return ret;

    /* Update groupinfo if active slave changed. */
    mutex_lock(&exa_master->mutex);
    if (exabond_master_groupinfo_flags_have_changed(exa_master))
        exabond_master_groupinfo_update(exa_master);
    mutex_unlock(&exa_master->mutex);
    return ret;
}

int
exabond_sysfs_init(struct exabond_info *e)
{
    int ret;

    /* NOTE:
     * Notice how we only create this class file in the init_net namespace.
     */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) \
    && LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0) \
    && !__HAS_NETDEV_CLASS_CREATE_FILE_NS
    class_attr_exabond_masters.namespace = exabond_get_sysfs_namespace;
#endif

#if __HAS_NETDEV_CLASS_CREATE_FILE_NS
    ret = netdev_class_create_file_ns(&class_attr_exabond_masters, &init_net);
#else
    ret = netdev_class_create_file(&class_attr_exabond_masters);
#endif
    if (ret == -EEXIST)
    {
        pr_warn("Sysfs class already exists.\n");
        return 0;
    }
    else if (ret != 0)
        pr_err("Failed to create sysfs class.\n");

    return ret;
}

int
exabond_sysfs_destroy(struct exabond_info *e)
{
#if __HAS_NETDEV_CLASS_CREATE_FILE_NS
    netdev_class_remove_file_ns(&class_attr_exabond_masters, &init_net);
#else
    netdev_class_remove_file(&class_attr_exabond_masters);
#endif
    return 0;
}
