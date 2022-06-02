/**
 * ExaNIC Link Aggregation driver
 * Copyright (C) 2011-2020 Exablaze Pty Ltd and its licensors
 *
 * NOTE:
 *
 * This driver currently doesn't support bond net_devices in net namespaces
 * other than the init_net.
 */
#define pr_fmt(fmt) "exasock-bonding: " fmt

#include <linux/version.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/bug.h>
#include <linux/skbuff.h>
#include <linux/sysfs.h>
#include <linux/if_ether.h>
#include <linux/spinlock.h>
#include <net/bonding.h>

/* Older versions of net/bonding.h exported DRV_VERSION/DRV_NAME
 * which conflict with those in exanic.h */
#undef DRV_VERSION
#undef DRV_NAME

#include "../exanic/exanic.h"
#include "exasock.h"
#include "exasock-bonding-priv.h"

#define to_dev_attr(_attr) container_of(_attr, struct device_attribute, attr)

// Global driver state singleton.
struct exabond_info exabond;
struct netlink_ext_ack;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
#define EXABOND_NL_SET_ERR_MSG(_obj,_msg) NL_SET_ERR_MSG((_obj),(_msg))
#else
#define EXABOND_NL_SET_ERR_MSG(_obj,_msg)
#endif

/* Kernel versions before 3.12 locked the bond slave list
 * differently. These macros abstracts that difference away.
 */
static inline void
bonding_master_list_lock(struct bonding *b)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0) || __HAS_BONDING_KO_HEADER
    rcu_read_lock();
#else
    read_lock(&b->lock);
#endif
}

static inline void
bonding_master_list_unlock(struct bonding *b)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0) || __HAS_BONDING_KO_HEADER
    rcu_read_unlock();
#else
    read_unlock(&b->lock);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0) || __HAS_BONDING_KO_HEADER
#define exabond_bond_for_each_slave(bond_master, slave_ret, list_iter) \
    bond_for_each_slave_rcu(bond_master, slave_ret, list_iter)
#else
#define exabond_bond_for_each_slave(bond_master, slave_ret, list_iter) \
    bond_for_each_slave(bond_master, slave_ret, list_iter)
#endif

static bool
up_bonding_ko_ref_if_zero(struct exabond_info *e)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
   struct module* m;
   int len = strlen("bonding");
#endif

    if (e->bonding_ko_ref)
        return true;

    /* find_module function has been removed since 5.12.0 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
    e->bonding_ko_ref = find_module("bonding");
    if (e->bonding_ko_ref == NULL || !try_module_get(e->bonding_ko_ref))
    {
        e->bonding_ko_ref = NULL;
        return false;
    }
    return true;
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0) */
    rcu_read_lock();
    list_for_each_entry_rcu(m, &THIS_MODULE->list, list)
    {
        if (m->state == MODULE_STATE_UNFORMED)
            continue;

        if (strlen(m->name) == len &&
            !memcmp(m->name, "bonding", len))
        {
            if (!try_module_get(m))
            {
                e->bonding_ko_ref = NULL;
                rcu_read_unlock();
                return false;
            }
            e->bonding_ko_ref = m;
            rcu_read_unlock();
            return true;
        }
    }
    rcu_read_unlock();
    e->bonding_ko_ref = NULL;
    return false;
#endif
}

static void
down_bonding_ko_ref_if_nonzero(struct exabond_info *e)
{
    if (e->bonding_ko_ref != NULL)
    {
        module_put(e->bonding_ko_ref);
        e->bonding_ko_ref = NULL;
    }
}

/* Scans through all the net_device(s) in a bonding instance and returns false
 * if at least one of them is *not* an exanic.
 */
static bool
exabond_bond_all_children_are_exanics(struct bonding *bond_master,
                                      char *first_non_exanic_iface_name)
{
    bool ret = true;
    struct slave *cur_slave;
    struct list_head *slave_iter;

    bonding_master_list_lock(bond_master);

    exabond_bond_for_each_slave(bond_master, cur_slave, slave_iter)
    {
        if (!exasock_is_exanic_dev(cur_slave->dev))
        {
            ret = false;
            strncpy(first_non_exanic_iface_name,
                    netdev_name(cur_slave->dev), IFNAMSIZ);
            break;
        }
    }

    bonding_master_list_unlock(bond_master);

    /* If n_slaves is 0 (i.e, the bond group has not been assigned any
     * children as yet), we return true and allow the bond group to be
     * managed by exabond.
     *
     * The code that validates that new slaves are exanic devices on
     * group membership update, will enforce the exablaze membership
     * exclusivity property for us.
     */
    return ret;
}

bool
exabond_bond_contains_netdev(struct bonding *bond_master,
                             const struct net_device *nd)
{
    struct slave *cur_slave;
    struct list_head *slave_iter;
    bool ret=false;

    bonding_master_list_lock(bond_master);

    exabond_bond_for_each_slave(bond_master, cur_slave, slave_iter)
    {
        if (strncmp(netdev_name(cur_slave->dev),
                    netdev_name(nd), IFNAMSIZ) == 0)
        {
            ret = true;
            break;
        }
    }

    bonding_master_list_unlock(bond_master);
    return ret;
}

/* Unlocked version */
struct exabond_master *
__exabond_ifaces_find_by_name(const char *iface_name)
{
    struct exabond_master *cur;

    list_for_each_entry(cur, &exabond.ifaces, sibling_ifaces)
    {
        BUG_ON(list_empty(&exabond.ifaces));
        BUG_ON(cur->net_device == NULL);

        if (strncmp(netdev_name(cur->net_device), iface_name, IFNAMSIZ) == 0)
            return cur;
    }

    return NULL;
}

struct exabond_master *
exabond_ifaces_find_by_name(const char *iface_name)
{
    unsigned long irqf;
    struct exabond_master *ret;

    spin_lock_irqsave(&exabond.lock, irqf);
    ret = __exabond_ifaces_find_by_name(iface_name);
    spin_unlock_irqrestore(&exabond.lock, irqf);
    return ret;
}

struct net_device *
exabond_ifaces_find_netdev_by_name(const char *iface_name)
{
    struct exabond_master *m;

    m = exabond_ifaces_find_by_name(iface_name);
    if (!m)
        return NULL;

    return m->net_device;
}
EXPORT_SYMBOL(exabond_ifaces_find_netdev_by_name);

static struct exabond_master *
__exabond_ifaces_find_by_major_minor(int maj, int min)
{
    struct exabond_master *cur;

    list_for_each_entry(cur, &exabond.ifaces, sibling_ifaces)
    {
        BUG_ON(cur->net_device == NULL);

        if (MAJOR(cur->miscdev.this_device->devt) != maj
            || cur->miscdev.minor != min)
            continue;

        return cur;
    }

    return NULL;
}

struct exabond_master *
exabond_ifaces_find_by_major_minor(int maj, int min)
{
    unsigned long irqf;
    struct exabond_master *ret;

    spin_lock_irqsave(&exabond.lock, irqf);
    ret = __exabond_ifaces_find_by_major_minor(maj, min);
    spin_unlock_irqrestore(&exabond.lock, irqf);
    return ret;
}

/* FIXME: Go through entire driver and document lock
 * dependencies for functions that require a lock to
 * be held.
 */
static void
__exabond_ifaces_list_remove(struct exabond_master *m)
{
    BUG_ON(list_empty(&exabond.ifaces));
    list_del(&m->sibling_ifaces);
}

void
exabond_ifaces_list_remove(struct exabond_master *m)
{
    unsigned long irqf;

    spin_lock_irqsave(&exabond.lock, irqf);
    __exabond_ifaces_list_remove(m);
    spin_unlock_irqrestore(&exabond.lock, irqf);
}

static int
__exabond_ndo_ioctl_get_slave_arg(struct net_device *bond_dev,
                                  struct ifreq *ifr,
                                  struct net_device **slave_dev)
{
    struct net *net;

    net = dev_net(bond_dev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
    if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
#else
    if (!capable(CAP_NET_ADMIN))
#endif
        return -EPERM;

    *slave_dev = __dev_get_by_name(net, ifr->ifr_slave);
    if (*slave_dev == NULL)
        return -ENODEV;

    return 0;
}

int
exabond_ndo_sioc_bond_enslave(struct net_device *dev,
                              struct ifreq *ifr,
                              int cmd)
{
    struct exabond_master *master;
    struct net_device *slave_dev;
    int ret;

    master = exabond_ifaces_find_by_name(netdev_name(dev));
    if (master == NULL)
    {
        WARN(1, "%s: bonding master has had "
             "its ndo_[add|del]_slave methods replaced by this "
             "driver, yet this driver does not believe that it is "
             "currently managing master %s.\n",
             netdev_name(dev), netdev_name(dev));

        return -ENODEV;
    }

    ret = __exabond_ndo_ioctl_get_slave_arg(dev, ifr,
                                            &slave_dev);

    if (ret != 0)
        return ret;

    /* Although the stock `bonding` driver allows you to enslave
     * a bonding master to another bonding master, we don't permit
     * that in exabond.
     *
     * The reason is that we don't currently have a way to represent
     * nested group membership in the groupinfo right now.
     */
    if (exabond_netif_is_bond_master(slave_dev))
    {
        pr_warn("%s: Attempting to add new slave "
                "%s which is itself another bonding master.\n",
                netdev_name(dev), netdev_name(slave_dev));

        return -EINVAL;
    }

    /* Ensure that the new slave is also an exanic. */
    if (!exasock_is_exanic_dev(slave_dev))
    {
        pr_warn("%s: Attempting to add new slave "
                "%s which is not an exanic device.\n",
                netdev_name(dev), netdev_name(slave_dev));

        return -ENODEV;
    }

    /* If there was originally no entry point, just return unsupported */
    if (!master->orig_netdev_ops->ndo_do_ioctl)
        return -EOPNOTSUPP;

    /* Grab the group membership lock to ensure that no other slave can
     * be added to the group while we are waiting for ndo_add_slave to
     * finish.
     */
    mutex_lock(&master->mutex);

    /* ndo_do_ioctl(SIOCBONDENSLAVE) checks for duplicate slave
     * addition so we don't have to.
     */
    ret = master->orig_netdev_ops->ndo_do_ioctl(dev, ifr, cmd);
    if (ret != 0)
    {
        mutex_unlock(&master->mutex);
        return ret;
    }

    exabond_master_groupinfo_update(master);
    mutex_unlock(&master->mutex);

    pr_info("%s: Successfully added new slave %s.\n",
            netdev_name(dev), ifr->ifr_slave);

    return 0;
}

int
exabond_ndo_sioc_bond_release(struct net_device *dev,
                              struct ifreq *ifr,
                              int cmd)
{
    struct exabond_master *master;
    int ret;

    master = exabond_ifaces_find_by_name(netdev_name(dev));
    if (master == NULL)
    {
        WARN(1, "Bug: bonding master %s has had "
             "its ndo_[add|del]_slave methods replaced by this "
             "driver, yet this driver does not believe that it is "
             "currently managing master %s.\n",
             netdev_name(dev), netdev_name(dev));

        return -ENODEV;
    }

    if (!master->orig_netdev_ops->ndo_do_ioctl)
        return -EOPNOTSUPP;

    mutex_lock(&master->mutex);

    ret = master->orig_netdev_ops->ndo_do_ioctl(dev, ifr, cmd);
    if (ret != 0)
    {
        mutex_unlock(&master->mutex);
        return ret;
    }

    exabond_master_groupinfo_update(master);
    mutex_unlock(&master->mutex);

    pr_info("%s: Successfully removed slave %s.\n",
            netdev_name(dev), ifr->ifr_slave);

    return 0;
}

/** Intercepts SIOC?HWTSTAMP commands sent on a bonding master and relays
 * them to the underlying child devices.
 */
static int
exabond_ndo_sioc_hwtstamp(struct net_device *master_dev, struct ifreq *ifr, int cmd)
{
    struct bonding *bonding_master;
    struct slave *cur_slave;
    struct list_head *slave_iter;
    int ret, err;

    bonding_master = netdev_priv(master_dev);

    if (cmd != SIOCSHWTSTAMP)
    {
        pr_err("%s: got into %s with invalid command %d.\n",
               netdev_name(master_dev), __func__, cmd);
        BUG();
    }

    ret = 0;

    bonding_master_list_lock(bonding_master);

    /* Loop through and apply the ioctl parameters to each device
     * in the bond.
     */
    exabond_bond_for_each_slave(bonding_master, cur_slave, slave_iter)
    {
        if (!cur_slave->dev->netdev_ops || !cur_slave->dev->netdev_ops->ndo_do_ioctl)
        {
            ret = -ENOTSUPP;
            continue;
        }

        err = cur_slave->dev->netdev_ops->ndo_do_ioctl(cur_slave->dev, ifr, cmd);
        if (err != 0)
        {
            pr_err("%s: Failed to apply ioctl(cmd=%d) to child dev %s\n",
                   netdev_name(master_dev), cmd, netdev_name(cur_slave->dev));

            ret = err;
        }
    }

    bonding_master_list_unlock(bonding_master);
    return ret;
}

int
exabond_ndo_do_ioctl(struct net_device *bond_dev,
                     struct ifreq *ifr, int cmd)
{
    int res;
    struct exabond_master *m;

    switch (cmd)
    {
    case BOND_ENSLAVE_OLD:
    case SIOCBONDENSLAVE:
        res = exabond_ndo_sioc_bond_enslave(bond_dev, ifr, cmd);
        break;

    case BOND_RELEASE_OLD:
    case SIOCBONDRELEASE:
        res = exabond_ndo_sioc_bond_release(bond_dev, ifr, cmd);
        break;

    case SIOCSHWTSTAMP:
        res = exabond_ndo_sioc_hwtstamp(bond_dev, ifr, cmd);
        break;

    default:
        m = exabond_ifaces_find_by_name(netdev_name(bond_dev));
        if (m == NULL)
        {
            WARN(1, "Bug in exabond_do_ioctl: "
                 "net_device_ops.do_ioctl invoked for a bonding "
                 "master (%s) which is not known to the exabond "
                 "driver.\n",
                 netdev_name(bond_dev));

            res = -ENODEV;
            break;
        }

        if (m->orig_netdev_ops->ndo_do_ioctl == NULL)
        {
            res = -EOPNOTSUPP;
            break;
        }

        res = m->orig_netdev_ops->ndo_do_ioctl(bond_dev, ifr, cmd);
        break;
    }

    return res;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
static int
exabond_ndo_add_slave(struct net_device *dev,
                      struct net_device *slave_dev
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
                      , struct netlink_ext_ack *extack
#endif
                      )
{
    struct ifreq ifr;

    strcpy(ifr.ifr_slave, netdev_name(slave_dev));
    return exabond_ndo_sioc_bond_enslave(dev, &ifr,
                                         SIOCBONDENSLAVE);
}

static int
exabond_ndo_del_slave(struct net_device *dev,
                      struct net_device *slave_dev)
{
    struct ifreq ifr;

    strcpy(ifr.ifr_slave, netdev_name(slave_dev));
    return exabond_ndo_sioc_bond_release(dev, &ifr,
                                         SIOCBONDRELEASE);
}
#endif

static const struct attribute_group **
exabond_netdev_find_attribute_group(struct net_device *nd,
                                    const char *name)
{
    const struct attribute_group **groups;
    int i = 0;

    groups = nd->dev.groups;

    if (groups == NULL || *groups == NULL)
    {
        pr_warn("Dev %s has no groups\n", netdev_name(nd));
        return NULL;
    }

    for (i = 0; groups[i]; i++)
    {
        if (groups[i]->name == NULL)
            continue;

        if (strcmp(groups[i]->name, name) == 0)
            return &groups[i];
    }

    return NULL;
}

static struct attribute **
exabond_netdev_find_attribute(const struct attribute_group *grp,
                              const char *name)
{
    int i;

    if (grp->attrs == NULL)
        return NULL;

    for (i = 0; grp->attrs[i]; i++)
    {
        if (grp->attrs[i]->name == NULL)
            continue;

        if (strcmp(grp->attrs[i]->name, name) == 0)
            return &grp->attrs[i];
    }

    return NULL;
}

static bool
exabond_netdev_check_mode_is_active_backup(const struct net_device *ndev)
{
    struct bonding *bonding_master;

    bonding_master = netdev_priv(ndev);
    if (bonding_master->params.mode != BOND_MODE_ACTIVEBACKUP)
    {
        pr_err("%s: Please set the bond's mode to 'active-backup' "
               "(mode number=%d) before attempting to manage it with exabond.\n",
               netdev_name(ndev), BOND_MODE_ACTIVEBACKUP);

        return false;
    }

    return true;
}

static int
exabond_netdev_replace_one_sysfs_bonding_attr_store_method(const struct attribute_group *grp,
                                                           const char *attr_name,
                                                           sysfs_dev_attr_store_fn_t **orig_fn_ptr_storage,
                                                           sysfs_dev_attr_store_fn_t *new_fn_ptr)
{
    struct attribute **attr;
    struct device_attribute *devattr;
    unsigned long irqf;
    bool performed_replace = false;

    /* Next find the desired attribute within the group. This is the
     * attribute whose "store()" method we have to replace with our own
     * wrapper.
     */
    attr = exabond_netdev_find_attribute(grp, attr_name);
    if (attr == NULL)
        return -1;

    devattr = to_dev_attr(*attr);

    spin_lock_irqsave(&exabond.lock, irqf);

    WARN((devattr->store != new_fn_ptr && *orig_fn_ptr_storage != NULL),
         "bonding driver's sysfs ops for attribute "
         "'%s' have not been replaced by this driver, yet orig_sysfs ops "
         "is not NULL.\n",
         attr_name);

    WARN((devattr->store == new_fn_ptr && *orig_fn_ptr_storage == NULL),
         "bonding driver's sysfs ops for attribute "
         "'%s' have indeed been replaced by this driver, yet original "
         "ops have not been preserved for restoration.\n",
         attr_name);

    if (devattr->store != new_fn_ptr)
    {
        /* Only replace if it hasn't been replaced already. */
        performed_replace = true;
        *orig_fn_ptr_storage = devattr->store;
        devattr->store = new_fn_ptr;
    }

    spin_unlock_irqrestore(&exabond.lock, irqf);

    if (performed_replace)
        pr_info("Replaced bonding driver sysfs "
                "ops for attribute '%s'.\n",
                attr_name);

    return 0;
}

static int
exabond_netdev_restore_one_sysfs_bonding_attr_store_method(const struct attribute_group *grp,
                                                           const char *attr_name,
                                                           sysfs_dev_attr_store_fn_t **orig_fn_ptr_storage,
                                                           sysfs_dev_attr_store_fn_t *our_replacement_fn)
{
    struct attribute **attr;
    struct device_attribute *devattr;
    bool performed_restore = false;

    attr = exabond_netdev_find_attribute(grp, attr_name);
    if (attr == NULL)
        return -1;

    /* Restore the function pointer to what it was before. */
    devattr = to_dev_attr(*attr);

    BUG_ON(!spin_is_locked(&exabond.lock));

    /* Only restore if there are no more masters being managed by this
     * driver.
     */
    if (list_empty(&exabond.ifaces))
    {
        if (*orig_fn_ptr_storage == NULL)
        {
            WARN(1, "Original copy of bonding "
                 "driver's ops for attr '%s' not saved for restoration!\n",
                 attr_name);

            WARN(devattr->store == our_replacement_fn,
                 "Bonding driver's sysfs ops for attr '%s' remain "
                 "pointing to our wrappers, "
                 "but we have no saved copy of the original bonding "
                 "driver ops. Would recommend unloading and "
                 "reloading the bonding driver.\n",
                 attr_name);
        }
        else
        {
            performed_restore = true;
            devattr->store = *orig_fn_ptr_storage;
            *orig_fn_ptr_storage = NULL;
        }
    }

    if (performed_restore)
        pr_info("Restored original bonding driver sysfs ops "
                "for attribute '%s'.\n",
                attr_name);

    return 0;
}

static int
exabond_netdev_replace_sysfs_bonding_attr_store_methods(
                                                        struct exabond_master *m)
{
    const struct attribute_group **grp;
    int ret;

    /* Explanation:
     *
     * The reason why we have to replace these specific sysfs attributes which
     * are exported by the `bonding` driver is that when these particular
     * attributes are changed, the bonding driver internally calls
     * `bond_select_active_slave()`, which may result in the active slave
     * being changed.
     *
     * For that reason we need to trap changes to these attributes so we can
     * be alerted when the active slave in the bond has potentially been
     * changed, so that we can update the groupinfo that we export to
     * userspace via mmap.
     */

    /* First find the "bonding" attribute group subfolder exported to sysfs
     * by the bonding driver.
     */
    grp = exabond_netdev_find_attribute_group(m->net_device, "bonding");
    if (grp == NULL)
        return -1;

    ret = exabond_netdev_replace_one_sysfs_bonding_attr_store_method(*grp,
                                           "mode",
                                            &exabond.orig_sysfs_attr_mode_store,
                                            exabond_sysfs_devattr_mode_store);
    if (ret != 0)
        goto err_replace_mode;

    ret = exabond_netdev_replace_one_sysfs_bonding_attr_store_method(*grp,
                                           "slaves",
                                           &exabond.orig_sysfs_attr_slaves_store,
                                           exabond_sysfs_devattr_slaves_store);
    if (ret != 0)
        goto err_replace_slaves;

    ret = exabond_netdev_replace_one_sysfs_bonding_attr_store_method(*grp,
                                           "active_slave",
                                           &exabond.orig_sysfs_attr_active_slave_store,
                                           exabond_sysfs_devattr_active_slave_store);
    if (ret != 0)
        goto err_replace_active_slave;

    ret = exabond_netdev_replace_one_sysfs_bonding_attr_store_method(*grp,
                                           "primary",
                                           &exabond.orig_sysfs_attr_primary_store,
                                           exabond_sysfs_devattr_primary_store);
    if (ret != 0)
        goto err_replace_primary;

    ret = exabond_netdev_replace_one_sysfs_bonding_attr_store_method(*grp,
                                           "primary_reselect",
                                           &exabond.orig_sysfs_attr_primary_reselect_store,
                                           exabond_sysfs_devattr_primary_reselect_store);
    if (ret != 0)
        goto err_replace_primary_reselect;

    return 0;

err_replace_primary_reselect:
    exabond_netdev_restore_one_sysfs_bonding_attr_store_method(*grp,
                                     "primary",
                                     &exabond.orig_sysfs_attr_primary_store,
                                     exabond_sysfs_devattr_primary_store);
err_replace_primary:
    exabond_netdev_restore_one_sysfs_bonding_attr_store_method(*grp,
                                     "active_slave",
                                     &exabond.orig_sysfs_attr_active_slave_store,
                                     exabond_sysfs_devattr_active_slave_store);
err_replace_active_slave:
    exabond_netdev_restore_one_sysfs_bonding_attr_store_method(*grp,
                                     "slaves",
                                     &exabond.orig_sysfs_attr_slaves_store,
                                     exabond_sysfs_devattr_slaves_store);
err_replace_slaves:
    exabond_netdev_restore_one_sysfs_bonding_attr_store_method(*grp,
                                     "mode",
                                     &exabond.orig_sysfs_attr_mode_store,
                                     exabond_sysfs_devattr_mode_store);
err_replace_mode:
    return -1;
}

static int
exabond_netdev_restore_sysfs_bonding_attr_store_methods(struct exabond_master *m)
{
    const struct attribute_group **grp;
    int err;

    grp = exabond_netdev_find_attribute_group(m->net_device, "bonding");
    if (grp == NULL)
        return -1;

    err = exabond_netdev_restore_one_sysfs_bonding_attr_store_method(*grp, "mode",
                                     &exabond.orig_sysfs_attr_mode_store,
                                     exabond_sysfs_devattr_mode_store);
    WARN_ON(err != 0);
    err = exabond_netdev_restore_one_sysfs_bonding_attr_store_method(*grp, "slaves",
                                     &exabond.orig_sysfs_attr_slaves_store,
                                     exabond_sysfs_devattr_slaves_store);
    WARN_ON(err != 0);
    err = exabond_netdev_restore_one_sysfs_bonding_attr_store_method(*grp, "active_slave",
                                     &exabond.orig_sysfs_attr_active_slave_store,
                                     exabond_sysfs_devattr_active_slave_store);
    WARN_ON(err != 0);
    err = exabond_netdev_restore_one_sysfs_bonding_attr_store_method(*grp, "primary",
                                     &exabond.orig_sysfs_attr_primary_store,
                                     exabond_sysfs_devattr_primary_store);
    WARN_ON(err != 0);
    err = exabond_netdev_restore_one_sysfs_bonding_attr_store_method(*grp, "primary_reselect",
                                     &exabond.orig_sysfs_attr_primary_reselect_store,
                                     exabond_sysfs_devattr_primary_reselect_store);
    WARN_ON(err != 0);

    return 0;
}

static int
exabond_netdev_replace_ops(struct exabond_master *m,
                           struct net_device *nd)
{
    /* The `struct net_device_ops` pointed to by `nd->netdev_ops` is read
     * only and it exists inside one of the kernel's .rodata sections,
     * so if we try to surgically replace `ndo_add_slave`/`ndo_del_slave`
     * directly, we'll trigger a protection fault.
     *
     * We could decide to keep a statically filled out
     * `struct net_device_ops` of our own, but then what if the
     * `net_device_ops` of different `nd` devices passed to us are
     * different?
     *
     * So we have to have a copy per bonding master.
     */
    if (exabond_netdev_replace_sysfs_bonding_attr_store_methods(m) != 0)
    {
        pr_err("master %s: Failed to replace "
               "sysfs device ops. The bonding.ko driver or the Linux "
               "netdev_ops has changed enough to make this function need "
               "updating. Please email Exablaze with a kernel log dump "
               "if you see this message.\n",
               netdev_name(m->net_device));

        return -1;
    }

    /* Save pointer to old netdev_ops and rtnl_link_ops */
    m->orig_netdev_ops = nd->netdev_ops;
    m->orig_rtnl_link_ops = nd->rtnl_link_ops;

    memcpy(&m->exabond_netdev_ops, nd->netdev_ops, sizeof(*nd->netdev_ops));
    memcpy(&m->exabond_rtnl_link_ops,
           nd->rtnl_link_ops, sizeof(*nd->rtnl_link_ops));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
    m->exabond_netdev_ops.ndo_add_slave = exabond_ndo_add_slave;
    m->exabond_netdev_ops.ndo_del_slave = exabond_ndo_del_slave;
#endif
    m->exabond_netdev_ops.ndo_do_ioctl = exabond_ndo_do_ioctl;

    m->exabond_rtnl_link_ops.changelink = exabond_rtnl_changelink;

    nd->netdev_ops = &m->exabond_netdev_ops;
    nd->rtnl_link_ops = &m->exabond_rtnl_link_ops;
    return 0;
}

static int
exabond_netdev_restore_ops(struct exabond_master *m,
                           struct net_device *nd)
{
    if (exabond_netdev_restore_sysfs_bonding_attr_store_methods(m) != 0)
    {
        pr_err("master %s: Failed to restore "
               "sysfs device ops.\n",
               netdev_name(m->net_device));

        return -1;
    }

    nd->netdev_ops = m->orig_netdev_ops;
    nd->rtnl_link_ops = m->orig_rtnl_link_ops;
    return 0;
}

/* This will atomically allocate, construct and add a bonding iface to the list
 * of managed ifaces.
 */
static struct exabond_master *
exabond_ifaces_list_alloc_and_construct_new_if_not_exists(
                                                          const char *iface_name,
                                                          struct net_device *ndev,
                                                          bool *already_existed)
{
    struct exabond_master *newobj, *res;
    unsigned long irqf;

    BUG_ON(already_existed == NULL);

    *already_existed = false;

    /* Preliminary check -- we might be able to avoid the kmalloc+vmalloc
     * calls if the iface is already managed.
     */
    res = exabond_ifaces_find_by_name(iface_name);
    if (res != NULL)
    {
        *already_existed = true;
        return res;
    }

    newobj = kmalloc(sizeof(*newobj), GFP_KERNEL);
    if (newobj == NULL)
        return NULL;

    if (exabond_master_init(newobj, ndev) != 0)
        goto out_kfree;

    spin_lock_irqsave(&exabond.lock, irqf);

    res = __exabond_ifaces_find_by_name(iface_name);
    if (res == NULL)
        list_add_tail(&newobj->sibling_ifaces, &exabond.ifaces);

    spin_unlock_irqrestore(&exabond.lock, irqf);

    if (res != NULL)
    {
        *already_existed = true;
        exabond_master_destroy(newobj);
        kfree(newobj);
        return res;
    }

    return newobj;

out_kfree:
    kfree(newobj);
    return NULL;
}

struct exabond_master *
exabond_ifaces_begin_managing(const char *iface_name,
                              bool *already_managed)
{
    struct exabond_master *master;
    struct net_device *ndev;
    char first_non_exanic_iface_name[IFNAMSIZ];
    int err;

    if (!dev_valid_name(iface_name))
    {
        pr_err("Invalid iface name %s.\n",
               iface_name);

        return NULL;
    }

    // Is the net_device known to NAPI?
    ndev = dev_get_by_name(&init_net, iface_name);
    if (ndev == NULL)
    {
        pr_err("Iface %s not known to kernel "
               "NAPI (net namespaces other than init_net currently "
               "not supported)\n",
               iface_name);

        return NULL;
    }

    // Is the net_device a bonding device? And a master as well?
    if (!exabond_netif_is_bond_master(ndev))
    {
        pr_err("Iface %s is not a bonding master. Exabond can "
               "only bind to bonding masters.\n",
               iface_name);

        goto out_downref;
    }

    /* Since there's no externally exported, trivial function for setting the
     * `mode` of a bonding.ko master to `active-backup`, we just demand that the
     * user do it themselves.
     */
    if (!exabond_netdev_check_mode_is_active_backup(ndev))
    {
        pr_err("%s: Please ensure that the bonding device "
               "you're attempting to manage is in `active-backup` mode (=%d).\n",
               netdev_name(ndev), BOND_MODE_ACTIVEBACKUP);

        goto out_downref;
    }

    /* Finally, are all of the underlying net_devices inside of the bonding
     * group exanic devices? Exabond is only meant to manage bonding
     * groups of exanic devices.
     */
    if (!exabond_bond_all_children_are_exanics(netdev_priv(ndev),
                                               first_non_exanic_iface_name))
    {
        pr_err("Iface %s, which is a child of iface %s is not an "
               "exanic device. All children must be exanic devices.\n",
               first_non_exanic_iface_name, iface_name);

        goto out_downref;
    }

    master = exabond_ifaces_list_alloc_and_construct_new_if_not_exists(
                                                                       iface_name,
                                                                       ndev,
                                                                       already_managed);

    if (master == NULL)
    {
        pr_err("Failed to alloc and construct "
               "metadata to manage iface %s.\n",
               iface_name);

        goto out_downref;
    }

    if (*already_managed)
    {
        // Down the refcounter.
        dev_put(ndev);
        // Return the already-managed device.
        return master;
    }

    /* Create the device node so userspace can call mmap(). */
    err = exabond_master_dev_create(master);
    if (err != 0)
        goto out_stop_managing;

    err = exabond_netdev_replace_ops(master, ndev);
    if (err != 0)
        goto out_stop_managing;

    /* Write the group membership data into the shmem for the first time */
    mutex_lock(&master->mutex);
    exabond_master_groupinfo_update(master);
    mutex_unlock(&master->mutex);

    up_bonding_ko_ref_if_zero(&exabond);
    return master;

out_stop_managing:
    /* ifaces_stop_managing_and_destroy calls exabond_master_destroy
     * which already calls dev_put(), so don't fallthrough to
     * out_downref.
     */
    exabond_ifaces_stop_managing_and_destroy(iface_name);
    return NULL;

out_downref:
    dev_put(ndev);
    return NULL;
}

/* Atomically removes a bonding iface from the list, destroys it and then
 * kfree()s it.
 *
 * @return Returns bool true if "iface_name" was indeed under management.
 */
bool
exabond_ifaces_stop_managing_and_destroy(const char *iface_name)
{
    unsigned long irqf;
    struct exabond_master *master;

    if (!dev_valid_name(iface_name))
    {
        pr_err("Invalid iface name %s.\n", iface_name);
        return false;
    }

    spin_lock_irqsave(&exabond.lock, irqf);

    master = __exabond_ifaces_find_by_name(iface_name);
    BUG_ON(list_empty(&exabond.ifaces) && master != NULL);
    if (master == NULL)
    {
        spin_unlock_irqrestore(&exabond.lock, irqf);
        return false;
    }

    BUG_ON(list_empty(&exabond.ifaces));
    __exabond_ifaces_list_remove(master);

    if (list_empty(&exabond.ifaces))
        down_bonding_ko_ref_if_nonzero(&exabond);

    exabond_netdev_restore_ops(master, master->net_device);
    spin_unlock_irqrestore(&exabond.lock, irqf);

    exabond_master_dev_destroy(master);
    exabond_master_destroy(master);
    kfree(master);

    return master != NULL;
}

static void
exabond_ifaces_stop_managing_and_destroy_all(void)
{
    struct exabond_master *cur, *deltmp;
    unsigned long irqf;
    /* temporary list to hold the items until they're deleted. */
    struct list_head dellist = LIST_HEAD_INIT(dellist);

    spin_lock_irqsave(&exabond.lock, irqf);

    list_for_each_entry_safe(cur, deltmp, &exabond.ifaces, sibling_ifaces)
    {
        __exabond_ifaces_list_remove(cur);
        exabond_netdev_restore_ops(cur, cur->net_device);
        list_add_tail(&cur->sibling_ifaces, &dellist);
    }

    down_bonding_ko_ref_if_nonzero(&exabond);

    spin_unlock_irqrestore(&exabond.lock, irqf);

    BUG_ON(!list_empty(&exabond.ifaces));
    /* Now destroy each item safely outside the critical section. */
    list_for_each_entry_safe(cur, deltmp, &dellist, sibling_ifaces)
    {
        pr_info("No longer managing bond %s\n",
                netdev_name(cur->net_device));

        list_del(&cur->sibling_ifaces);

        exabond_master_dev_destroy(cur);
        exabond_master_destroy(cur);
        kfree(cur);
    }
}

int
exabond_master_init(struct exabond_master *m, struct net_device *nd)
{
    int ret;

    BUG_ON(nd == NULL);

    memset(m, 0, sizeof(*m));

    m->groupinfo = vmalloc_user(PAGE_SIZE);
    if (m->groupinfo == NULL)
        return -ENOMEM;

    ret = exabond_master_groupinfo_init(m->groupinfo);
    if (ret != 0)
        goto out_vfree;

    mutex_init(&m->mutex);
    INIT_LIST_HEAD(&m->sibling_ifaces);
    m->net_device = nd;

    exabond_master_monitor_init(m);
    return 0;

out_vfree:
    vfree(m->groupinfo);
    return ret;
}

void
exabond_master_destroy(struct exabond_master *m)
{
    BUG_ON(m == NULL || m->net_device == NULL);

    exabond_master_monitor_destroy(m);

    dev_put(m->net_device);
    m->net_device = NULL;
    exabond_master_groupinfo_destroy(m->groupinfo);
    vfree(m->groupinfo);
    m->groupinfo = NULL;
}

int
exabond_init(struct exabond_info *e)
{
    int err;

    spin_lock_init(&e->lock);
    INIT_LIST_HEAD(&e->ifaces);

    err = exabond_sysfs_init(e);
    if (err)
    {
        pr_err("Failed to init sysfs state.\n");
        return err;
    }

    return 0;
}

void
exabond_destroy(struct exabond_info *e)
{
    /* Stop sysfs first so no new devices can be added. */
    exabond_sysfs_destroy(e);
    /* Then destruct all devices managed by the module. */
    exabond_ifaces_stop_managing_and_destroy_all();
}
