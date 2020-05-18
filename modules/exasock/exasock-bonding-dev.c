/**
 * ExaNIC Link Aggregation driver
 * Copyright (C) 2011-2020 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) "exasock-bonding: " fmt

#include <linux/bug.h>
#include <linux/if_ether.h>
#include <linux/vmalloc.h>
#include <linux/atomic.h>
#include <net/bonding.h>

/* older versions of net/bonding.h exported DRV_VERSION/DRV_NAME
 * which conflict with those in exanic.h */
#undef DRV_VERSION
#undef DRV_NAME

#include "../exanic/exanic.h"
#include "exasock-bonding-priv.h"

static struct exabond_master *
get_fileptr_privdata(struct file *filep)
{
    struct miscdevice *miscdev;

    /* The miscdevice driver places a pointer to the `struct miscdevice`
     * that we passed as an argument to `misc_register`, into the
     * `private_data` member of the `struct file` that is passed to it when
     * open() is called on that device (see misc_open() in linux source).
     *
     * So in order to get a pointer to our exabond_master object, we can
     * just use container_of().
     */
    miscdev = (struct miscdevice *)filep->private_data;
    return container_of(miscdev, struct exabond_master, miscdev);
}

static int
exabond_master_dev_open(struct inode *inode, struct file *filp)
{
    struct exabond_master *supplied_master, *searched_master;

    supplied_master = get_fileptr_privdata(filp);
    searched_master = exabond_ifaces_find_by_major_minor(imajor(inode),
                                                         iminor(inode));

    return (supplied_master == searched_master) ? 0 : -ENODATA;
}

static int
exabond_master_dev_close(struct inode *inode, struct file *filp)
{
    return 0;
}

static int
exabond_master_dev_mmap(struct file *filp,
                        struct vm_area_struct *vma)
{
    const size_t mapping_sz = vma->vm_end - vma->vm_start;
    int ret;
    struct exabond_master *master;

    master = get_fileptr_privdata(filp);

    if (vma->vm_flags & (VM_WRITE | VM_EXEC))
        return -EACCES;

    if (mapping_sz != PAGE_SIZE)
    {
        pr_err("Requested mapping size must be "
               "exactly %lu.\n",
               PAGE_SIZE);

        return -EINVAL;
    }

    if (!IS_ALIGNED(vma->vm_start, PAGE_SIZE))
    {
        pr_err("Requested mapping must begin on "
               "a page boundary\n");

        return -EINVAL;
    }

    ret = remap_vmalloc_range(vma, master->groupinfo, 0);
    if (ret != 0)
    {
        pr_err("Failed to share groupinfo for "
               "%s via mmap.\n",
               netdev_name(master->net_device));

        return -ENOMEM;
    }

    return 0;
}

struct file_operations exabond_dev_fops = {
    .owner = THIS_MODULE,
    .open = exabond_master_dev_open,
    .release = exabond_master_dev_close,
    .mmap = exabond_master_dev_mmap
};

/** Compares the current stale state of the groupinfo against the internal
 * state of the bonding.ko driver to see if we need to update the groupinfo.
 */
bool
exabond_master_groupinfo_flags_have_changed(struct exabond_master *m)
{
    bool had_active;
    struct slave *slave;
    struct bonding *bonding_drv_master;
    int exa_id, exa_port;

    bonding_drv_master = netdev_priv(m->net_device);

    had_active = !!(m->groupinfo->active_slave_id.typed.flags
                    & EXABOND_GRPINFO_FLAG_ACTIVE);

    slave = rtnl_dereference(bonding_drv_master->curr_active_slave);

    /* If an active slave has been chosen when one hadn't been before, OR
     * an active slave had been chosen before when one doesn't exist now,
     * return true;
     */
    if ((slave != NULL && !had_active) || (slave == NULL && had_active))
        return true;

    /* If an active slave has been chosen, but it's not the same as the previous,
     * return true;
     */
    if (had_active && slave)
    {
        exanic_netdev_get_id_and_port(slave->dev, &exa_id, &exa_port);
        if (!exabond_groupinfo_active_id_and_port_eq(m->groupinfo, exa_id, exa_port))
            return true;
    }

    return false;
}

/* Composes and returns a uint32_t which is formatted in the layout that
 * userspace expects to find in the groupinfo as an atomic uint32_t.
 * @return groupinfo value to be atomically placed into the groupinfo
 *         for reading by userspace.
 */
void
exabond_master_groupinfo_update(struct exabond_master *m)
{
    struct slave *active_slave;
    struct bonding *bonding_drv_master;
    int exa_id, exa_port;
    struct exabond_master_groupinfo newval;

    bonding_drv_master = netdev_priv(m->net_device);

    /* Clear the flags, but also preserve the previous active slave ID if
     * there was one.
     */
    newval.active_slave_id.raw = m->groupinfo->active_slave_id.raw;
    newval.active_slave_id.typed.flags = 0;

    /* It's possible for curr_active_slave to be NULL. */
    active_slave = rtnl_dereference(bonding_drv_master->curr_active_slave);
    if (active_slave)
    {
        exanic_netdev_get_id_and_port(active_slave->dev, &exa_id, &exa_port);
        newval.active_slave_id.typed.exanic_id = exa_id;
        newval.active_slave_id.typed.exanic_port = exa_port;
        newval.active_slave_id.typed.flags |= EXABOND_GRPINFO_FLAG_ACTIVE;
    }

    atomic_set((atomic_t *)&m->groupinfo->active_slave_id.raw,
               newval.active_slave_id.raw);
}

int
exabond_master_groupinfo_init(struct exabond_master_groupinfo *g)
{
    BUG_ON(sizeof(atomic_t) < sizeof(struct exabond_slave_exanic_id));

    memset(g, 0, sizeof(*g));
    return 0;
}

void
exabond_master_groupinfo_destroy(struct exabond_master_groupinfo *g)
{
    g->active_slave_id.raw = 0;
}

int
exabond_master_dev_create(struct exabond_master *m)
{
    int err;
    struct miscdevice tmp = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = m->devname,
        .fops = &exabond_dev_fops
    };

    snprintf(m->devname, EXABOND_DEV_NAME_SZ, "%s-%s",
             THISMOD_NAME_STRING, netdev_name(m->net_device));

    m->miscdev = tmp;

    err = misc_register(&m->miscdev);
    if (err != 0)
        return err;

    pr_info("%s: Major %d, Minor %d, devname %s.\n",
            netdev_name(m->net_device),
            MAJOR(m->miscdev.this_device->devt), m->miscdev.minor,
            m->devname);

    return 0;
}

void
exabond_master_dev_destroy(struct exabond_master *m)
{
    misc_deregister(&m->miscdev);
}
