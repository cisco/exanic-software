/**
 * ExaNIC driver
 * Copyright (C) 2011-2013 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/etherdevice.h>
#include <linux/limits.h>
#include <linux/vmalloc.h>

#include "../../libs/exanic/pcie_if.h"
#include "../../libs/exanic/fifo_if.h"
#include "../../libs/exanic/ioctl.h"
#include "exanic.h"
#include "exanic-structs.h"

/**
 * Handles /dev/exanic open().
 */
static int exanic_open(struct inode *inode, struct file *filp)
{
    struct exanic *exanic;
    struct exanic_ctx *ctx;

    exanic = exanic_find_by_minor(iminor(inode));
    if (exanic == NULL)
    {
        pr_err("Failed to locate exanic for minor = %u.\n", iminor(inode));
        return -ENODEV;
    }

    mutex_lock(&exanic->mutex);
    ctx = exanic_alloc_ctx(exanic);
    mutex_unlock(&exanic->mutex);
    if (ctx == NULL)
    {
        dev_err(&exanic->pci_dev->dev, DRV_NAME
            "%u: Failed to allocate exanic_ctx.\n", exanic->id);
        return -ENOMEM;
    }

    filp->private_data = ctx;
    return 0;
}

/**
 * Handles /dev/exanic close().
 */
static int exanic_release(struct inode *inode, struct file *filp)
{
    struct exanic_ctx *ctx = filp->private_data;
    struct exanic *exanic = ctx->exanic;

    mutex_lock(&exanic->mutex);
    exanic_free_ctx(ctx);
    mutex_unlock(&exanic->mutex);

    return 0;
}

/**
 * Maps the ExaNIC registers.
 */
static int exanic_map_registers(struct exanic *exanic, struct vm_area_struct *vma)
{
    int err;
    struct device *dev = &exanic->pci_dev->dev;
    size_t map_size = vma->vm_end - vma->vm_start;

    /* Size check */
    if (map_size > exanic->regs_size)
    {
        dev_err(dev, DRV_NAME
            "%u: Tried to map registers region with wrong size %lu "
            "(expected <=%zu).\n", exanic->id, vma->vm_end - vma->vm_start,
            exanic->regs_size);
        return -EINVAL;
    }

    /* Do the mapping */
    err = remap_pfn_range(vma, vma->vm_start,
            exanic->regs_phys >> PAGE_SHIFT, map_size,
            pgprot_noncached(vma->vm_page_prot));
    if (err)
    {
        dev_err(dev, DRV_NAME
            "%u: remap_pfn_range failed for registers region.\n", exanic->id);
    }
    else
    {
        dev_dbg(dev, DRV_NAME
            "%u: Mapped registers region at phys: 0x%pap, virt: 0x%p.\n",
            exanic->id, &exanic->regs_phys, (void *)vma->vm_start);
    }

    return err;
}

/**
 * Map the devkit register region.
 */
static int exanic_map_devkit_regs(struct exanic *exanic,
                                  struct vm_area_struct *vma, bool extended)
{
    int err;
    struct device *dev = &exanic->pci_dev->dev;
    size_t map_size = vma->vm_end - vma->vm_start;

    phys_addr_t phys_addr = extended ? exanic->devkit_regs_ex_phys :
                                       exanic->devkit_regs_phys;
    size_t resource_size = extended ? exanic->devkit_regs_ex_size :
                                      exanic->devkit_regs_size;

    if (map_size > resource_size)
    {
        dev_err(dev, DRV_NAME
            "%u: Tried to map %sdevkit regs with wrong size %lu "
            "(expected <=%zu).\n",
            exanic->id, extended ? "extended " : "",
            vma->vm_end - vma->vm_start,
            resource_size);
        return -EINVAL;
    }

    /* Do the mapping */
    err = remap_pfn_range(vma, vma->vm_start,
            phys_addr >> PAGE_SHIFT, map_size,
            pgprot_noncached(vma->vm_page_prot));
    if (err)
    {
        dev_err(dev, DRV_NAME
            "%u: remap_pfn_range failed for %sdevkit regs.\n",
            exanic->id, extended ? "extended " : "");
    }
    else
    {
        dev_dbg(dev, DRV_NAME
            "%u: Mapped %sdevkit regs at phys: 0x%pap, virt: 0x%p.\n",
            exanic->id, extended ? "extended " : "",
            &phys_addr, (void *)vma->vm_start);
    }

    return err;
}

/**
 * Map the devkit memory region.
 */
static int exanic_map_devkit_mem(struct exanic *exanic,
                                 struct vm_area_struct *vma, bool extended)
{
    int err;
    struct device *dev = &exanic->pci_dev->dev;
    size_t map_size = vma->vm_end - vma->vm_start;

    phys_addr_t phys_addr = extended ? exanic->devkit_mem_ex_phys :
                                       exanic->devkit_mem_phys;
    size_t resource_size = extended ? exanic->devkit_mem_ex_size :
                                      exanic->devkit_mem_size;

    if (map_size > resource_size)
    {
        dev_err(dev, DRV_NAME
            "%u: Tried to map %sdevkit mem with wrong size %lu "
            "(expected <=%zu).\n",
            exanic->id, extended ? "extended " : "",
            vma->vm_end - vma->vm_start,
            resource_size);
        return -EINVAL;
    }

    /* Do the mapping */
    err = remap_pfn_range(vma, vma->vm_start,
            phys_addr >> PAGE_SHIFT, map_size,
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
            pgprot_writecombine(vma->vm_page_prot)
  #else
            pgprot_noncached(vma->vm_page_prot)
  #endif
          );
    if (err)
    {
        dev_err(dev, DRV_NAME
            "%u: remap_pfn_range failed for %sdevkit mem.\n",
            exanic->id, extended ? "extended " : "");
    }
    else
    {
        dev_dbg(dev, DRV_NAME
            "%u: Mapped %sdevkit mem at phys: 0x%pap, virt: 0x%p.\n",
            exanic->id, extended ? "extended " : "",
            &phys_addr, (void *)vma->vm_start);
    }

    return err;
}

static int exanic_map_info(struct exanic *exanic, struct vm_area_struct *vma)
{
    int err;
    struct device *dev = &exanic->pci_dev->dev;
    size_t map_size = vma->vm_end - vma->vm_start;

    if (!exanic->info_page) /* no info page allocated (e.g. unsupported card) */
        return -EINVAL;

    if (vma->vm_flags & VM_WRITE)
        return -EACCES;

    if (map_size > (EXANIC_INFO_NUM_PAGES * PAGE_SIZE))
    {
        dev_err(dev, DRV_NAME
            "%u: Tried to map info page with wrong size %zu "
            "(expected <=%u).\n", exanic->id, map_size, EXANIC_INFO_NUM_PAGES);
        return -EINVAL;
    }

    err = remap_vmalloc_range(vma, exanic->info_page, 0);
    if (err)
    {
        dev_err(dev, DRV_NAME
            "%u: remap_vmalloc_range failed for info page.\n", exanic->id);
    }
    else
    {
        dev_dbg(dev, DRV_NAME
            "%u: Mapped info page at virt: 0x%p.\n", exanic->id,
            (void *)vma->vm_start);
    }

    return err;
}

static int exanic_map_filters(struct exanic *exanic, struct vm_area_struct *vma)
{
    int err;
    struct device *dev = &exanic->pci_dev->dev;
    size_t map_size = vma->vm_end - vma->vm_start;

    /* Size check */
    if (map_size > exanic->filters_size)
    {
        dev_err(dev, DRV_NAME
            "%u: Tried to map filters with wrong size %zu "
            "(expected <=%zu).\n", exanic->id, map_size, exanic->filters_size);
        return -EINVAL;
    }

    /* Do the mapping */
    err = remap_pfn_range(vma, vma->vm_start,
            exanic->filters_phys >> PAGE_SHIFT, map_size,
            pgprot_noncached(vma->vm_page_prot));
    if (err)
    {
        dev_err(dev, DRV_NAME
            "%u: remap_pfn_range failed for filters.\n", exanic->id);
    }
    else
    {
        dev_dbg(dev, DRV_NAME
            "%u: Mapped filters at phys: 0x%pap, virt: 0x%p.\n", exanic->id,
            &exanic->filters_phys, (void *)vma->vm_start);
    }

    return err;
}

static int exanic_map_tx_region(struct exanic *exanic, struct vm_area_struct *vma)
{
    int err;
    struct device *dev = &exanic->pci_dev->dev;
    size_t map_size = vma->vm_end - vma->vm_start;

    /* Size check */
    if (map_size > exanic->tx_region_size)
    {
        dev_err(dev, DRV_NAME
            "%u: Tried to map TX region with wrong size %zu "
            "(expected <=%zu).\n", exanic->id, map_size, exanic->tx_region_size);
        return -EINVAL;
    }

    /* Do the mapping */
    err = remap_pfn_range(vma, vma->vm_start,
            exanic->tx_region_phys >> PAGE_SHIFT, map_size,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
            pgprot_writecombine(vma->vm_page_prot)
#else
            pgprot_noncached(vma->vm_page_prot)
#endif
        );
    if (err)
    {
        dev_err(dev, DRV_NAME
            "%u: remap_pfn_range failed for TX region.\n", exanic->id);
    }
    else
    {
        dev_dbg(dev, DRV_NAME
            "%u: Mapped TX region at phys: 0x%pap, virt: 0x%p.\n", exanic->id,
            &exanic->tx_region_phys, (void *)vma->vm_start);
    }

    return err;
}

static int exanic_map_tx_feedback(struct exanic *exanic,
                                  struct vm_area_struct *vma)
{
    int err;
    struct device *dev = &exanic->pci_dev->dev;
    size_t map_size = vma->vm_end - vma->vm_start;
    size_t off;
    phys_addr_t phys_addr;

    /* Size check */
    if (map_size > (EXANIC_TX_FEEDBACK_NUM_PAGES * PAGE_SIZE))
    {
        dev_err(dev, DRV_NAME
            "%u: Tried to map TX feedback region with wrong size %zu "
            "(expected <=%lu).\n", exanic->id, map_size,
            EXANIC_TX_FEEDBACK_NUM_PAGES * PAGE_SIZE);
        return -EINVAL;
    }

    /* Do the mapping */
    for (off = 0; off < map_size; off += PAGE_SIZE)
    {
        err = vm_insert_page(vma, vma->vm_start + off,
                virt_to_page(exanic->tx_feedback_virt + off));
        if (err)
        {
            phys_addr = virt_to_phys(exanic->tx_feedback_virt + off);
            dev_err(dev, DRV_NAME
                "%u: vm_insert_page failed for TX feedback region "
                "at phys: 0x%pap, virt: 0x%p\n", exanic->id,
                &phys_addr, (void *)(vma->vm_start + off));
            return err;
        }
    }

    phys_addr = virt_to_phys(exanic->tx_feedback_virt);
    dev_dbg(dev, DRV_NAME
        "%u: Mapped TX feedback region at phys: 0x%pap, virt: 0x%p.\n",
        exanic->id, &phys_addr, (void *)vma->vm_start);

    return 0;
}

static int exanic_map_rx_region(struct exanic *exanic, struct vm_area_struct *vma,
                                unsigned port_num, unsigned buffer_num,
                                int check_numa_node)
{
    int err;
    struct device *dev = &exanic->pci_dev->dev;
    void *rx_region_virt;
    size_t map_size = vma->vm_end - vma->vm_start;
    size_t off;
    phys_addr_t phys_addr;

    if (buffer_num > 0)
    {
        rx_region_virt =
          exanic->port[port_num].filter_buffers[buffer_num - 1].region_virt;
    }
    else
    {
        rx_region_virt = exanic->port[port_num].rx_region_virt;
    }

    /* RX region can only be mapped read-only */
    if (vma->vm_flags & VM_WRITE)
        return -EACCES;

    /* Size check */
    if (map_size > (EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE))
    {
        dev_err(dev, DRV_NAME
            "%u: Tried to map RX region with wrong size %zu "
            "(expected <=%lu).\n", exanic->id, map_size,
            EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE);
        return -EINVAL;
    }

    /* Port number check */
    if (port_num >= exanic->num_ports)
    {
        dev_err(dev, DRV_NAME
            "%u: Tried to map RX region for unknown port %u\n", exanic->id,
            port_num);
        return -EINVAL;
    }

    /* Buffer number check. */
    if (buffer_num > exanic->max_filter_buffers)
    {
        dev_err(dev, DRV_NAME
            "%u: Tried to map RX region for unknown filter buffer %u\n",
            exanic->id, buffer_num - 1);
        return -EINVAL;
    }

    /* Check that RX region has been allocated */
    if (exanic->port[port_num].rx_region_virt == NULL)
    {
        dev_err(dev, DRV_NAME
            "%u: Tried to map RX region on disabled port %u\n", exanic->id,
            port_num);
        return -EINVAL;
    }

    /* Check that filter buffer has been allocated */
    if (buffer_num > 0)
    {
        if (exanic->port[port_num].filter_buffers[buffer_num - 1].region_virt
                == NULL)
        {
            dev_err(dev, DRV_NAME
                "%u: Tried to map RX region on disabled filter buffer %u\n",
                exanic->id, buffer_num - 1);
            return -EINVAL;
        }
    }

    /* Numa node check if required */
    if (check_numa_node &&
        ((buffer_num == 0 && exanic->port[port_num].numa_node !=
            numa_node_id()) ||
        (buffer_num > 0 &&
            exanic->port[port_num].filter_buffers[buffer_num - 1].numa_node
          != numa_node_id())))
    {
        dev_err(dev, DRV_NAME
            "%u: Tried to map RX region on wrong NUMA node.\n", exanic->id);
        return -EINVAL;
    }

    /* Do the mapping */
    for (off = 0; off < map_size; off += PAGE_SIZE)
    {
        err = vm_insert_page(vma, vma->vm_start + off,
                virt_to_page(rx_region_virt + off));
        if (err)
        {
            phys_addr = virt_to_phys(rx_region_virt + off);
            dev_err(dev, DRV_NAME
                "%u: vm_insert_page failed for RX region "
                "at phys: 0x%pap, virt: 0x%p\n", exanic->id,
                &phys_addr, (void *)(vma->vm_start + off));
            return err;
        }
    }

    phys_addr = virt_to_phys(rx_region_virt);
    dev_dbg(dev, DRV_NAME
        "%u: Mapped RX region at phys: 0x%pap, virt: 0x%p.\n", exanic->id,
        &phys_addr, (void *)vma->vm_start);

    return 0;
}

/**
 * Handles /dev/exanic mmap().
 */
static int exanic_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct exanic_ctx *ctx = filp->private_data;
    struct exanic *exanic = ctx->exanic;
    struct device *dev = &exanic->pci_dev->dev;
    unsigned port_num, buffer_num, offset;
    int ret;

    mutex_lock(&exanic->mutex);

    if (vma->vm_pgoff == EXANIC_PGOFF_REGISTERS)
        ret = exanic_map_registers(exanic, vma);
    else if (vma->vm_pgoff == EXANIC_PGOFF_INFO)
        ret = exanic_map_info(exanic, vma);
    else if (vma->vm_pgoff == EXANIC_PGOFF_FILTERS)
        ret = exanic_map_filters(exanic, vma);
    else if (vma->vm_pgoff == EXANIC_PGOFF_TX_REGION)
        ret = exanic_map_tx_region(exanic, vma);
    else if (vma->vm_pgoff == EXANIC_PGOFF_TX_FEEDBACK)
        ret = exanic_map_tx_feedback(exanic, vma);
    else if ((vma->vm_pgoff >= EXANIC_PGOFF_RX_REGION)
              && (vma->vm_pgoff < EXANIC_PGOFF_FILTER_REGION))
    {
        port_num = (vma->vm_pgoff - EXANIC_PGOFF_RX_REGION)
                                        / EXANIC_RX_DMA_NUM_PAGES;
        offset   = (vma->vm_pgoff - EXANIC_PGOFF_RX_REGION)
                                        % EXANIC_RX_DMA_NUM_PAGES;

        if ((port_num >= exanic->num_ports) || (offset != 0))
            goto err_invalid_offset;

        ret = exanic_map_rx_region(exanic, vma, port_num, 0,
                ctx->check_numa_node);
    }
    else if ((vma->vm_pgoff >= EXANIC_PGOFF_FILTER_REGION)
              && (vma->vm_pgoff < EXANIC_PGOFF_DEVKIT_REGS))
    {
        port_num  = (vma->vm_pgoff - EXANIC_PGOFF_FILTER_REGION)
                      / (exanic->max_filter_buffers * EXANIC_RX_DMA_NUM_PAGES);
        buffer_num = (vma->vm_pgoff - EXANIC_PGOFF_FILTER_REGION)
                             / EXANIC_RX_DMA_NUM_PAGES
                               - port_num * exanic->max_filter_buffers;
        offset     = (vma->vm_pgoff - EXANIC_PGOFF_FILTER_REGION)
                             % EXANIC_RX_DMA_NUM_PAGES;

        if ((port_num >= exanic->num_ports) || (offset != 0))
            goto err_invalid_offset;

        ret = exanic_map_rx_region(exanic, vma, port_num,
                           buffer_num+1, ctx->check_numa_node);
    }
    else if (vma->vm_pgoff == EXANIC_PGOFF_DEVKIT_REGS)
    {
        ret = exanic_map_devkit_regs(exanic, vma, false);
    }
    else if (vma->vm_pgoff == EXANIC_PGOFF_DEVKIT_MEM)
    {
        ret = exanic_map_devkit_mem(exanic, vma, false);
    }
    else if (vma->vm_pgoff >= EXANIC_PGOFF_TX_REGION_EXT &&
             vma->vm_pgoff < EXANIC_PGOFF_RX_REGION_EXT)
    {
        ret = exanic_map_tx_region(exanic, vma);
    }
    else if (vma->vm_pgoff >= EXANIC_PGOFF_RX_REGION_EXT &&
             vma->vm_pgoff < EXANIC_PGOFF_DEVKIT_REGS_EXT)
    {
        port_num = (vma->vm_pgoff - EXANIC_PGOFF_RX_REGION_EXT)
                                        / EXANIC_RX_DMA_NUM_PAGES;
        offset   = (vma->vm_pgoff - EXANIC_PGOFF_RX_REGION_EXT)
                                        % EXANIC_RX_DMA_NUM_PAGES;

        if ((port_num >= exanic->num_ports) || (offset != 0))
            goto err_invalid_offset;

        ret = exanic_map_rx_region(exanic, vma, port_num, 0,
                ctx->check_numa_node);
    }
    else if (vma->vm_pgoff == EXANIC_PGOFF_DEVKIT_REGS_EXT)
    {
        ret = exanic_map_devkit_regs(exanic, vma, true);
    }
    else if (vma->vm_pgoff == EXANIC_PGOFF_DEVKIT_MEM_EXT)
    {
        ret = exanic_map_devkit_mem(exanic, vma, true);
    }
    else
    {
        goto err_invalid_offset;
    }

    mutex_unlock(&exanic->mutex);
    return ret;

err_invalid_offset:
    mutex_unlock(&exanic->mutex);
    dev_err(dev, DRV_NAME
        "%u: Tried to map an unknown region at page offset %lu\n",
        exanic->id, vma->vm_pgoff);
    return -EINVAL;
}

/**
 * Handles /dev/exanic ioctl().
 */
static long exanic_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct exanic_ctx *ctx = filp->private_data;
    struct exanic *exanic = ctx->exanic;
    int ret;

    if (_IOC_TYPE(cmd) != EXANICCTL_TYPE)
        return -ENOTTY;

    switch (cmd)
    {
        case EXANICCTL_TX_BUFFER_ALLOC:
            {
                struct exanicctl_tx_buffer_alloc ctl;

                if (copy_from_user(&ctl, (void *)arg, sizeof(ctl)) != 0)
                    return -EFAULT;

                if (ctl.port_number >= exanic->num_ports)
                    return -EINVAL;

                if ((ctl.size & ~PAGE_MASK))
                    return -EINVAL;

                mutex_lock(&exanic->mutex);
                ret = exanic_alloc_tx_region(ctx, ctl.port_number, ctl.size,
                        &ctl.offset);
                mutex_unlock(&exanic->mutex);
                if (ret != 0)
                    return ret;

                if (copy_to_user((void *)arg, &ctl, sizeof(ctl)) != 0)
                    return -EFAULT;

                return 0;
            }

        case EXANICCTL_TX_BUFFER_FREE:
            {
                struct exanicctl_tx_buffer_free ctl;

                if (copy_from_user(&ctl, (void *)arg, sizeof(ctl)) != 0)
                    return -EFAULT;

                if (ctl.port_number >= exanic->num_ports)
                    return -EINVAL;

                if ((ctl.offset & ~PAGE_MASK) || (ctl.size & ~PAGE_MASK))
                    return -EINVAL;

                mutex_lock(&exanic->mutex);
                ret = exanic_free_tx_region(ctx, ctl.port_number, ctl.size,
                        ctl.offset);
                mutex_unlock(&exanic->mutex);
                return ret;
            }

        case EXANICCTL_TX_FEEDBACK_ALLOC:
            {
                struct exanicctl_tx_feedback_alloc ctl;

                if (copy_from_user(&ctl, (void *)arg, sizeof(ctl)) != 0)
                    return -EFAULT;

                if (ctl.port_number >= exanic->num_ports)
                    return -EINVAL;

                mutex_lock(&exanic->mutex);
                ret = exanic_alloc_tx_feedback(ctx, ctl.port_number,
                        &ctl.feedback_slot);
                mutex_unlock(&exanic->mutex);
                if (ret != 0)
                    return ret;

                if (copy_to_user((void *)arg, &ctl, sizeof(ctl)) != 0)
                    return -EFAULT;

                return 0;
            }

        case EXANICCTL_TX_FEEDBACK_FREE:
            {
                struct exanicctl_tx_feedback_free ctl;

                if (copy_from_user(&ctl, (void *)arg, sizeof(ctl)) != 0)
                    return -EFAULT;

                if (ctl.port_number >= exanic->num_ports ||
                        ctl.feedback_slot >= EXANIC_TX_FEEDBACK_NUM_SLOTS)
                    return -EINVAL;

                mutex_lock(&exanic->mutex);
                ret = exanic_free_tx_feedback(ctx, ctl.port_number,
                        ctl.feedback_slot);
                mutex_unlock(&exanic->mutex);
                return ret;
            }

        case EXANICCTL_INFO:
            {
                struct exanicctl_info ctl;
                int i;

                ctl.tx_buffer_size = exanic->tx_region_size;
                ctl.filters_size = exanic->filters_size;

                for (i = 0; i < 4; i++)
                {
                    if (exanic->ndev[i] == NULL)
                        ctl.if_index[i] = 0;
                    else
                        ctl.if_index[i] = exanic->ndev[i]->ifindex;
                }

                if (copy_to_user((void *)arg, &ctl, sizeof(ctl)) != 0)
                    return -EFAULT;

                return 0;
            }

        case EXANICCTL_INFO_EX:
            {
                struct exanicctl_info_ex ctl;
                int i;

                ctl.tx_buffer_size = exanic->tx_region_size;
                ctl.filters_size = exanic->filters_size;
                ctl.max_buffers = exanic->max_filter_buffers;

                for (i = 0; i < 4; i++)
                {
                    if (exanic->ndev[i] == NULL)
                        ctl.if_index[i] = 0;
                    else
                        ctl.if_index[i] = exanic->ndev[i]->ifindex;
                }

                if (copy_to_user((void *)arg, &ctl, sizeof(ctl)) != 0)
                    return -EFAULT;

                return 0;
            }

        case EXANICCTL_INFO_EX2:
            {
                struct exanicctl_info_ex2 ctl;
                int i;

                memset(&ctl, 0, sizeof(ctl));
                ctl.tx_buffer_size = exanic->tx_region_size;
                ctl.filters_size = exanic->filters_size;
                ctl.max_buffers = exanic->max_filter_buffers;
                ctl.num_ports = exanic->num_ports;

                BUG_ON(EXANIC_MAX_PORTS > ARRAY_SIZE(ctl.if_index));
                for (i = 0; i < EXANIC_MAX_PORTS; i++)
                {
                    if (exanic->ndev[i] == NULL)
                        ctl.if_index[i] = 0;
                    else
                        ctl.if_index[i] = exanic->ndev[i]->ifindex;
                }

                if (copy_to_user((void *)arg, &ctl, sizeof(ctl)) != 0)
                    return -EFAULT;

                return 0;
            }

        case EXANICCTL_RX_FILTER_ADD_IP:
            {
                struct exanicctl_rx_filter_add_ip ctl;
                struct exanic_ip_filter_slot filter;
                int ret;

                if (copy_from_user(&ctl, (void *)arg, sizeof(ctl)) != 0)
                    return -EFAULT;

                if (ctl.port_number >= exanic->num_ports)
                    return -EINVAL;

                if (ctl.buffer_number >= exanic->max_filter_buffers)
                    return -EINVAL;

                filter.buffer = ctl.buffer_number;
                filter.protocol = ctl.protocol;
                filter.src_addr = ctl.src_addr;
                filter.dst_addr = ctl.dst_addr;
                filter.src_port = ctl.src_port;
                filter.dst_port = ctl.dst_port;

                mutex_lock(&exanic->mutex);
                ret = exanic_insert_ip_filter(exanic, ctl.port_number,
                                             &filter);
                mutex_unlock(&exanic->mutex);
                if (ret < 0)
                    return ret;
                ctl.filter_id = ret;
                if (copy_to_user((void *)arg, &ctl, sizeof(ctl)) != 0)
                    return -EFAULT;

                return 0;
            }
        case EXANICCTL_RX_FILTER_ADD_MAC:
            {
                struct exanicctl_rx_filter_add_mac ctl;
                struct exanic_mac_filter_slot filter;
                int ret, i;

                if (copy_from_user(&ctl, (void *)arg, sizeof(ctl)) != 0)
                    return -EFAULT;

                if (ctl.port_number >= exanic->num_ports)
                    return -EINVAL;

                if (ctl.buffer_number >= exanic->max_filter_buffers)
                    return -EINVAL;

                filter.buffer = ctl.buffer_number;

                for (i = 0; i < 6; i++)
                    filter.dst_mac[i] = ctl.dst_mac[i];

                filter.ethertype = ctl.ethertype;
                filter.vlan = ctl.vlan;
                filter.vlan_match_method = ctl.vlan_match_method;

                mutex_lock(&exanic->mutex);
                ret = exanic_insert_mac_filter(exanic, ctl.port_number,
                                             &filter);
                mutex_unlock(&exanic->mutex);
                if (ret < 0)
                    return ret;
                ctl.filter_id = ret;
                if (copy_to_user((void *)arg, &ctl, sizeof(ctl)) != 0)
                    return -EFAULT;

                return 0;
            }
        case EXANICCTL_RX_FILTER_REMOVE_IP:
            {
                struct exanicctl_rx_filter_remove_ip ctl;
                struct exanic_port *port;
                int ret;

                if (copy_from_user(&ctl, (void *)arg, sizeof(ctl)) != 0)
                    return -EFAULT;

                if (ctl.port_number >= exanic->num_ports)
                    return -EINVAL;
                port = &exanic->port[ctl.port_number];

                if (ctl.filter_id >= port->max_ip_filter_slots)
                    return -EINVAL;

                mutex_lock(&exanic->mutex);
                ret = exanic_remove_ip_filter(exanic, ctl.port_number,
                        ctl.filter_id);
                mutex_unlock(&exanic->mutex);
                return ret;
            }
        case EXANICCTL_RX_FILTER_REMOVE_MAC:
            {
                struct exanicctl_rx_filter_remove_mac ctl;
                struct exanic_port *port;
                int ret;

                if (copy_from_user(&ctl, (void *)arg, sizeof(ctl)) != 0)
                    return -EFAULT;

                if (ctl.port_number >= exanic->num_ports)
                    return -EINVAL;
                port = &exanic->port[ctl.port_number];

                if (ctl.filter_id >= port->max_mac_filter_slots)
                    return -EINVAL;

                mutex_lock(&exanic->mutex);
                ret = exanic_remove_mac_filter(exanic, ctl.port_number,
                        ctl.filter_id);
                mutex_unlock(&exanic->mutex);
                return ret;
            }
        case EXANICCTL_RX_FILTER_BUFFER_ALLOC:
            {
                struct exanicctl_rx_filter_buffer_alloc ctl;
                int ret;

                if (copy_from_user(&ctl, (void *)arg, sizeof(ctl)) != 0)
                    return -EFAULT;

                if (ctl.port_number >= exanic->num_ports)
                    return -EINVAL;
                if (ctl.buffer_number >= exanic->max_filter_buffers)
                    return -EINVAL;

                mutex_lock(&exanic->mutex);
                /* Check to see if we already have a reference. */
                if (exanic_has_filter_buffer_ref(ctx, ctl.port_number,
                                                  ctl.buffer_number))
                {
                    mutex_unlock(&exanic->mutex);
                    return 0;
                }

                ret = exanic_add_filter_buffer_ref(ctx, ctl.port_number,
                                                    ctl.buffer_number);
                if (ret < 0)
                {
                    mutex_unlock(&exanic->mutex);
                    return ret;
                }
                /* Try to allocate the buffer. */
                ret = exanic_alloc_filter_dma(exanic, ctl.port_number,
                                              ctl.buffer_number, -1);

                /* Unwind reference on failure. */
                if (ret < 0)
                    exanic_remove_filter_buffer_ref(ctx, ctl.port_number,
                                                    ctl.buffer_number);
                mutex_unlock(&exanic->mutex);
                return ret;
            }
        case EXANICCTL_RX_FILTER_BUFFER_ALLOC_EX:
            {
                struct exanicctl_rx_filter_buffer_alloc ctl;
                int ret;

                if (copy_from_user(&ctl, (void *)arg, sizeof(ctl)) != 0)
                    return -EFAULT;

                if (ctl.port_number >= exanic->num_ports)
                    return -EINVAL;
                if (ctl.buffer_number >= exanic->max_filter_buffers &&
                        ctl.buffer_number != UINT_MAX)
                    return -EINVAL;

                mutex_lock(&exanic->mutex);
                if (ctl.buffer_number == UINT_MAX)
                {
                    /* Need to find a free buffer. */
                    ctl.buffer_number = exanic_get_free_filter_buffer(exanic,
                                                            ctl.port_number);
                    if (ctl.buffer_number == -1)
                    {
                        mutex_unlock(&exanic->mutex);
                        return -ENOMEM;
                    }
                }
                /* Check to see if we already have a reference. */
                if (exanic_has_filter_buffer_ref(ctx, ctl.port_number,
                                                  ctl.buffer_number))
                {
                    mutex_unlock(&exanic->mutex);
                    return 0;
                }

                ret = exanic_add_filter_buffer_ref(ctx, ctl.port_number,
                                                    ctl.buffer_number);
                if (ret < 0)
                {
                    mutex_unlock(&exanic->mutex);
                    return ret;
                }
                /* Try to allocate the buffer. */
                ret = exanic_alloc_filter_dma(exanic, ctl.port_number,
                                              ctl.buffer_number, -1);

                if (copy_to_user((void *)arg, &ctl, sizeof(ctl)) != 0)
                    ret = -EFAULT;

                /* Unwind reference on failure. */
                if (ret < 0)
                    exanic_remove_filter_buffer_ref(ctx, ctl.port_number,
                                                    ctl.buffer_number);
                mutex_unlock(&exanic->mutex);
                return ret;
            }
        case EXANICCTL_RX_FILTER_BUFFER_FREE:
            {
                struct exanicctl_rx_filter_buffer_free ctl;
                struct exanic_port *port;

                if (copy_from_user(&ctl, (void *)arg, sizeof(ctl)) != 0)
                    return -EFAULT;

                port = &exanic->port[ctl.port_number];

                if (ctl.port_number >= exanic->num_ports)
                    return -EINVAL;
                if (ctl.buffer_number >= exanic->max_filter_buffers)
                    return -EINVAL;
                if (port->filter_buffers[ctl.buffer_number].refcount == 0)
                    return -EACCES;

                mutex_lock(&exanic->mutex);
                exanic_remove_filter_buffer_ref(ctx, ctl.port_number,
                                                ctl.buffer_number);
                exanic_free_filter_dma(exanic, ctl.port_number,
                                              ctl.buffer_number);

                mutex_unlock(&exanic->mutex);
                return 0;
            }
        case EXANICCTL_RX_HASH_CONFIGURE:
            {
                struct exanicctl_rx_hash_configure ctl;
                struct exanic_port *port;
                if (copy_from_user(&ctl, (void *)arg, sizeof(ctl)) != 0)
                    return -EFAULT;
                if (ctl.port_number >= exanic->num_ports)
                    return -EINVAL;
                port = &exanic->port[ctl.port_number];
                if (ctl.function >= port->num_hash_functions)
                    return -EINVAL;
                mutex_lock(&exanic->mutex);
                exanic_configure_port_hash(exanic, ctl.port_number,
                                           ctl.enable, ctl.mask,
                                           ctl.function);
                mutex_unlock(&exanic->mutex);
                return 0;
            }
        case EXANICCTL_DEVKIT_INFO:
            {
                struct exanicctl_devkit_info ctl;

                ctl.regs_size = exanic->devkit_regs_size;
                ctl.mem_size = exanic->devkit_mem_size;

                if (copy_to_user((void *)arg, &ctl, sizeof(ctl)) != 0)
                    return -EFAULT;

                return 0;
            }
        case EXANICCTL_DEVKIT_INFO_EX:
            {
                struct exanicctl_devkit_info ctl;
                ctl.regs_size = exanic->devkit_regs_ex_size;
                ctl.mem_size = exanic->devkit_mem_ex_size;

                if (copy_to_user((void *)arg, &ctl, sizeof(ctl)) != 0)
                    return -EFAULT;

                return 0;
            }
        case EXANICCTL_DEVICE_USAGE:
            {
                struct exanicctl_usage_info ctl = {
                    .users = 0,
                };

                mutex_lock(&exanic->mutex);
                ctl.users = exanic_count_tx_feedback_users(exanic)
                            + exanic_count_rx_users(exanic);
                mutex_unlock(&exanic->mutex);

                if (copy_to_user((void *)arg, &ctl, sizeof(ctl)) != 0)
                    return -EFAULT;

                return 0;
            }

        default:
            return -ENOTTY;
    }
}

struct file_operations exanic_fops = {
    .owner          = THIS_MODULE,
    .open           = exanic_open,
    .release        = exanic_release,
    .mmap           = exanic_mmap,
    .unlocked_ioctl = exanic_ioctl,
};
