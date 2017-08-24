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

#include "../../libs/exanic/pcie_if.h"
#include "../../libs/exanic/fifo_if.h"
#include "../../libs/exanic/ioctl.h"
#include "exanic.h"
#include "exanic-structs.h"


/**
 * Allocate an ExaNIC context.
 *
 * Called with the exanic mutex held.
 */
struct exanic_ctx *exanic_alloc_ctx(struct exanic *exanic)
{
    struct exanic_ctx *ctx;

    ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
    if (ctx == NULL)
        return NULL;

    ctx->exanic = exanic;
    ctx->check_numa_node = 0; /* Don't do a NUMA node check by default */
    bitmap_zero(ctx->tx_region_bitmap, EXANIC_TX_REGION_MAX_NUM_PAGES);
    bitmap_zero(ctx->tx_feedback_bitmap, EXANIC_TX_FEEDBACK_NUM_SLOTS);
    memset(ctx->rx_refcount, 0, sizeof(ctx->rx_refcount));
    INIT_LIST_HEAD(&ctx->filter_buffer_ref_list);
    return ctx;
}

/**
 * Free an ExaNIC context.
 * This will also trigger auto-disable of ports that are no longer in use.
 *
 * Called with the exanic mutex held.
 */
void exanic_free_ctx(struct exanic_ctx *ctx)
{
    struct exanic *exanic = ctx->exanic;
    int i;
    struct exanic_filter_buffer_ref *ref; 
    struct list_head *pos, *pos_next;
    /* Deallocate TX region and feedback slots associated with this fd */
    bitmap_andnot(exanic->tx_region_bitmap, exanic->tx_region_bitmap,
            ctx->tx_region_bitmap, EXANIC_TX_REGION_MAX_NUM_PAGES);
    bitmap_andnot(exanic->tx_feedback_bitmap, exanic->tx_feedback_bitmap,
            ctx->tx_feedback_bitmap, EXANIC_TX_FEEDBACK_NUM_SLOTS);


    /* Free any filter DMA buffers. */
    list_for_each_safe(pos, pos_next, &ctx->filter_buffer_ref_list)
    {
        ref = list_entry(pos, struct exanic_filter_buffer_ref,
                         list);
        exanic_free_filter_dma(exanic, ref->port, ref->buffer); 
        list_del(pos);
        kfree(ref);
    } 

    /* Decrement RX reference counts */
    for (i = 0; i < exanic->num_ports; ++i)
    {
        if (ctx->rx_refcount[i] != 0)
        {
            dev_err(&exanic->pci_dev->dev, DRV_NAME
                    ": Non-zero rx_refcount[%d] = %d when freeing exanic_ctx\n",
                    i, ctx->rx_refcount[i]);
            exanic->port[i].rx_refcount -= ctx->rx_refcount[i];
        }
    }

    /* Disable ports if no longer in use */
    for (i = 0; i < exanic->num_ports; ++i)
    {
        if (!exanic_rx_in_use(exanic, i))
            exanic_free_rx_dma(exanic, i);
    }

    kfree(ctx);
}

/**
 * Increment reference count for the RX region.
 *
 * Called with the exanic mutex held.
 */
void exanic_rx_get(struct exanic_ctx *ctx, unsigned port_num)
{
    ctx->rx_refcount[port_num]++;
    ctx->exanic->port[port_num].rx_refcount++;
}

/**
 * Decrement reference count for the RX region.
 *
 * Called with the exanic mutex held.
 */
void exanic_rx_put(struct exanic_ctx *ctx, unsigned port_num)
{
    ctx->exanic->port[port_num].rx_refcount--;
    ctx->rx_refcount[port_num]--;
}

/**
 * Allocate part of the TX region.
 *
 * Called with exanic mutex held.
 */
int exanic_alloc_tx_region(struct exanic_ctx *ctx, unsigned port_num,
                           size_t size, size_t *offset_ptr)
{
    struct exanic *exanic = ctx->exanic;
    struct exanic_port *port = &exanic->port[port_num];
    size_t usable_start_page = port->tx_region_usable_offset >> PAGE_SHIFT;
    size_t usable_end_page = usable_start_page +
        (port->tx_region_usable_size >> PAGE_SHIFT);
    size_t num_pages = size >> PAGE_SHIFT;
    size_t page, p;

    /* Scan through the bitmap looking for a contiguous region of num_pages */
    for (page = usable_start_page; page + num_pages <= usable_end_page; page++)
    {
        for (p = page; p < page + num_pages; p++)
            if (test_bit(p, exanic->tx_region_bitmap))
                break;
        if (p >= page + num_pages)
            break;
    }

    if (page + num_pages > usable_end_page)
    {
        dev_err(&exanic->pci_dev->dev, DRV_NAME
            "%u: Failed to allocate TX region of size: 0x%05zx.\n",
            exanic->id, size);
        return -ENOMEM;
    }

    /* Mark the region as allocated to this fd */
    for (p = page; p < page + num_pages; p++)
    {
        set_bit(p, exanic->tx_region_bitmap);
        set_bit(p, ctx->tx_region_bitmap);
    }

    dev_dbg(&exanic->pci_dev->dev, DRV_NAME
        "%u: Allocated TX region offset: 0x%08lx, size: 0x%05zx.\n",
        exanic->id, page * PAGE_SIZE, size);

    /* Return the allocated offset */
    *offset_ptr = page * PAGE_SIZE;
    return 0;
}

/**
 * Deallocate part of the TX region.
 *
 * Called with exanic mutex held.
 */
int exanic_free_tx_region(struct exanic_ctx *ctx, unsigned port_num,
                          size_t size, size_t offset)
{
    struct exanic *exanic = ctx->exanic;
    size_t start_page = offset >> PAGE_SHIFT;
    size_t end_page = start_page + (size >> PAGE_SHIFT);
    size_t p;

    /* Test whether the page was allocated to this fd, then free it */
    for (p = start_page; p < end_page; p++)
    {
        if (test_bit(p, ctx->tx_region_bitmap))
        {
            clear_bit(p, exanic->tx_region_bitmap);
            clear_bit(p, ctx->tx_region_bitmap);
        }
    }

    dev_dbg(&exanic->pci_dev->dev, DRV_NAME
        "%u: Freed TX region offset: 0x%08zx, size: 0x%05zx.\n",
        exanic->id, offset, size);

    return 0;
}

/**
 * Allocate a TX feedback slot.
 *
 * Called with the exanic mutex held.
 */
int exanic_alloc_tx_feedback(struct exanic_ctx *ctx, unsigned port_num,
                             unsigned *feedback_slot_ptr)
{
    struct exanic *exanic = ctx->exanic;
    size_t start = port_num * (EXANIC_TX_FEEDBACK_NUM_SLOTS / EXANIC_MAX_PORTS);
    size_t end = start + (EXANIC_TX_FEEDBACK_NUM_SLOTS / EXANIC_MAX_PORTS);
    unsigned slot;

    slot = find_next_zero_bit(exanic->tx_feedback_bitmap, end, start);
    if (slot >= end)
    {
        dev_err(&exanic->pci_dev->dev, DRV_NAME
            "%u: Failed to allocate TX feedback slot.\n", exanic->id);
        return -ENOMEM;
    }

    set_bit(slot, exanic->tx_feedback_bitmap);
    set_bit(slot, ctx->tx_feedback_bitmap);

    dev_dbg(&exanic->pci_dev->dev, DRV_NAME
        "%u: Allocated TX feedback slot: %d\n", exanic->id, slot);

    *feedback_slot_ptr = slot;
    return 0;
}

/**
 * Deallocate a TX feedback slot.
 *
 * Called with the exanic mutex held.
 */
int exanic_free_tx_feedback(struct exanic_ctx *ctx, unsigned port_num,
                            unsigned feedback_slot)
{
    struct exanic *exanic = ctx->exanic;

    if (test_bit(feedback_slot, ctx->tx_feedback_bitmap))
    {
        clear_bit(feedback_slot, exanic->tx_feedback_bitmap);
        clear_bit(feedback_slot, ctx->tx_feedback_bitmap);
    }

    dev_dbg(&exanic->pci_dev->dev, DRV_NAME
        "%u: Freed TX feedback slot: %d\n", exanic->id, feedback_slot);

    return 0;
}

int exanic_has_filter_buffer_ref(struct exanic_ctx *ctx, unsigned port_num,
                                    unsigned buffer_num)
{
    struct list_head *pos;
    struct exanic_filter_buffer_ref *ref;
     
    list_for_each(pos, &ctx->filter_buffer_ref_list)
    {
        ref = list_entry(pos, struct exanic_filter_buffer_ref,
                                list);
        if (ref->buffer == buffer_num &&
            ref->port == port_num)
            return 1;
    }
    
    return 0;
}

int exanic_add_filter_buffer_ref(struct exanic_ctx *ctx, unsigned port_num,
                                    unsigned buffer_num)
{
    struct exanic_filter_buffer_ref *ref;
    if (exanic_has_filter_buffer_ref(ctx, port_num, buffer_num))
        return 0;

    ref = kzalloc(sizeof(struct exanic_filter_buffer_ref), GFP_KERNEL);
    if (ref == NULL)
        return -ENOMEM;
    INIT_LIST_HEAD(&ref->list);
    ref->port = port_num;
    ref->buffer = buffer_num;
    list_add(&ref->list, &ctx->filter_buffer_ref_list);
    return 0;
}

int exanic_remove_filter_buffer_ref(struct exanic_ctx *ctx, unsigned port_num,
                                        unsigned buffer_num)
{
    struct exanic_filter_buffer_ref *ref; 
    struct list_head *pos;
    list_for_each(pos, &ctx->filter_buffer_ref_list)
    {
        ref = list_entry(pos, struct exanic_filter_buffer_ref,
                          list);
        if (ref->buffer == buffer_num &&
              ref->port == port_num)
        {
            list_del(pos);
            kfree(ref);
            return 0;
        }
    } 

    return -1;
}
