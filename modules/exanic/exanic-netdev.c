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
#include <linux/ethtool.h>
#include <linux/miscdevice.h>
#include <linux/etherdevice.h>
#include <linux/net_tstamp.h>

#include "../../libs/exanic/pcie_if.h"
#include "../../libs/exanic/fifo_if.h"
#include "../../libs/exanic/ioctl.h"
#include "exanic.h"
#include "exanic-structs.h"

/**
 * Module command line parameters
 */
static int disable_exasock;
module_param(disable_exasock, int, 0);
MODULE_PARM_DESC(disable_exasock, "Disable loading of exasock module");

static unsigned int txbuf_size_min = 4;
module_param(txbuf_size_min, uint, 0);
MODULE_PARM_DESC(txbuf_size_min,
    "Minimum size of kernel TX buffer in kB (default: 4)");

/* Some earlier versions of Linux do not have the netdev_* logging
 * functions or macros defined */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34) && !defined(netdev_printk)
#define netdev_printk(level, netdev, format, args...)           \
        dev_printk(level, (netdev)->dev.parent,                 \
                   "%s: " format, (netdev)->name, ##args)
#define netdev_err(dev, format, args...)                        \
        netdev_printk(KERN_ERR, dev, format, ##args)
#define netdev_info(dev, format, args...)                       \
        netdev_printk(KERN_INFO, dev, format, ##args)
#endif

/* Hardware timestamping flag depends on kernel version */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
#define tx_hw_tstamp_flag(skb) skb_tx(skb)->hardware
#else
#define tx_hw_tstamp_flag(skb) (skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
#define netdev_tx_t int
#endif

#ifndef SUPPORTED_1000baseKX_Full
#define SUPPORTED_1000baseKX_Full	(1 << 17)
#endif
#ifndef SUPPORTED_10000baseKR_Full
#define SUPPORTED_10000baseKR_Full	(1 << 19)
#endif
#ifndef SUPPORTED_40000baseCR4_Full
#define SUPPORTED_40000baseCR4_Full	(1 << 24)
#endif
#ifndef SUPPORTED_40000baseSR4_Full
#define SUPPORTED_40000baseSR4_Full	(1 << 25)
#endif
#ifndef SUPPORTED_40000baseLR4_Full
#define SUPPORTED_40000baseLR4_Full	(1 << 26)
#endif
#ifndef SPEED_40000
#define SPEED_40000 40000
#endif

#ifndef SIOCGHWTSTAMP
#define SIOCGHWTSTAMP 0x89b1
#endif

/* Loop timeout when waiting for feedback. */
#define FEEDBACK_TIMEOUT                10000

#define DEFAULT_RX_COALESCE_US          10
#define MAX_RX_COALESCE_US              100000

/* Maximum number of chunks to be processed in exanic_netdev_poll() */
#define POLL_MAX_CHUNKS                 1024

/* Minimum size of TX buffer in bytes */
#define MIN_TX_BUF_SIZE                 (txbuf_size_min * 1024)

struct exanic_netdev_tx
{
    unsigned            feedback_slot;
    volatile uint16_t   *feedback;
    char                *buffer;
    uint32_t            buffer_offset;
    uint32_t            buffer_size;
    uint32_t            next_offset;
    uint16_t            feedback_seq;
    uint16_t            request_seq;
    uint16_t            rollover_seq;
    uint16_t            next_seq;
    int                 queue_len;
    uint32_t            *feedback_offsets;
};

struct exanic_netdev_rx
{
    volatile struct rx_chunk *buffer;
    uint32_t            next_chunk;
    uint8_t             generation;
};

struct exanic_netdev_priv
{
    struct net_device   *ndev;
    struct napi_struct  napi;
    struct timer_list   rx_timer;
    struct hrtimer      rx_hrtimer;
    bool                rx_enabled;
    bool                rx_hw_tstamp;
    bool                tx_hw_tstamp;

    struct exanic       *exanic;
    struct exanic_ctx   *ctx;
    unsigned            port;
    volatile uint32_t   *registers;

    /* RX and TX are initialised iff bypass_only is false and interface is up */
    bool                bypass_only;

    struct exanic_netdev_rx rx;
    struct exanic_netdev_tx tx;

    struct sk_buff      *skb;
    uint32_t            hdr_chunk_id;
    bool                length_error;

    spinlock_t          tx_lock;

    uint32_t            rx_coalesce_timeout_ns;
};

struct exanic_netdev_intercept
{
    exanic_netdev_intercept_func func;

    struct list_head    list;
};

static LIST_HEAD(intercept_funcs);

enum
{
    FEEDBACK_INTERVAL = 512,

    MAX_ETH_OVERHEAD_BYTES = 26, /* header + 2 VLAN tags + FCS */

    /* Additional RX error codes */
    EXANIC_RX_FRAME_SWOVFL = 256,
    EXANIC_RX_FRAME_TRUNCATED = 257,
};

static void exanic_rx_catchup(struct exanic_netdev_rx *rx)
{
    /* Find the next chunk in which data will arrive */
    uint8_t generation = rx->buffer[0].u.info.generation;
    uint32_t next_chunk;
    for (next_chunk = 1; next_chunk < EXANIC_RX_NUM_CHUNKS; next_chunk++)
        if (rx->buffer[next_chunk].u.info.generation != generation)
            break;
    if (next_chunk < EXANIC_RX_NUM_CHUNKS)
    {
        rx->generation = generation;
        rx->next_chunk = next_chunk;
    }
    else
    {
        rx->generation = generation + 1;
        rx->next_chunk = 0;
    }
}

static int exanic_rx_ready(struct exanic_netdev_rx *rx)
{
    union {
        struct rx_chunk_info info;
        uint64_t data;
    } u;

    u.data = rx->buffer[rx->next_chunk].u.data;

    return (u.info.generation != (uint8_t)(rx->generation - 1));
}

static void exanic_rx_set_irq(struct exanic_netdev_rx *rx)
{
    struct exanic_netdev_priv *priv =
        container_of(rx, struct exanic_netdev_priv, rx);
    uint32_t next;

    /* Set IRQ to fire when more data becomes available */
    next = rx->generation * EXANIC_RX_NUM_CHUNKS + rx->next_chunk;
    writel(EXANIC_PORT_IRQ_ENABLE | next,
           &priv->registers[REG_PORT_INDEX(priv->port, REG_PORT_IRQ_CONFIG)]);
}

static ssize_t exanic_receive_chunk_inplace(struct exanic_netdev_rx *rx,
                                            char **rx_buf_ptr,
                                            uint32_t *chunk_id,
                                            int *more_chunks)
{
    union {
        struct rx_chunk_info info;
        uint64_t data;
    } u;

    u.data = rx->buffer[rx->next_chunk].u.data;

    if (u.info.generation == rx->generation)
    {
        /* Data is available */
        *rx_buf_ptr = (char *)rx->buffer[rx->next_chunk].payload;

        if (chunk_id != NULL)
            *chunk_id = rx->generation * EXANIC_RX_NUM_CHUNKS + rx->next_chunk;

        /* Advance next_chunk to next chunk */
        rx->next_chunk++;
        if (rx->next_chunk == EXANIC_RX_NUM_CHUNKS)
        {
            rx->next_chunk = 0;
            rx->generation++;
        }

        if (u.info.length != 0)
        {
            /* Last chunk */
            if (u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK)
                return -(u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK);

            *more_chunks = 0;
            return u.info.length;
        }
        else
        {
            /* More chunks to come */
            *more_chunks = 1;
            return EXANIC_RX_CHUNK_PAYLOAD_SIZE;
        }
    }
    else if (u.info.generation == (uint8_t)(rx->generation - 1))
    {
        /* No new data */
        return 0;
    }
    else
    {
        /* Got lapped? */
        exanic_rx_catchup(rx);
        return -EXANIC_RX_FRAME_SWOVFL;
    }
}

static int exanic_receive_chunk_recheck(struct exanic_netdev_rx *rx,
                                        uint32_t chunk_id)
{
    uint32_t chunk = chunk_id % EXANIC_RX_NUM_CHUNKS;
    uint8_t generation = chunk_id / EXANIC_RX_NUM_CHUNKS;

    return rx->buffer[chunk].u.info.generation == generation;
}

static uint32_t exanic_receive_chunk_timestamp(struct exanic_netdev_rx *rx,
                                               uint32_t chunk_id)
{
    uint32_t chunk = chunk_id % EXANIC_RX_NUM_CHUNKS;

    return rx->buffer[chunk].u.info.timestamp;
}

static size_t exanic_tx_buf_size(struct exanic_netdev_priv *priv,
                                 size_t max_frame_size)
{
    struct exanic *exanic = priv->ctx->exanic;
    struct exanic_port *port = &exanic->port[priv->port];
    size_t padding = exanic_payload_padding_bytes(EXANIC_TX_TYPE_RAW);
    size_t max_chunk_size = ALIGN(max_frame_size + padding
                                  + sizeof(struct tx_chunk), 8);
    size_t tx_buf_size = (max_chunk_size + FEEDBACK_INTERVAL) * 2;

    if (tx_buf_size < MIN_TX_BUF_SIZE)
        tx_buf_size = MIN_TX_BUF_SIZE;
    if (tx_buf_size > port->tx_region_usable_size)
        tx_buf_size = port->tx_region_usable_size;

    return PAGE_ALIGN(tx_buf_size);
}

static int exanic_update_tx_feedback(struct exanic_netdev_tx *tx)
{
    struct exanic_netdev_priv *priv =
        container_of(tx, struct exanic_netdev_priv, tx);
    uint16_t feedback_seq = *tx->feedback;

    if ((uint16_t)(tx->next_seq - feedback_seq) <= tx->queue_len)
    {
        tx->feedback_seq = feedback_seq;
        return 0;
    }
    else
    {
        netdev_err(priv->ndev,
                "invalid TX feedback sequence number 0x%x\n", feedback_seq);
        tx->feedback_seq = tx->next_seq - 1;
        *tx->feedback = tx->feedback_seq;
        return -1;
    }
}

static size_t exanic_max_tx_chunk_size(struct exanic_netdev_tx *tx)
{
    /* The maximum TX chunk size is chosen so that we don't end up
     * waiting for a feedback that was never requested.
     *
     * Example of what we wish to avoid:
     *
     * 0. TX buffer is empty
     * 1. send chunk of size buffer_size / 2 - 8       feedback requested
     * 2. send chunk of size FEEDBACK_INTERVAL         feedback not requested
     * 3. send chunk of size buffer_size / 2           this will wait forever
     *
     * Note that the chunk size is only checked if we have to wait. */
    return tx->buffer_size / 2 - FEEDBACK_INTERVAL;
}

static struct tx_chunk *exanic_prepare_tx_chunk(struct exanic_netdev_tx *tx,
                                                size_t chunk_size)
{
    struct exanic_netdev_priv *priv =
        container_of(tx, struct exanic_netdev_priv, tx);
    size_t aligned_size = ALIGN(chunk_size, 8);
    size_t feedback_offset;
    int timeout;

    timeout = FEEDBACK_TIMEOUT;
    while ((uint16_t)(tx->next_seq - tx->feedback_seq) >= tx->queue_len)
    {
        /* Spin on TX feedback for more available sequence numbers */
        if (exanic_update_tx_feedback(tx) == -1)
            return NULL;
        if (--timeout == 0)
            return NULL;
    }

    timeout = FEEDBACK_TIMEOUT;
    while (1)
    {
        /* Check if we have not wrapped around since feedback_seq */
        if ((uint16_t)(tx->next_seq - tx->feedback_seq) <=
                (uint16_t)(tx->next_seq - tx->rollover_seq))
        {
            /* Everything after next_offset is available */
            if (tx->next_offset + aligned_size <= tx->buffer_size)
                break;

            /* Not enough space, need to wrap around */
            tx->next_offset = 0;
            tx->rollover_seq = tx->next_seq;
        }

        /* Available space is between next_offset and feedback_offset */
        feedback_offset =
            tx->feedback_offsets[tx->feedback_seq & (tx->queue_len - 1)];
        if (tx->next_offset + aligned_size <= feedback_offset)
            break;

        /* Make sure chunk size is not too big so that we don't wait forever */
        if (aligned_size > exanic_max_tx_chunk_size(tx))
        {
            netdev_err(priv->ndev,
                    "requested TX chunk size is too large\n");
            return NULL;
        }

        /* Spin on TX feedback for more space */
        if (exanic_update_tx_feedback(tx) == -1)
            return NULL;

        if (--timeout == 0)
           return NULL;
    }

    return (struct tx_chunk *)(tx->buffer + tx->next_offset);
}

static void exanic_send_tx_chunk(struct exanic_netdev_tx *tx, size_t chunk_size)
{
    struct exanic_netdev_priv *priv =
        container_of(tx, struct exanic_netdev_priv, tx);
    size_t aligned_size = ALIGN(chunk_size, 8);
    struct tx_chunk *chunk = (struct tx_chunk *)(tx->buffer + tx->next_offset);
    size_t offset = tx->next_offset;
    size_t request_offset =
        tx->feedback_offsets[tx->request_seq & (tx->queue_len - 1)];
    int need_feedback = 0;

    tx->next_offset += aligned_size;

    /* We request feedback if the last request was too long ago, by sequence
     * number or by amount of data sent */
    if ((uint16_t)(tx->next_seq - tx->request_seq) > tx->queue_len / 2)
        /* Need more sequence numbers */
        need_feedback = 1;
    else if ((uint16_t)(tx->next_seq - tx->request_seq) >
            (uint16_t)(tx->next_seq - tx->rollover_seq))
        /* Wrapped around since last feedback request */
        need_feedback = 1;
    else if (tx->next_offset - request_offset > FEEDBACK_INTERVAL)
        /* Too many bytes since last feedback request */
        need_feedback = 1;

    /* Fill out feedback info in tx_chunk header */
    writew(tx->next_seq, &chunk->feedback_id);
    writew(tx->feedback_slot | (need_feedback ? 0 : 0x8000),
           &chunk->feedback_slot_index);

    /* Send transmit command */
    wmb();
    writel(offset + tx->buffer_offset,
           &priv->registers[REG_PORT_INDEX(priv->port, REG_PORT_TX_COMMAND)]);

    /* Update state */
    tx->feedback_offsets[tx->next_seq & (tx->queue_len - 1)]
        = tx->next_offset;
    if (need_feedback)
        tx->request_seq = tx->next_seq;
    tx->next_seq++;
}

static int __exanic_transmit_frame(struct exanic_netdev_tx *tx,
                                   struct sk_buff *skb)
{
    size_t padding = exanic_payload_padding_bytes(EXANIC_TX_TYPE_RAW);
    size_t chunk_size = skb->len + padding + sizeof(struct tx_chunk);
    struct tx_chunk *chunk;

    chunk = exanic_prepare_tx_chunk(tx, chunk_size);
    if (chunk == NULL)
        return -1;

    writew(skb->len + padding, &chunk->length);
    writeb(EXANIC_TX_TYPE_RAW, &chunk->type);
    writeb(0, &chunk->flags);
    memcpy_toio(chunk->payload + padding, skb->data, skb->len);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    skb_tx_timestamp(skb);
#endif

    exanic_send_tx_chunk(tx, chunk_size);
    return 0;
}

/**
 * This is the polling function used when interrupts are not available.
 */
static void exanic_timer_callback(unsigned long data)
{
    struct exanic_netdev_priv *priv = (struct exanic_netdev_priv *)data;

    if (priv->rx_enabled)
    {
        if (exanic_rx_ready(&priv->rx))
            napi_schedule(&priv->napi);
        mod_timer(&priv->rx_timer, jiffies + 1);
    }
}

/**
 * This timer is used to delay interrupt re-arming when coalescing is enabled.
 */
static enum hrtimer_restart exanic_hrtimer_callback(struct hrtimer *timer)
{
    struct exanic_netdev_priv *priv =
        container_of(timer, struct exanic_netdev_priv, rx_hrtimer);
    if (priv->rx_enabled)
    {
        if (exanic_rx_ready(&priv->rx))
            napi_schedule(&priv->napi);
        else
            exanic_rx_set_irq(&priv->rx);
    }
    /* HR timer is started again in poll if necessary - not here! */
    return HRTIMER_NORESTART;
}

/**
 * Called from exanic_rx_irq_handler()
 *
 * This may be called on ports that are not enabled, so we need to check.
 */
void exanic_netdev_rx_irq_handler(struct net_device *ndev)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);

    if (priv->rx_enabled)
    {
        if (exanic_rx_ready(&priv->rx))
            napi_schedule(&priv->napi);
    }
}

/**
 * Start receiving and transmitting packets for the kernel IP stack
 *
 * Called with exanic mutex held.
 */
static int exanic_netdev_kernel_start(struct net_device *ndev)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    size_t max_frame_size = ndev->mtu + MAX_ETH_OVERHEAD_BYTES;
    size_t tx_buf_size = exanic_tx_buf_size(priv, max_frame_size);
    size_t tx_buf_offset;
    unsigned feedback_slot;
    int queue_len;
    uint32_t *feedback_offsets;
    int err;
    unsigned long flags;

    /* Allocate TX resources */
    err = exanic_alloc_tx_region(priv->ctx, priv->port, tx_buf_size,
                                 &tx_buf_offset);
    if (err)
        goto err_alloc_tx_region;

    err = exanic_alloc_tx_feedback(priv->ctx, priv->port, &feedback_slot);
    if (err)
        goto err_alloc_tx_feedback;

    /* queue_len is always a power of 2 */
    queue_len = tx_buf_size / EXANIC_TX_CMD_FIFO_SIZE_DIVISOR;
    feedback_offsets = kcalloc(queue_len, sizeof(uint32_t), GFP_KERNEL);

    BUG_ON(priv->rx.buffer != NULL);
    priv->rx.buffer = exanic_rx_region(priv->exanic, priv->port);

    exanic_rx_catchup(&priv->rx);

    spin_lock_irqsave(&priv->tx_lock, flags);

    BUG_ON(priv->tx.buffer != NULL);
    priv->tx.feedback_slot = feedback_slot;
    priv->tx.feedback = exanic_tx_feedback(priv->exanic) + feedback_slot;
    priv->tx.buffer_offset = tx_buf_offset;
    priv->tx.buffer = exanic_tx_region(priv->exanic) + tx_buf_offset;
    priv->tx.buffer_size = tx_buf_size;
    priv->tx.next_offset = 0;
    priv->tx.feedback_seq = 0;
    priv->tx.request_seq = 0;
    priv->tx.rollover_seq = 1;
    priv->tx.next_seq = 1;
    priv->tx.queue_len = queue_len;
    priv->tx.feedback_offsets = feedback_offsets;
    priv->tx.feedback_offsets[0] = tx_buf_size;

    *priv->tx.feedback = 0;

    spin_unlock_irqrestore(&priv->tx_lock, flags);

    /* We use a HR timer to reduce IRQ rate under certain loads. */
    hrtimer_init(&priv->rx_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    priv->rx_hrtimer.function = &exanic_hrtimer_callback;
    priv->rx_coalesce_timeout_ns = DEFAULT_RX_COALESCE_US * 1000;

    napi_enable(&priv->napi);
    netif_start_queue(ndev);

    priv->rx_enabled = true;

    /* Set interrupt to fire on the next packet to arrive */
    exanic_rx_set_irq(&priv->rx);

    if (!(priv->exanic->caps & EXANIC_CAP_RX_IRQ))
    {
        netdev_info(ndev, "interrupts not available; "
                "using timer to poll for packets\n");

        /* Set up timer callback to trigger polling */
        setup_timer(&priv->rx_timer, exanic_timer_callback, (unsigned long)priv);
        mod_timer(&priv->rx_timer, jiffies + 1);
    }

    return 0;

err_alloc_tx_feedback:
    exanic_free_tx_region(priv->ctx, priv->port, PAGE_SIZE, tx_buf_offset);
err_alloc_tx_region:
    return err;
}

/**
 * Stop receiving and transmitting packets for the kernel IP stack
 *
 * Called with exanic mutex held.
 */
static void exanic_netdev_kernel_stop(struct net_device *ndev)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    unsigned long flags;

    /* This flag stops the timer as well as the irq handler */
    priv->rx_enabled = false;

    /* Wait a little to make sure irq handler has stopped running
     * TODO: Should this use a spinlock instead? */
    udelay(10);

    if (!(priv->exanic->caps & EXANIC_CAP_RX_IRQ))
        del_timer_sync(&priv->rx_timer);

    hrtimer_cancel(&priv->rx_hrtimer);

    napi_disable(&priv->napi);
    netif_stop_queue(ndev);

    /* Discard partially received packet */
    if (priv->skb != NULL)
        dev_kfree_skb(priv->skb);
    priv->skb = NULL;

    /* Free TX resources */
    spin_lock_irqsave(&priv->tx_lock, flags);
    exanic_free_tx_region(priv->ctx, priv->port, PAGE_SIZE,
            priv->tx.buffer_offset);
    exanic_free_tx_feedback(priv->ctx, priv->port, priv->tx.feedback_slot);
    kfree(priv->tx.feedback_offsets);
    memset(&priv->tx, 0, sizeof(priv->tx));
    spin_unlock_irqrestore(&priv->tx_lock, flags);

    /* Clear RX state */
    memset(&priv->rx, 0, sizeof(priv->rx));
}

/**
 * Handles "ifconfig up" on an ExaNIC interface.
 */
static int exanic_netdev_open(struct net_device *ndev)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    struct mutex *mutex = exanic_mutex(priv->exanic);
    int err;

    mutex_lock(mutex);

    /* If processes are still attached from a previous "up" state, it is
     * not safe to re-enable the port, or the processes will now be out of
     * sync with the hardware pointers and may receive garbage data. */
    if (exanic_rx_in_use(priv->exanic, priv->port))
    {
        netdev_err(ndev, "cannot re-enable port, interface still in use\n");
        err = -EBUSY;
        goto err_rx_in_use;
    }

    /* Allocate context before trying to allocate buffers */
    BUG_ON(priv->ctx != NULL);
    priv->ctx = exanic_alloc_ctx(priv->exanic);
    if (priv->ctx == NULL)
    {
        err = -ENOMEM;
        goto err_alloc_ctx;
    }

    /* Allocate buffers before enabling the port.
     * This will work even if the buffers are already allocated. */
    err = exanic_alloc_rx_dma(priv->exanic, priv->port, -1);
    if (err)
        goto err_alloc_rx_dma;

    /* Increment RX reference count before enabling the port */
    exanic_rx_get(priv->ctx, priv->port);

    /* Enable and power on the port */
    err = exanic_enable_port(priv->exanic, priv->port);
    if (err)
        goto err_enable_port;

    if (!priv->bypass_only)
    {
        /* Automatically load ExaNIC sockets support module */
        if (!disable_exasock)
            request_module("exasock");

        /* Start sending and receiving packets in kernel */
        err = exanic_netdev_kernel_start(ndev);
        if (err)
            goto err_kernel_start;
    }

    mutex_unlock(mutex);

    netdev_info(ndev, "interface opened\n");
    return 0;

err_kernel_start:
err_enable_port:
    exanic_rx_put(priv->ctx, priv->port);
err_alloc_rx_dma:
    /* This will free the RX buffers */
    exanic_free_ctx(priv->ctx);
    priv->ctx = NULL;
err_alloc_ctx:
err_rx_in_use:
    mutex_unlock(mutex);

    netdev_err(ndev, "interface open failed\n");
    return err;
}

/**
 * Handles "ifconfig down" on an ExaNIC interface.
 *
 * This function is not allowed to fail!
 */
static int exanic_netdev_stop(struct net_device *ndev)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    struct mutex *mutex = exanic_mutex(priv->exanic);

    mutex_lock(mutex);

    if (!priv->bypass_only)
        exanic_netdev_kernel_stop(ndev);

    BUG_ON(priv->tx.buffer != NULL);
    BUG_ON(priv->rx.buffer != NULL);

    /* Disable and power off the port */
    exanic_disable_port(priv->exanic, priv->port);

    /* No longer need the RX buffers since the port is disabled */
    exanic_rx_put(priv->ctx, priv->port);

    /* Free context. This will free RX buffers if there are no more users. */
    exanic_free_ctx(priv->ctx);
    priv->ctx = NULL;

    mutex_unlock(mutex);

    netdev_info(ndev, "interface closed\n");
    return 0;
}

/**
 * Send a packet on an ExaNIC interface.
 */
static netdev_tx_t exanic_netdev_xmit(struct sk_buff *skb,
                                      struct net_device *ndev)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    int err;
    unsigned long flags;
    bool tx_hw_tstamp;
    uint32_t tx_count_before = 0;

    if (priv->bypass_only)
    {
        /* Bypass only mode - cannot send packets from kernel */
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    tx_hw_tstamp = priv->tx_hw_tstamp && tx_hw_tstamp_flag(skb);
    if (tx_hw_tstamp)
    {
        /* Record transmit counter before frame is sent */
        tx_count_before = readl(&priv->registers[
                REG_PORT_STAT_INDEX(priv->port, REG_PORT_STAT_TX)]);
    }

    spin_lock_irqsave(&priv->tx_lock, flags);

    if (priv->tx.buffer == NULL)
    {
        /* exanic_netdev_kernel_stop may have freed the buffer */
        spin_unlock_irqrestore(&priv->tx_lock, flags);
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    err = __exanic_transmit_frame(&priv->tx, skb);

    spin_unlock_irqrestore(&priv->tx_lock, flags);

    if (tx_hw_tstamp)
    {
        uint32_t tx_count_after, tx_timestamp, tx_count_final;

        /* Keep checking transmit counter until frame is sent */
        unsigned retry = 0;
        do
            tx_count_after = readl(&priv->registers[
                    REG_PORT_STAT_INDEX(priv->port, REG_PORT_STAT_TX)]);
        while (tx_count_after == tx_count_before && ++retry < 1000);

        tx_timestamp = readl(&priv->registers[
                REG_PORT_INDEX(priv->port, REG_PORT_TX_LAST_TIME)]);
        tx_count_final = readl(&priv->registers[
                REG_PORT_STAT_INDEX(priv->port, REG_PORT_STAT_TX)]);

        if (tx_count_after == tx_count_before + 1 &&
                tx_count_final == tx_count_after)
        {
            /* Timestamp is valid */
            struct skb_shared_hwtstamps hwtstamps;
            memset(&hwtstamps, 0, sizeof(hwtstamps));
            hwtstamps.hwtstamp =
                exanic_ptp_time_to_ktime(priv->exanic, tx_timestamp);
            skb_tstamp_tx(skb, &hwtstamps);
        }
        else
        {
            /* Missed the timestamp */
            netdev_info(ndev, "tx timestamping failed\n");
        }
    }

    if (err)
        ndev->stats.tx_errors++;
    else
    {
        ndev->stats.tx_packets++;
        ndev->stats.tx_bytes += skb->len;
    }

    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}

/**
 * Update multicast and promiscuous mode setting on ExaNIC interface.
 *
 * Currently all multicast packets are received by default.
 */
static void exanic_netdev_set_rx_mode(struct net_device *ndev)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    uint32_t reg;

    reg = readl(&priv->registers[REG_PORT_INDEX(priv->port, REG_PORT_FLAGS)]);
    if (ndev->flags & IFF_PROMISC)
        reg |= EXANIC_PORT_FLAG_PROMISCUOUS;
    else
        reg &= ~EXANIC_PORT_FLAG_PROMISCUOUS;
    writel(reg, &priv->registers[REG_PORT_INDEX(priv->port, REG_PORT_FLAGS)]);
}

/**
 * Set the MAC address of an ExaNIC interface.
 */
static int exanic_netdev_set_mac_addr(struct net_device *ndev, void *p)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    struct mutex *mutex = exanic_mutex(priv->exanic);
    struct sockaddr *addr = p;
    u8 mac_addr[ETH_ALEN];
    int err;

    mutex_lock(mutex);

    err = exanic_set_mac_addr_regs(priv->exanic, priv->port, addr->sa_data);
    if (!err)
        err = exanic_get_mac_addr_regs(priv->exanic, priv->port, mac_addr);
    if (!err)
        memcpy(ndev->dev_addr, mac_addr, ETH_ALEN);

    mutex_unlock(mutex);

    return err;
}

/**
 * Handle user setting the MTU on an ExaNIC interface.
 */
static int exanic_netdev_change_mtu(struct net_device *ndev, int new_mtu)
{
    if (netif_running(ndev))
        return -EBUSY;

    ndev->mtu = new_mtu;
    return 0;
}

/**
 * Handle ioctl request on a ExaNIC interface.
 */
int exanic_netdev_ioctl(struct net_device *ndev, struct ifreq *ifr, int cmd)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    struct exanic *exanic = priv->exanic;

    switch (cmd)
    {
    case SIOCSHWTSTAMP:
        {
            struct hwtstamp_config config;

            if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
                return -EFAULT;

            /* reserved for future extensions */
            if (config.flags)
                return -EINVAL;

            if (config.tx_type != HWTSTAMP_TX_OFF &&
                    config.tx_type != HWTSTAMP_TX_ON)
                return -ERANGE;

            if (config.tx_type == HWTSTAMP_TX_OFF)
            {
                if (priv->tx_hw_tstamp)
                {
                    priv->tx_hw_tstamp = false;
                    netdev_info(ndev, "hardware tx timestamping disabled\n");
                }
            }
            else
            {
                if (!priv->tx_hw_tstamp)
                {
                    priv->tx_hw_tstamp = true;
                    netdev_info(ndev, "hardware tx timestamping enabled\n");
                }
            }

            if (config.rx_filter == HWTSTAMP_FILTER_NONE)
            {
                if (priv->rx_hw_tstamp)
                {
                    priv->rx_hw_tstamp = false;
                    netdev_info(ndev, "hardware rx timestamping disabled\n");
                }
            }
            else
            {
                config.rx_filter = HWTSTAMP_FILTER_ALL;

                if (!priv->rx_hw_tstamp)
                {
                    priv->rx_hw_tstamp = true;
                    netdev_info(ndev, "hardware rx timestamping enabled\n");
                }
            }

            if (copy_to_user(ifr->ifr_data, &config, sizeof(config)))
                return -EFAULT;

            return 0;
        }
    case SIOCGHWTSTAMP:
    case EXAIOCGHWTSTAMP:
        {
            struct hwtstamp_config config;

            memset(&config, 0, sizeof(config));

            config.tx_type =
                priv->tx_hw_tstamp ? HWTSTAMP_TX_ON : HWTSTAMP_TX_OFF;
            config.rx_filter =
                priv->rx_hw_tstamp ? HWTSTAMP_FILTER_ALL : HWTSTAMP_FILTER_NONE;

            if (copy_to_user(ifr->ifr_data, &config, sizeof(config)))
                return -EFAULT;

            return 0;
        }
    case EXAIOCGIFINFO:
        {
            /* Provide device name and port number to user */
            struct exaioc_ifinfo info;
            memset(&info, 0, sizeof(info));
            strncpy(info.dev_name, exanic->name, sizeof(info.dev_name) - 1);
            info.port_num = priv->port;
            if (copy_to_user(ifr->ifr_data, &info, sizeof(info)))
                return -EFAULT;
            return 0;
        }
    default:
        return -EOPNOTSUPP;
    }
}

static struct net_device_ops exanic_ndos = {
    .ndo_open               = exanic_netdev_open,
    .ndo_stop               = exanic_netdev_stop,
    .ndo_start_xmit         = exanic_netdev_xmit,
    .ndo_set_rx_mode        = exanic_netdev_set_rx_mode,
    .ndo_set_mac_address    = exanic_netdev_set_mac_addr,
    .ndo_change_mtu         = exanic_netdev_change_mtu,
    .ndo_do_ioctl           = exanic_netdev_ioctl,
};

static int exanic_netdev_get_settings(struct net_device *ndev,
                                      struct ethtool_cmd *cmd)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    uint32_t reg;

    reg = readl(&priv->registers[REG_EXANIC_INDEX(REG_EXANIC_CAPS)]);
    cmd->supported = SUPPORTED_FIBRE;
    if (reg & EXANIC_CAP_100M)
        cmd->supported |= SUPPORTED_100baseT_Full | SUPPORTED_Autoneg;
    if (reg & EXANIC_CAP_1G)
        cmd->supported |= SUPPORTED_1000baseT_Full | SUPPORTED_1000baseKX_Full | SUPPORTED_Autoneg;
    if (reg & EXANIC_CAP_10G)
        cmd->supported |= SUPPORTED_10000baseKR_Full;
    if (reg & EXANIC_CAP_40G)
         cmd->supported |= SUPPORTED_40000baseCR4_Full |
                           SUPPORTED_40000baseSR4_Full |
                           SUPPORTED_40000baseLR4_Full;

    reg = readl(&priv->registers[REG_PORT_INDEX(priv->port, REG_PORT_SPEED)]);
    ethtool_cmd_speed_set(cmd, reg);

    cmd->duplex = DUPLEX_FULL;
    cmd->port = PORT_FIBRE;
    cmd->transceiver = XCVR_INTERNAL;

    reg = readl(&priv->registers[REG_PORT_INDEX(priv->port, REG_PORT_FLAGS)]);
    if (reg & EXANIC_PORT_FLAG_AUTONEG_ENABLE)
        cmd->autoneg = AUTONEG_ENABLE;
    else
        cmd->autoneg = AUTONEG_DISABLE;

    return 0;
}

static int exanic_netdev_set_settings(struct net_device *ndev,
                                      struct ethtool_cmd *cmd)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    uint32_t reg, speed, caps;

    caps = readl(&priv->registers[REG_EXANIC_INDEX(REG_EXANIC_CAPS)]);

    speed = ethtool_cmd_speed(cmd);
    reg = readl(&priv->registers[REG_PORT_INDEX(priv->port, REG_PORT_SPEED)]);
    if (speed != reg)
    {
        if ((speed == SPEED_100 && (caps & EXANIC_CAP_100M)) ||
            (speed == SPEED_1000 && (caps & EXANIC_CAP_1G)) ||
            (speed == SPEED_10000 && (caps & EXANIC_CAP_10G)) ||
            (speed == SPEED_40000 && (caps & EXANIC_CAP_40G)))
        {
            /* Card specific updates */
            if (priv->exanic->hw_id == EXANIC_HW_X4 ||
                    priv->exanic->hw_id == EXANIC_HW_X2 ||
                        priv->exanic->hw_id == EXANIC_HW_X10 ||
                            priv->exanic->hw_id == EXANIC_HW_X10_GM ||
                            priv->exanic->hw_id == EXANIC_HW_X40 ||
                            priv->exanic->hw_id == EXANIC_HW_V5P)
            {
                if (exanic_x4_x2_set_speed(priv->exanic, priv->port, reg, speed))
                    return -EINVAL;
                exanic_x4_x2_save_speed(priv->exanic, priv->port, speed);
            }

            /* Change port speed, even if the port is up */
            writel(speed, &priv->registers[REG_PORT_INDEX(priv->port,
                        REG_PORT_SPEED)]);
        }
        else
        {
            /* Invalid speed */
            return -EINVAL;
        }
    }

    reg = readl(&priv->registers[REG_PORT_INDEX(priv->port, REG_PORT_FLAGS)]);
    if (cmd->autoneg == AUTONEG_ENABLE)
        reg |= EXANIC_PORT_FLAG_AUTONEG_ENABLE;
    else
        reg &= ~EXANIC_PORT_FLAG_AUTONEG_ENABLE;
    writel(reg, &priv->registers[REG_PORT_INDEX(priv->port, REG_PORT_FLAGS)]);

    if (priv->exanic->hw_id == EXANIC_HW_X4 ||
            priv->exanic->hw_id == EXANIC_HW_X2 ||
                priv->exanic->hw_id == EXANIC_HW_X10 ||
                    priv->exanic->hw_id == EXANIC_HW_X10_GM ||
                    priv->exanic->hw_id == EXANIC_HW_X40 ||
                    priv->exanic->hw_id == EXANIC_HW_V5P)
        exanic_x4_x2_save_autoneg(priv->exanic, priv->port,
                                  cmd->autoneg == AUTONEG_ENABLE);

    return 0;
}

static void exanic_netdev_get_drvinfo(struct net_device *ndev,
                                      struct ethtool_drvinfo *info)
{
    strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
    strlcpy(info->version, DRV_VERSION, sizeof(info->version));
    strlcpy(info->bus_info, dev_name(ndev->dev.parent), sizeof(info->bus_info));
}

static u32 exanic_netdev_get_link(struct net_device *ndev)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    uint32_t reg;

    reg = readl(&priv->registers[REG_PORT_INDEX(priv->port, REG_PORT_STATUS)]);
    return !!(reg & EXANIC_PORT_STATUS_LINK);
}

/* Definitions for ethtool priv flags interface */
enum {
    EXANIC_PFLAG_BYPASS_ONLY,
    EXANIC_PFLAG_MIRROR_RX,
    EXANIC_PFLAG_MIRROR_TX,
    EXANIC_PFLAG_BRIDGE,
    EXANIC_PFLAG_LEN
};

static const char exanic_priv_flags_str[EXANIC_PFLAG_LEN][ETH_GSTRING_LEN] = {
    "bypass_only",
    "mirror_rx",
    "mirror_tx",
    "bridging",
};

static void exanic_netdev_get_strings(struct net_device *ndev, u32 stringset,
                                      u8 *data)
{
    switch (stringset)
    {
    case ETH_SS_PRIV_FLAGS:
        memcpy(data, exanic_priv_flags_str, EXANIC_PFLAG_LEN * ETH_GSTRING_LEN);
        break;
    }
}

static int exanic_netdev_get_sset_count(struct net_device *ndev, int sset)
{
    switch (sset)
    {
    case ETH_SS_PRIV_FLAGS:
        return EXANIC_PFLAG_LEN;
    default:
        return -EINVAL;
    }
}

static u32 exanic_netdev_get_priv_flags(struct net_device *ndev)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    bool state;
    u32 flags = 0;

    if (priv->bypass_only)
        flags |= (1 << EXANIC_PFLAG_BYPASS_ONLY);

    exanic_get_feature_cfg(priv->exanic, priv->port, EXANIC_MIRROR_RX, &state);
    if (state)
        flags |= (1 << EXANIC_PFLAG_MIRROR_RX);

    exanic_get_feature_cfg(priv->exanic, priv->port, EXANIC_MIRROR_TX, &state);
    if (state)
        flags |= (1 << EXANIC_PFLAG_MIRROR_TX);

    exanic_get_feature_cfg(priv->exanic, priv->port, EXANIC_BRIDGE, &state);
    if (state)
        flags |= (1 << EXANIC_PFLAG_BRIDGE);

    return flags;
}

static int exanic_netdev_set_priv_flags(struct net_device *ndev, u32 flags)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    struct mutex *mutex = exanic_mutex(priv->exanic);
    int err = 0;

    mutex_lock(mutex);

    if (priv->exanic->function_id == EXANIC_FUNCTION_NIC ||
        priv->exanic->function_id == EXANIC_FUNCTION_PTP_GM ||
        priv->exanic->function_id == EXANIC_FUNCTION_DEVKIT)
    {
        bool bypass_only = ((flags & (1 << EXANIC_PFLAG_BYPASS_ONLY)) != 0);
        bool mirror_rx = ((flags & (1 << EXANIC_PFLAG_MIRROR_RX)) != 0);
        bool mirror_tx = ((flags & (1 << EXANIC_PFLAG_MIRROR_TX)) != 0);
        bool bridge = ((flags & (1 << EXANIC_PFLAG_BRIDGE)) != 0);

        if (bypass_only && !priv->bypass_only)
        {
            /* Bypass only mode on */
            if (ndev->flags & IFF_UP)
                exanic_netdev_kernel_stop(ndev);
            priv->bypass_only = true;
            netdev_info(ndev, "bypass only mode on\n");
        }
        else if (!bypass_only && priv->bypass_only)
        {
            /* Bypass only mode off */
            if (ndev->flags & IFF_UP)
            {
                err = exanic_netdev_kernel_start(ndev);
                if (err)
                    goto out;
            }
            priv->bypass_only = false;
            netdev_info(ndev, "bypass only mode off\n");
        }

        /* Set RX mirroring mode */
        err = exanic_set_feature_cfg(priv->exanic, priv->port, EXANIC_MIRROR_RX,
                mirror_rx);
        if (err)
            goto out;

        /* Set TX mirroring mode */
        err = exanic_set_feature_cfg(priv->exanic, priv->port, EXANIC_MIRROR_TX,
                mirror_tx);
        if (err)
            goto out;

        /* Set bridging mode */
        err = exanic_set_feature_cfg(priv->exanic, priv->port, EXANIC_BRIDGE,
                bridge);
        if (err)
            goto out;
    }

out:
    mutex_unlock(mutex);
    return err;
}

static int exanic_netdev_get_coalesce(struct net_device *ndev,
                                      struct ethtool_coalesce *ec)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    ec->rx_coalesce_usecs = priv->rx_coalesce_timeout_ns / 1000;
    return 0;
}

static int exanic_netdev_set_coalesce(struct net_device *ndev,
                                      struct ethtool_coalesce *ec)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);

    if (ec->rx_coalesce_usecs > MAX_RX_COALESCE_US)
      return -EINVAL;

    priv->rx_coalesce_timeout_ns = ec->rx_coalesce_usecs * 1000;
    return 0;
}

#if defined(ETHTOOL_GET_TS_INFO)
static int exanic_netdev_get_ts_info(struct net_device *ndev,
                                     struct ethtool_ts_info *eti)
{
#if defined(CONFIG_PTP_1588_CLOCK) || defined(CONFIG_PTP_1588_CLOCK_MODULE)
    struct exanic_netdev_priv *priv = netdev_priv(ndev);

    if (priv->exanic->ptp_clock != NULL)
    {
        eti->so_timestamping = SOF_TIMESTAMPING_RX_HARDWARE |
            SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE |
            SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE |
            SOF_TIMESTAMPING_RAW_HARDWARE;
        eti->phc_index = ptp_clock_index(priv->exanic->ptp_clock);
        eti->tx_types = (1 << HWTSTAMP_TX_OFF) | (1 << HWTSTAMP_TX_ON);
        eti->rx_filters = (1 << HWTSTAMP_FILTER_NONE) |
            (1 << HWTSTAMP_FILTER_ALL);
    }
    else
#endif
    {
        eti->so_timestamping = SOF_TIMESTAMPING_RX_SOFTWARE |
            SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;
        eti->phc_index = -1;
        eti->tx_types = 0;
        eti->rx_filters = 0;
    }

    return 0;
}
#endif

static struct ethtool_ops exanic_ethtool_ops = {
    .get_settings           = exanic_netdev_get_settings,
    .set_settings           = exanic_netdev_set_settings,
    .get_drvinfo            = exanic_netdev_get_drvinfo,
    .get_link               = exanic_netdev_get_link,
    .get_strings            = exanic_netdev_get_strings,
    .get_priv_flags         = exanic_netdev_get_priv_flags,
    .set_priv_flags         = exanic_netdev_set_priv_flags,
    .get_sset_count         = exanic_netdev_get_sset_count,
    .get_coalesce           = exanic_netdev_get_coalesce,
    .set_coalesce           = exanic_netdev_set_coalesce,
#if defined(ETHTOOL_GET_TS_INFO) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
    .get_ts_info            = exanic_netdev_get_ts_info,
#endif
};

#if defined(ETHTOOL_GET_TS_INFO) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
/* RedHat 2.6.x backports place get_ts_info in ethtool_ops_ext */
static struct ethtool_ops_ext exanic_ethtool_ops_ext = {
    .size                   = sizeof(struct ethtool_ops_ext),
    .get_ts_info            = exanic_netdev_get_ts_info
};
#define SET_ETHTOOL_OPS_EXT(ndev, ops) set_ethtool_ops_ext(ndev, ops)
#else
#define SET_ETHTOOL_OPS_EXT(ndev, ops)
#endif

static void exanic_deliver_skb(struct sk_buff *skb)
{
    struct exanic_netdev_intercept *i;

    /* Send packet to packet intercept functions */
    list_for_each_entry(i, &intercept_funcs, list)
        if (i->func(skb))
            return;

    /* Packet was not intercepted, send packet to kernel stack */
    netif_receive_skb(skb);
}

/**
 * Poll for new packets on an ExaNIC interface.
 */
static int exanic_netdev_poll(struct napi_struct *napi, int budget)
{
    struct exanic_netdev_priv *priv =
        container_of(napi, struct exanic_netdev_priv, napi);
    struct exanic_netdev_rx *rx = &priv->rx;
    struct net_device *ndev = priv->ndev;
    size_t max_frame_size = ndev->mtu + MAX_ETH_OVERHEAD_BYTES;
    int received = 0, chunk_count = 0;
    ssize_t len;
    uint32_t chunk_id = 0, tstamp;
    char *ptr = NULL;
    int more_chunks = 0;
    ktime_t interval;

    while (received < budget && chunk_count < POLL_MAX_CHUNKS)
    {
        if (priv->skb == NULL)
        {
            /* New packet */
            priv->skb = netdev_alloc_skb(ndev, max_frame_size + NET_IP_ALIGN);
            if (priv->skb == NULL)
                break;
            skb_reserve(priv->skb, NET_IP_ALIGN);
            priv->length_error = false;
        }

        chunk_count++;
        len = exanic_receive_chunk_inplace(rx, &ptr, &chunk_id, &more_chunks);
        if (len == 0)
            break;
        else if (len < 0)
        {
            /* Receive error */
            ndev->stats.rx_errors++;
            if (len == -EXANIC_RX_FRAME_SWOVFL)
                ndev->stats.rx_fifo_errors++;
            else if (len == -EXANIC_RX_FRAME_CORRUPT)
                ndev->stats.rx_crc_errors++;
            dev_kfree_skb(priv->skb);
            priv->skb = NULL;
            received++;
            continue;
        }
        else if (len > skb_tailroom(priv->skb))
        {
            /* Packet too large */
            len = skb_tailroom(priv->skb);
            priv->length_error = true;
        }

        /* Record chunk id of first chunk */
        if (priv->skb->len == 0)
            priv->hdr_chunk_id = chunk_id;

        /* Copy chunk data */
        memcpy(skb_put(priv->skb, len), ptr, len);

        if (!more_chunks)
        {
            if (priv->length_error)
            {
                /* Packet was truncated because it was too large */
                ndev->stats.rx_length_errors++;
                dev_kfree_skb(priv->skb);
                priv->skb = NULL;
                received++;
                continue;
            }

            tstamp = exanic_receive_chunk_timestamp(rx, priv->hdr_chunk_id);

            if (!exanic_receive_chunk_recheck(rx, priv->hdr_chunk_id))
            {
                /* Chunk was overwritten while we were reading */
                ndev->stats.rx_errors++;
                ndev->stats.rx_fifo_errors++;
                dev_kfree_skb(priv->skb);
                priv->skb = NULL;
                received++;
                continue;
            }

            priv->skb->protocol = eth_type_trans(priv->skb, ndev);

            /* Calculate hardware timestamp if enabled */
            if (priv->rx_hw_tstamp)
            {
                skb_hwtstamps(priv->skb)->hwtstamp =
                    exanic_ptp_time_to_ktime(priv->exanic, tstamp);
            }

            ndev->stats.rx_packets++;
            ndev->stats.rx_bytes += priv->skb->len;

            /* Deliver packet to intercept functions or kernel stack */
            exanic_deliver_skb(priv->skb);
            priv->skb = NULL;
            received++;
        }
    }

    if (priv->skb != NULL && priv->skb->len == 0)
    {
        /* Discard zero length skb */
        dev_kfree_skb(priv->skb);
        priv->skb = NULL;
    }

    if (received < budget)
    {
        napi_complete(napi);

        if (exanic_rx_ready(rx))
        {
            /* Poll again as soon as possible */
            napi_reschedule(napi);
        }
        else if (priv->rx_coalesce_timeout_ns > 0)
        {
            /* Sleep a little before re-arming interrupt */
            interval = ktime_set(0, priv->rx_coalesce_timeout_ns);
            hrtimer_start(&priv->rx_hrtimer, interval, HRTIMER_MODE_REL);
        }
        else
        {
            exanic_rx_set_irq(rx);
        }
    }

    return received;
}

/**
 * Allocate and register an exanic ethernet interface.
 *
 * This presents one port of the exanic as an ethernet device to
 * the Linux network stack.
 */
int exanic_netdev_alloc(struct exanic *exanic, unsigned port,
                        struct net_device **ndev_ptr)
{
    struct exanic_netdev_priv *priv;
    struct net_device *ndev;
    u8 mac_addr[ETH_ALEN];
    int err;

    ndev = alloc_etherdev(sizeof(struct exanic_netdev_priv));
    if (!ndev)
    {
        err = -ENOMEM;
        goto err_alloc;
    }

    priv = netdev_priv(ndev);
    priv->ndev = ndev;
    priv->exanic = exanic;
    priv->ctx = NULL;
    priv->port = port;
    priv->registers = exanic_registers(exanic);
    priv->skb = NULL;

    spin_lock_init(&priv->tx_lock);

    SET_NETDEV_DEV(ndev, exanic_dev(exanic));
    netif_napi_add(ndev, &priv->napi, exanic_netdev_poll, 64);
    ndev->ethtool_ops = &exanic_ethtool_ops;
    SET_ETHTOOL_OPS_EXT(ndev, &exanic_ethtool_ops_ext);
    ndev->netdev_ops = &exanic_ndos;

    err = exanic_get_mac_addr_regs(exanic, port, mac_addr);
    if (!err)
        memcpy(ndev->dev_addr, mac_addr, ETH_ALEN);

    memcpy(ndev->perm_addr, exanic->port[port].orig_mac_addr, ETH_ALEN);

#if __HAS_NETDEVICE_DEV_PORT
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
    /* RedHat 2.6.x backports place this member under netdev_extended */
    netdev_extended(ndev)->dev_port = port;
#else
    ndev->dev_port = port;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
    /* Allow jumbo frames (in 4.10+ MTU limit is 1500 by default) */
    ndev->max_mtu = 9000;
#endif

    if (priv->exanic->function_id != EXANIC_FUNCTION_NIC &&
            priv->exanic->function_id != EXANIC_FUNCTION_PTP_GM &&
                priv->exanic->function_id != EXANIC_FUNCTION_DEVKIT)
    {
        /* Only NICs, PTP masters, and devkits can function as a normal network
         * interface */
        priv->bypass_only = true;
    }

    err = register_netdev(ndev);
    if (err)
        goto err_register;

    netdev_info(ndev, "ExaNIC ethernet interface %s:%d, hwaddr %pM\n",
            exanic->name, port, mac_addr);

    /* Update link status */
    exanic_netdev_check_link(ndev);

    *ndev_ptr = ndev;
    return 0;

err_register:
    free_netdev(ndev);
err_alloc:
    return err;
}

/**
 * Unregister and deallocate an exanic ethernet interface.
 */
void exanic_netdev_free(struct net_device *ndev)
{
    if (!ndev)
        return;
    flush_scheduled_work();
    unregister_netdev(ndev);
    free_netdev(ndev);
}

/**
 * Check link status and call netif_carrier_on() or netif_carrier_off().
 */
void exanic_netdev_check_link(struct net_device *ndev)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    uint32_t reg;

    reg = readl(&priv->registers[REG_PORT_INDEX(priv->port, REG_PORT_STATUS)]);
    if (reg & EXANIC_PORT_STATUS_LINK)
    {
        if (!netif_carrier_ok(ndev))
            netif_carrier_on(ndev);
    }
    else if (netif_carrier_ok(ndev))
        netif_carrier_off(ndev);
}

/**
 * Send a packet on an ExaNIC interface.
 */
int exanic_transmit_frame(struct net_device *ndev, struct sk_buff *skb)
{
    struct exanic_netdev_priv *priv = netdev_priv(ndev);
    int err;
    unsigned long flags;

    spin_lock_irqsave(&priv->tx_lock, flags);

    if (priv->tx.buffer == NULL)
    {
        netdev_err(ndev, "TX not enabled\n");
        spin_unlock_irqrestore(&priv->tx_lock, flags);
        dev_kfree_skb(skb);
        return -1;
    }

    err = __exanic_transmit_frame(&priv->tx, skb);

    spin_unlock_irqrestore(&priv->tx_lock, flags);
    dev_kfree_skb(skb);
    return err;
}
EXPORT_SYMBOL(exanic_transmit_frame);

/**
 * Add a function to intercept incoming frames before the Linux stack.
 *
 * The intercept function is to return true if the frame is consumed,
 * and false if the frame needs to continue up the stack.
 */
int exanic_netdev_intercept_add(exanic_netdev_intercept_func func)
{
    struct exanic_netdev_intercept *f;

    f = kmalloc(sizeof(struct exanic_netdev_intercept), GFP_KERNEL);
    if (f == NULL)
        return -ENOMEM;

    f->func = func;

    list_add_tail(&f->list, &intercept_funcs);

    return 0;
}
EXPORT_SYMBOL(exanic_netdev_intercept_add);

/**
 * Remove the intercept function from the list.
 */
void exanic_netdev_intercept_remove(exanic_netdev_intercept_func func)
{
    struct exanic_netdev_intercept *f;

    list_for_each_entry(f, &intercept_funcs, list)
    {
        if (f->func == func)
        {
            list_del(&f->list);
            kfree(f);
            return;
        }
    }
}
EXPORT_SYMBOL(exanic_netdev_intercept_remove);
