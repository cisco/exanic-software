/**
 * TCP acceleration engine management
 * Copyright (C) 2011-2013 Exablaze Pty Ltd and its licensors
 */

#include <linux/pci.h>
#include <linux/miscdevice.h>

#include <linux/etherdevice.h>
#include <linux/types.h>

#include "../../libs/exanic/checksum.h"
#include "../../libs/exanic/const.h"
#include "../../libs/exanic/pcie_if.h"
#include "exanic.h"
#include "exanic-structs.h"

static exanic_ate_client_process_skb_cb exanic_ate_client_process_skb;
static DEFINE_RWLOCK(exanic_ate_client_lock);

#define WRITE_ATE_PORT32(port, ate_id, whichreg, val)   \
        writel((val), exanic->regs_virt +                       \
               REG_ATE_OFFSET(port, ate_id, whichreg))

#define READ_ATE_PORT32(port, ate_id, whichreg)               \
        readl(exanic->regs_virt + REG_ATE_OFFSET(port, ate_id, whichreg))


/*
 * For the window size, hardware expects the size to be in the upper 16 bits
 * (and in network byte order), but it uses the whole register for
 * calculating the checksum. so, we need to make sure the lower bits are
 * zero.
 */
#define CONVERT_HW_WINDOW(sz)                   \
(htons(sz & 0xffff) << 16)

/**
 * Check that ATE is available on the device, and allocate the ATE ID.
 * Returns false if ATE not available or ATE ID already allocated.
 */
int exanic_ate_acquire(struct exanic *exanic,
                                unsigned port_num, int ate_id)
{
    int err = 0;
    if (ate_id >= EXANIC_ATE_ENGINES_PER_PORT)
        return -EINVAL;

    if (exanic->devkit_regs_virt == 0)
        return -EOPNOTSUPP;

    if (!(exanic->caps & EXANIC_CAP_ATE))
        return -EOPNOTSUPP;

    if (!(exanic->port[port_num].has_ate))
        return -EOPNOTSUPP;

    err = down_interruptible(
            &exanic->port[port_num].ate_lockbox[ate_id]);
    if (err)
        return err;

    return 0;
}

/**
 * Deallocate an ATE on an exanic
 */
void exanic_ate_release(struct exanic *exanic, unsigned port_num, int ate_id)
{
    if (ate_id >= EXANIC_ATE_ENGINES_PER_PORT)
        return;

    up(&exanic->port[port_num].ate_lockbox[ate_id]);
}

/**
 * Turn off an ATE
 */
void exanic_ate_disable(struct exanic *exanic, unsigned port_num, int ate_id)
{
    uint32_t ctl_reg;

    if (ate_id >= EXANIC_ATE_ENGINES_PER_PORT)
        return;

    /* Disable ATE */
    ctl_reg = READ_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_CTL);
    ctl_reg &= ~EXANIC_ATE_CTL_ENABLED;
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_CTL, ctl_reg);
}

/**
 * Hand off new connection to hardware TCP transmit engine
 */
int exanic_ate_init(struct exanic* exanic, unsigned port_num, int ate_id,
                    struct exanic_ate_cfg *cfg)
{
    uint32_t reg;
    uint16_t csum_ip;
    uint16_t csum_tcp;
    uint32_t csum_scratch[3];

    if (exanic->devkit_regs_virt == 0)
        return -EOPNOTSUPP;

    csum_scratch[0] = htonl(cfg->ip_src);
    csum_scratch[1] = htonl(cfg->ip_dst);
    csum_ip = csum(csum_scratch, 8, 0xc506);

    csum_scratch[2] = (htons(cfg->port_src) << 16) | htons(cfg->port_dst);
    csum_tcp = csum(csum_scratch, 12, 0x501a);

    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_DST_MAC_ADDR_HI,
                     cfg->eth_dst[0] | (cfg->eth_dst[1] << 8) |
                     (cfg->eth_dst[2] << 16) | (cfg->eth_dst[3] << 24));
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_DST_HI_SRC_LO_MAC_ADDR_HI,
                     cfg->eth_dst[4] | (cfg->eth_dst[5] << 8) |
                     (cfg->eth_src[0] << 16) | (cfg->eth_src[1] << 24));
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_SRC_MAC_ADDR_LO,
                     cfg->eth_src[2] | (cfg->eth_src[3] << 8) |
                     (cfg->eth_src[4] << 16) | (cfg->eth_src[5] << 24));
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_TCP_IP_PART_CKSUMS,
                     (csum_tcp << 16) | csum_ip);
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_SRC_IP, cfg->ip_src);
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_DST_IP, cfg->ip_dst);
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_SRC_DST_PORT,
                     (cfg->port_dst << 16) | cfg->port_src);
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_SEQ, cfg->init_seq_num);
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_ACK, cfg->ack_num);
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_WINDOW, CONVERT_HW_WINDOW(cfg->window));

    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_ACK_2, cfg->ack_num);
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_WINDOW_2, CONVERT_HW_WINDOW(cfg->window));
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_MAX_SEQ, cfg->max_seq_num);

    reg = 0;
    reg |= EXANIC_ATE_CTL_ENABLED;
    if (!cfg->win_limit_disabled)
        reg |= EXANIC_ATE_CTL_CHECK_SEQ;
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_CTL, reg);

    return 0;
}

int exanic_ate_update(struct exanic* exanic, unsigned port_num, int ate_id,
                      struct exanic_ate_update *cfg)
{
    uint32_t ctl;

    if (exanic->devkit_mem_virt == 0)
        return -EOPNOTSUPP;

    ctl = READ_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_CTL);
    if ((ctl & EXANIC_ATE_CTL_CURR_BUF) == 0)
    {
        WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_ACK_2, cfg->ack_num);
        WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_WINDOW_2, CONVERT_HW_WINDOW(cfg->window));
        ctl |= EXANIC_ATE_CTL_CURR_BUF;
    }
    else
    {
        WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_ACK, cfg->ack_num);
        WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_WINDOW, CONVERT_HW_WINDOW(cfg->window));
        ctl &= ~EXANIC_ATE_CTL_CURR_BUF;
    }

    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_CTL, ctl);
    WRITE_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_MAX_SEQ, cfg->max_seq_num);

    return 0;
}

void exanic_ate_regdump(struct exanic *exanic, unsigned port_num,
                        int ate_id, struct exanic_ate_regdump *cfg)
{
    /* dump the following registers into cfg:
     * seq, max-seq, ack1, win1, ack2, win2, ctl */
    *cfg = (struct exanic_ate_regdump)
    {
        .ack = READ_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_ACK),
        .ack2 = READ_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_ACK_2),
        .win = READ_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_WINDOW),
        .win2 = READ_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_WINDOW_2),
        .ctrl = READ_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_CTL),
        .seq = exanic_ate_read_seq(exanic, port_num, ate_id)
    };
}

uint32_t exanic_ate_read_seq(struct exanic* exanic, unsigned port_num,
                             int ate_id)
{
    return READ_ATE_PORT32(port_num, ate_id, EXANIC_ATE_REGS_SEQ);
}

void exanic_ate_deliver_skb(struct sk_buff *skb)
{
    read_lock(&exanic_ate_client_lock);
    if (exanic_ate_client_process_skb)
        exanic_ate_client_process_skb(skb);
    read_unlock(&exanic_ate_client_lock);
}

/**
 * Register ATE client's callback function to process frames received from
 * ExaNIC's Accelerated TCP Engine.
 */
int exanic_ate_client_register(exanic_ate_client_process_skb_cb cb)
{
    write_lock_bh(&exanic_ate_client_lock);
    if (exanic_ate_client_process_skb != NULL)
    {
        write_unlock_bh(&exanic_ate_client_lock);
        return -EBUSY;
    }

    exanic_ate_client_process_skb = cb;
    write_unlock_bh(&exanic_ate_client_lock);

    return 0;
}
EXPORT_SYMBOL(exanic_ate_client_register);

/**
 * Release the ATE client's callback function.
 */
void exanic_ate_client_unregister(exanic_ate_client_process_skb_cb cb)
{
    write_lock_bh(&exanic_ate_client_lock);
    if (exanic_ate_client_process_skb != cb)
    {
        write_unlock_bh(&exanic_ate_client_lock);
        return;
    }

    exanic_ate_client_process_skb = NULL;
    write_unlock_bh(&exanic_ate_client_lock);
    return;
}
EXPORT_SYMBOL(exanic_ate_client_unregister);
