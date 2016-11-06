/**
 * Kernel support for the ExaSock library
 * Copyright (C) 2011-2013 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/ip.h>

#include "../../libs/exasock/kernel/api.h"
#include "../../libs/exasock/kernel/structs.h"

#include "../exanic/exanic.h"
#include "exasock.h"

int exasock_ip_send(uint8_t proto, uint32_t dst_addr, uint32_t src_addr,
                    struct sk_buff *skb)
{
    struct iphdr *iph;

    iph = (struct iphdr *)skb_push(skb, sizeof(struct iphdr));

    memset(iph, 0, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = sizeof(struct iphdr) / 4;
    iph->tot_len = htons(skb->len);
    iph->frag_off = htons(IP_DF);
    iph->ttl = IPDEFTTL;
    iph->protocol = proto;
    iph->saddr = src_addr;
    iph->daddr = dst_addr;
    iph->check = ip_fast_csum(iph, iph->ihl);

    skb_reset_network_header(skb);

    return exasock_dst_insert(dst_addr, NULL, NULL, skb);
}
