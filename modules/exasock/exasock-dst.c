/**
 * Kernel support for the ExaSock library
 * Copyright (C) 2011-2013 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/hash.h>
#include <linux/vmalloc.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/arp.h>
#include <net/route.h>

#include "../../libs/exasock/kernel/api.h"
#include "../../libs/exasock/kernel/structs.h"

#include "../exanic/exanic.h"
#include "exasock.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
#define rtable_dst(rt) ((rt)->u.dst)
#else
#define rtable_dst(rt) ((rt)->dst)
#endif

#ifndef DEFINE_SEMAPHORE
#define DEFINE_SEMAPHORE DECLARE_MUTEX
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
#define __HAS_OLD_NETCORE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
#define __FILLS_RT_IIF
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) \
    && LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
#define __HAS_RT_TABLE_ID
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0)
  #if LINUX_VERSION_CODE > KERNEL_VERSION(3, 0, 75)
    /* SLES11 3.0.76 kernel */
    #define exasock_dst_neigh_lookup(dst, daddr) dst_get_neighbour(dst)
  #else
    #define exasock_dst_neigh_lookup(dst, daddr) ((dst)->neighbour)
  #endif
  #define exasock_dst_neigh_release(neigh)
#else
  #define exasock_dst_neigh_lookup(dst, daddr) dst_neigh_lookup(dst, daddr)
  #define exasock_dst_neigh_release(neigh)     neigh_release(neigh)
#endif

#define DEFAULT_DST_TABLE_SIZE (1 << 16)
#define DST_EXPIRY_TIME (300 * HZ)
#define NEIGH_HASH_BITS 12
#define NEIGH_HASH_SIZE (1 << NEIGH_HASH_BITS)

struct exasock_dst_entry
{
    struct rtable *     rt;
#ifndef __HAS_RT_TABLE_ID
    bool                default_rt;
#endif
    struct neighbour *  neigh;
#ifndef __HAS_OLD_NETCORE
    struct flowi4       fl4;
#endif
    unsigned long       used;
    unsigned int        idx;

    /* List of packets waiting for this entry to become valid */
    struct list_head    dst_queue;

    struct list_head    list;
    struct list_head    neigh_hash;
};

struct exasock_dst_queue_entry
{
    struct sk_buff *    skb;
    struct list_head    list;
};

static struct exasock_dst_entry **dst_table;
static size_t                   dst_table_size;
static struct list_head         dst_entries; /* Sorted by last used time */
static struct list_head *       dst_neigh_hash;
static DEFINE_SPINLOCK(         dst_lock);
static struct timer_list        dst_expiry_timer;
static bool                     dst_expiry_timer_running;

/* Shared memory for user to notify kernel of exa_dst_entry usage */
static uint8_t *                dst_used_flags;

/* User-visible copy of the destination table */
static struct exa_dst_entry *   dst_user_table;

static void __update_user_dst_entry(
#ifndef __HAS_RT_TABLE_ID
                                    bool default_rt,
#endif
                                    unsigned int idx)
{
    if (dst_table[idx])
    {
        struct neighbour *neigh = dst_table[idx]->neigh;
#if defined(__HAS_OLD_NETCORE) || defined(__HAS_RT_TABLE_ID)
        struct rtable *rt = dst_table[idx]->rt;
#endif
#ifndef __HAS_OLD_NETCORE
        struct flowi4 fl4 = dst_table[idx]->fl4;
        uint32_t dst_addr = fl4.daddr;
        uint32_t src_addr = fl4.saddr;
#else
        uint32_t dst_addr = rt->rt_dst;
        uint32_t src_addr = rt->rt_src;
#endif

        if (dst_user_table[idx].dst_addr == dst_addr &&
            dst_user_table[idx].src_addr == src_addr &&
            memcmp(dst_user_table[idx].eth_addr, neigh->ha, ETH_ALEN) == 0)
        {
            /* Avoid invalidating caches if no change */
            return;
        }

        /* Tell user processes to skip over this entry */
        dst_user_table[idx].state = EXA_DST_ENTRY_INVALID;

        dst_user_table[idx].dst_addr = dst_addr;
        dst_user_table[idx].src_addr = src_addr;
        memcpy(dst_user_table[idx].eth_addr, neigh->ha, ETH_ALEN);
        dst_user_table[idx].def_rt =
#ifdef __HAS_RT_TABLE_ID
            (rt->rt_table_id == RT_TABLE_MAIN ||
             rt->rt_table_id == RT_TABLE_DEFAULT) ? 1 : 0;
#else
            default_rt ? 1 : 0;
#endif
        if (neigh->nud_state & NUD_VALID)
            dst_user_table[idx].state = EXA_DST_ENTRY_VALID;
        else
            dst_user_table[idx].state = EXA_DST_ENTRY_INCOMPLETE;

        /* This will cause anyone who has cached this entry to refresh */
        dst_user_table[idx].gen_id++;
    }
    else
    {
        if (dst_user_table[idx].state == EXA_DST_ENTRY_EMPTY)
            return;

        dst_user_table[idx].state = EXA_DST_ENTRY_EMPTY;
        dst_user_table[idx].dst_addr = 0;
        dst_user_table[idx].src_addr = 0;
        memset(dst_user_table[idx].eth_addr, 0, ETH_ALEN);
        dst_user_table[idx].gen_id++;
    }
}

/* dst_entry must have been removed from the table and all lists already */
static void __free_dst_entry(struct exasock_dst_entry *de)
{
    struct exasock_dst_queue_entry *qe, *tmp;

    /* Clear dst_queue */
    list_for_each_entry_safe(qe, tmp, &(de->dst_queue), list)
    {
        list_del(&qe->list);
        kfree_skb(qe->skb);
        kfree(qe);
    }

    if (de->neigh)
        exasock_dst_neigh_release(de->neigh);

    if (de->rt)
        ip_rt_put(de->rt);

    kfree(de);
}

/* Find entry, returns next empty entry if not found, lock must be held */
static unsigned int __find_dst_entry(uint32_t daddr, uint32_t saddr)
{
    unsigned int hash, idx;

    hash = idx = exa_dst_hash(daddr) & (dst_table_size - 1);
    while (true)
    {
        if (dst_table[idx] == NULL ||
#ifndef __HAS_OLD_NETCORE
            (dst_table[idx]->fl4.daddr == daddr &&
             dst_table[idx]->fl4.saddr == saddr))
#else
            (dst_table[idx]->rt->rt_dst == daddr &&
             dst_table[idx]->rt->rt_src == saddr))
#endif
            return idx;

        idx = (idx + 1) & (dst_table_size - 1);
        if (idx == hash)
            return ~0;
    }
}

/* Update timer to fire at the expiry of the next entry, lock must be held */
static void __update_dst_expiry_timer(void)
{
    struct exasock_dst_entry *de;

    if (dst_expiry_timer_running && !list_empty(&dst_entries))
    {
        de = list_first_entry(&dst_entries, struct exasock_dst_entry, list);
        mod_timer(&dst_expiry_timer, de->used + DST_EXPIRY_TIME);
    }
}

/* Remove an entry from the hash table, lock must be held */
static void __remove_dst_entry(unsigned int idx)
{
    unsigned int empty_idx, hash_idx;
    uint32_t daddr;

    /* Remove the hash table entry */
    dst_table[idx] = NULL;
    empty_idx = idx;

    /* Shuffle entries up if necessary */
    while (true)
    {
        idx = (idx + 1) & (dst_table_size - 1);

        if (!dst_table[idx])
            break;

#ifndef __HAS_OLD_NETCORE
        daddr = dst_table[idx]->fl4.daddr;
#else
        daddr = dst_table[idx]->rt->rt_dst;
#endif
        hash_idx = exa_dst_hash(daddr) & (dst_table_size - 1);

        if (((idx - hash_idx) & (dst_table_size - 1)) >=
            ((idx - empty_idx) & (dst_table_size - 1)))
        {
            dst_table[empty_idx] = dst_table[idx];
            dst_table[empty_idx]->idx = empty_idx;
            dst_table[idx] = NULL;
            __update_user_dst_entry(
#ifndef __HAS_RT_TABLE_ID
                                    dst_table[empty_idx]->default_rt,
#endif
                                    empty_idx);
            empty_idx = idx;
        }
    }

    __update_user_dst_entry(
#ifndef __HAS_RT_TABLE_ID
                            false,
#endif
                            empty_idx);
}

/**
 * Find output interface and route.
 */
static struct net_device *__exasock_dst_get_if(uint32_t *saddr,
                                               struct rtable **rt,
#ifndef __HAS_OLD_NETCORE
                                               struct flowi4 *fl4)
#else
                                               struct flowi *fl)
#endif
{
    struct net_device *ndev;
    int oif;

#ifndef __HAS_OLD_NETCORE
    *rt = __ip_route_output_key(&init_net, fl4);
    if (IS_ERR(*rt))
#else
    *rt = NULL;
    if (__ip_route_output_key(&init_net, rt, fl) != 0)
#endif
        return NULL;

#ifndef __FILLS_RT_IIF
    *saddr = fl4->saddr;
    oif = fl4->flowi4_oif;
#else
    *saddr = (*rt)->rt_src;
    oif = (*rt)->rt_iif;
#endif
    ndev = dev_get_by_index(&init_net, oif);
    if (ndev == NULL)
    {
        ip_rt_put(*rt);
        *rt = NULL;
    }

    return ndev;
}

/* Check first entry in the list, remove if expired and adjust the table */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
static void dst_expiry_timer_handler(struct timer_list *t)
#else
static void dst_expiry_timer_handler(unsigned long data)
#endif
{
    struct neighbour *new_neigh;
    struct exasock_dst_entry *de;

    spin_lock_bh(&dst_lock);

    if (list_empty(&dst_entries))
    {
        __update_dst_expiry_timer();
        spin_unlock_bh(&dst_lock);
        return;
    }

    /* Get first entry in dst_entries list */
    de = list_first_entry(&dst_entries, struct exasock_dst_entry, list);

    BUG_ON(dst_table[de->idx] != de);

    if (time_after(de->used + DST_EXPIRY_TIME, jiffies))
    {
        /* Entry is not expiring yet - timer fired unexpectedly? */
        __update_dst_expiry_timer();
        spin_unlock_bh(&dst_lock);
        return;
    }

    /* Remove the entry if not used since last check */
    if (!dst_used_flags[de->idx])
        goto remove_entry;
    dst_used_flags[de->idx] = 0;

    /* Check route to see if it is stale */
#if __HAS_RT_GENID_GETTER_IPV4
    if (rt_genid_ipv4(dev_net(rtable_dst(de->rt).dev)) != de->rt->rt_genid)
#elif __HAS_RT_GENID_GETTER
    if (rt_genid(dev_net(rtable_dst(de->rt).dev)) != de->rt->rt_genid)
#else
    if (atomic_read(&dev_net(rtable_dst(de->rt).dev)->ipv4.rt_genid) !=
        de->rt->rt_genid)
#endif
    {
#ifndef __HAS_OLD_NETCORE
        struct flowi4 fl4 = { .daddr = de->fl4.daddr, .saddr = de->fl4.saddr };
#else
        struct flowi fl = {
            .nl_u = {
                .ip4_u = { .daddr = de->rt->rt_dst, .saddr = de->rt->rt_src },
            },
        };
#endif
        unsigned int hash;

        /* Release old neigbour and route cache entry */
        exasock_dst_neigh_release(de->neigh);
        de->neigh = NULL;
        ip_rt_put(de->rt);

        /* Get new route from routing table */
#ifndef __HAS_OLD_NETCORE
        de->rt = __ip_route_output_key(&init_net, &fl4);
        if (IS_ERR(de->rt))
#else
        if (__ip_route_output_key(&init_net, &de->rt, &fl) != 0)
#endif
        {
            de->rt = NULL;
            goto remove_entry;
        }

        new_neigh = exasock_dst_neigh_lookup(&rtable_dst(de->rt), &fl4.daddr);
        de->neigh = new_neigh;
        hash = hash_ptr(new_neigh, NEIGH_HASH_BITS);
        list_del(&de->neigh_hash);
        list_add_tail(&de->neigh_hash, &dst_neigh_hash[hash]);
        __update_user_dst_entry(
#ifndef __HAS_RT_TABLE_ID
                                de->default_rt,
#endif
                                de->idx);
    }

    /* Update last used time of entry */
    de->used = jiffies;
    list_del(&de->list);
    list_add_tail(&de->list, &dst_entries);
    __update_dst_expiry_timer();

    spin_unlock_bh(&dst_lock);

    /* Update Linux neighbour table usage */
    neigh_event_send(de->neigh, NULL);
    return;

remove_entry:
    list_del(&de->list);
    list_del(&de->neigh_hash);
    __remove_dst_entry(de->idx);
    __update_dst_expiry_timer();

    spin_unlock_bh(&dst_lock);

    __free_dst_entry(de);
}

/* Remove any packets pending in destination table queue related to a given
 * connection */
void exasock_dst_remove_socket(uint32_t local_addr, uint32_t peer_addr,
                               uint16_t local_port, uint16_t peer_port)
{
    struct exasock_dst_queue_entry *qe, *tmp;
    struct exasock_dst_entry *de;
    unsigned idx;

    spin_lock_bh(&dst_lock);

    idx = __find_dst_entry(peer_addr, local_addr);
    if ((idx == ~0) || dst_table[idx] == NULL)
        goto exit;

    de = dst_table[idx];

    list_for_each_entry_safe(qe, tmp, &de->dst_queue, list)
    {
        struct sk_buff *skb = qe->skb;
        struct iphdr *iph;
        struct tcphdr *th;

        iph = (struct iphdr *)skb->data;
        if (iph->protocol != IPPROTO_TCP)
            continue;
        th = (struct tcphdr *)(skb->data + iph->ihl * 4);
        if ((iph->saddr == local_addr) && (iph->daddr == peer_addr) &&
            (th->source == local_port) && (th->dest == peer_port))
        {
            dev_put(skb->dev);
            kfree_skb(skb);
            list_del(&qe->list);
            kfree(qe);
        }
    }
exit:
    spin_unlock_bh(&dst_lock);
}

/**
 * Update a table entry after a neighbour reply.
 */
void exasock_dst_neigh_update(struct neighbour *neigh)
{
    struct exasock_dst_entry *de;
    struct exasock_dst_queue_entry *qe, *tmp;
    unsigned int hash;
    LIST_HEAD(temp_head);

    if (!(neigh->nud_state & NUD_VALID))
        return;

    spin_lock_bh(&dst_lock);

    hash = hash_ptr(neigh, NEIGH_HASH_BITS);
    list_for_each_entry(de, &dst_neigh_hash[hash], neigh_hash)
    {
        if (de->neigh == neigh)
        {
            __update_user_dst_entry(
#ifndef __HAS_RT_TABLE_ID
                                    de->default_rt,
#endif
                                    de->idx);

            /* Move the packets on the queue to our temporary list */
            list_splice_tail_init(&de->dst_queue, &temp_head);
        }
    }

    /* Send packets in our temporary list */
    list_for_each_entry_safe(qe, tmp, &temp_head, list)
    {
        struct sk_buff *skb = qe->skb;
        struct net_device *skbdev = skb->dev;
        struct net_device *realdev = skbdev;

        /* Fill out ethernet header in packet */
#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
        if (skbdev->priv_flags & IFF_802_1Q_VLAN)
        {
            struct vlan_ethhdr *hdr;

            hdr = (struct vlan_ethhdr *)skb_push(skb, VLAN_ETH_HLEN);
            memcpy(hdr->h_dest, neigh->ha, ETH_ALEN);
            memcpy(hdr->h_source, skbdev->dev_addr, ETH_ALEN);
            hdr->h_vlan_proto = htons(ETH_P_8021Q);
            hdr->h_vlan_TCI = htons(vlan_dev_vlan_id(skbdev));
            hdr->h_vlan_encapsulated_proto = htons(ETH_P_IP);
            realdev = vlan_dev_real_dev(skbdev);
        }
        else
#endif
        {
            struct ethhdr *hdr;

            hdr = (struct ethhdr *)skb_push(skb, ETH_HLEN);
            memcpy(hdr->h_dest, neigh->ha, ETH_ALEN);
            memcpy(hdr->h_source, skbdev->dev_addr, ETH_ALEN);
            hdr->h_proto = htons(ETH_P_IP);
        }

        /* Send packet */
        exanic_netdev_transmit_frame(realdev, skb);

        dev_put(skbdev);
        list_del(&qe->list);
        kfree(qe);
    }

    spin_unlock_bh(&dst_lock);

    BUG_ON(!list_empty(&temp_head));
}

/**
 * Get destination MAC address for a connection.
 */
uint8_t *exasock_dst_get_dmac(uint32_t daddr, uint32_t saddr)
{
    struct exasock_dst_entry *de;
    unsigned idx;

    idx = __find_dst_entry(daddr, saddr);

    if (idx == ~0 || dst_table[idx] == NULL)
    {
        return NULL;
    }
    else
    {
        /* Existing entry */
        de = dst_table[idx];
        if (de->neigh->nud_state & NUD_VALID)
            return de->neigh->ha;
        else
            return NULL;
    }
}

/**
 * Get output device for a connection.
 */
struct net_device *exasock_dst_get_netdev(uint32_t dst_addr, uint32_t src_addr)
{
    struct net_device *ndev;
    struct rtable *rt;
#ifndef __HAS_OLD_NETCORE
    struct flowi4 fl4 = { .daddr = dst_addr, .saddr = src_addr };
#else
    struct flowi fl = {
        .nl_u = {
            .ip4_u = { .daddr = dst_addr, .saddr = src_addr },
        },
    };
#endif

    ndev = __exasock_dst_get_if(&src_addr, &rt,
#ifndef __HAS_OLD_NETCORE
                                &fl4);
#else
                                &fl);
#endif
    if (ndev)
        ip_rt_put(rt);

    return ndev;
}

/**
 * Look up or create destination entry and insert skb into queue.
 */
int exasock_dst_insert(uint32_t dst_addr, uint32_t *src_addr,
                       struct sk_buff *skb)
{
    struct exasock_dst_entry *de;
    struct exasock_dst_queue_entry *qe;
    struct net_device *ndev;
    struct rtable *rt;
#ifndef __HAS_OLD_NETCORE
    struct flowi4 fl4 = { .daddr = dst_addr, .saddr = *src_addr };
#else
    struct flowi fl = {
        .nl_u = {
            .ip4_u = { .daddr = dst_addr, .saddr = *src_addr },
        },
    };
#endif
    uint32_t saddr = *src_addr;
    unsigned idx;
    int err;

    /* Determine output interface */
    ndev = __exasock_dst_get_if(&saddr, &rt,
#ifndef __HAS_OLD_NETCORE
                                &fl4);
#else
                                &fl);
#endif
    if (ndev == NULL)
    {
        err = -ENETUNREACH;
        goto err_get_if;
    }

    /* Verify that output interface is an ExaNIC */
    if (!exasock_is_exanic_dev(exasock_get_realdev(ndev)))
    {
        err = -ENETUNREACH;
        goto err_not_exanic;
    }

    /* Allocate structs */
    de = kmalloc(sizeof(struct exasock_dst_entry), GFP_KERNEL);
    if (de == NULL)
    {
        err = -ENOMEM;
        goto err_entry_alloc;
    }

    if (skb)
    {
        qe = kmalloc(sizeof(struct exasock_dst_queue_entry), GFP_KERNEL);
        if (qe == NULL)
        {
            err = -ENOMEM;
            goto err_queue_alloc;
        }
        skb->dev = ndev;
        qe->skb = skb;
    }
    else
    {
        qe = NULL;
        dev_put(ndev);
        ndev = NULL;
    }

    spin_lock_bh(&dst_lock);

    idx = __find_dst_entry(dst_addr, saddr);

    if (idx == ~0)
    {
        err = -ENOMEM;
        goto err_find_dst_entry;
    }
    else if (dst_table[idx])
    {
        /* Existing entry */
        kfree(de);
        de = dst_table[idx];
        list_del(&de->list);
        ip_rt_put(rt);
    }
    else
    {
        /* New entry */
        unsigned int hash;
        de->rt = rt;
#ifndef __HAS_RT_TABLE_ID
        de->default_rt = false;
#endif
        de->neigh = exasock_dst_neigh_lookup(&rtable_dst(rt), &fl4.daddr);
#ifndef __HAS_OLD_NETCORE
        de->fl4 = fl4;
#endif
        de->idx = idx;
        INIT_LIST_HEAD(&de->dst_queue);
        hash = hash_ptr(de->neigh, NEIGH_HASH_BITS);
        list_add_tail(&de->neigh_hash, &dst_neigh_hash[hash]);
        dst_table[idx] = de;
        __update_user_dst_entry(
#ifndef __HAS_RT_TABLE_ID
                                de->default_rt,
#endif
                                idx);
    }

    dst_used_flags[idx] = 0;
    de->used = jiffies;
#ifndef __HAS_RT_TABLE_ID
    if (*src_addr == htonl(INADDR_ANY))
        de->default_rt = true;
#endif
    list_add_tail(&de->list, &dst_entries);

    if (qe)
        list_add_tail(&qe->list, &de->dst_queue);

    __update_dst_expiry_timer();

    spin_unlock_bh(&dst_lock);

    /* Initiate lookup using Linux neighbour cache */
    neigh_event_send(de->neigh, NULL);

    /* Packet could have been queued even though neigh is valid */
    if (de->neigh->nud_state & NUD_VALID)
        exasock_dst_neigh_update(de->neigh);

    *src_addr = saddr;

    return 0;

err_find_dst_entry:
    spin_unlock_bh(&dst_lock);
    kfree(qe);
err_queue_alloc:
    kfree(de);
err_entry_alloc:
err_not_exanic:
    if (ndev)
        dev_put(ndev);
    ip_rt_put(rt);
err_get_if:
    kfree_skb(skb);
    return err;
}

/**
 * Remove all table entries which contain source address src_addr
 */
void exasock_dst_invalidate_src(uint32_t src_addr)
{
    struct exasock_dst_entry *de;
    unsigned int idx;

    for (idx = 0; idx < dst_table_size; idx++)
    {
        /* Read the user table to avoid having to take a lock
         * unless we find a match */
        if (dst_user_table[idx].src_addr == src_addr)
        {
            spin_lock_bh(&dst_lock);
            de = dst_table[idx];
            if (de != NULL &&
#ifndef __HAS_OLD_NETCORE
                de->fl4.saddr == src_addr)
#else
                de->rt->rt_src == src_addr)
#endif
            {
                /* Found a match, remove the table entry */
                list_del(&de->list);
                list_del(&de->neigh_hash);
                __remove_dst_entry(idx);
                spin_unlock_bh(&dst_lock);
                __free_dst_entry(de);
            }
            else
                spin_unlock_bh(&dst_lock);
        }
    }
}

int exasock_dst_used_flags_mmap(struct vm_area_struct *vma)
{
    return remap_vmalloc_range(vma, dst_used_flags,
            vma->vm_pgoff - (EXASOCK_OFFSET_DST_USED_FLAGS / PAGE_SIZE));
}

int exasock_dst_table_mmap(struct vm_area_struct *vma)
{
    if (vma->vm_flags & VM_WRITE)
        return -EACCES;

    return remap_vmalloc_range(vma, dst_user_table,
            vma->vm_pgoff - (EXASOCK_OFFSET_DST_TABLE / PAGE_SIZE));
}

unsigned int exasock_dst_table_size(void)
{
    return dst_table_size;
}

/**
 * This function is called from exasock_init() when the driver is loaded.
 */
int __init exasock_dst_init(void)
{
    unsigned i;
    int err;

    dst_table_size = DEFAULT_DST_TABLE_SIZE;
    dst_table = kcalloc(dst_table_size, sizeof(struct exasock_dst_entry *),
            GFP_KERNEL);
    dst_neigh_hash = kmalloc(NEIGH_HASH_SIZE * sizeof(struct list_head),
            GFP_KERNEL);
    dst_used_flags = vmalloc_user(dst_table_size * sizeof(uint8_t));
    dst_user_table = vmalloc_user(dst_table_size *
            sizeof(struct exa_dst_entry));

    if (dst_table == NULL || dst_neigh_hash == NULL ||
        dst_used_flags == NULL || dst_user_table == NULL)
    {
        err = -ENOMEM;
        goto err_alloc;
    }

    INIT_LIST_HEAD(&dst_entries);
    for (i = 0; i < NEIGH_HASH_SIZE; i++)
        INIT_LIST_HEAD(&dst_neigh_hash[i]);

    dst_expiry_timer_running = true;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
    timer_setup(&dst_expiry_timer, dst_expiry_timer_handler, 0);
#else
    setup_timer(&dst_expiry_timer, dst_expiry_timer_handler, 0);
#endif
    return 0;

err_alloc:
    vfree(dst_user_table);
    vfree(dst_used_flags);
    kfree(dst_neigh_hash);
    kfree(dst_table);
    return err;
}

/**
 * This function is called from exasock_exit() when the driver is unloaded
 * and by exasock_init() on error.
 */
void exasock_dst_exit(void)
{
    struct exasock_dst_entry *de, *tmp;

    dst_expiry_timer_running = false;
    del_timer_sync(&dst_expiry_timer);

    spin_lock_bh(&dst_lock);

    list_for_each_entry_safe(de, tmp, &dst_entries, list)
    {
        list_del(&de->list);
        list_del(&de->neigh_hash);
        dst_table[de->idx] = NULL;
        __free_dst_entry(de);
    }

    spin_unlock_bh(&dst_lock);

    kfree(dst_table);
    kfree(dst_neigh_hash);
    vfree(dst_used_flags);
    vfree(dst_user_table);
}
