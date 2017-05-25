/**
 * Kernel support for the ExaSock library
 * Copyright (C) 2011-2017 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/file.h>

#include "../../libs/exasock/kernel/api.h"
#include "../../libs/exasock/kernel/structs.h"

#include "../exanic/exanic.h"
#include "exasock.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
#define __HAS_OLD_HLIST_ITERATOR
#endif

struct exasock_udp
{
    struct exasock_hdr          hdr;

    uint32_t                    local_addr;
    uint32_t                    peer_addr;
    uint16_t                    local_port;
    uint16_t                    peer_port;

    void *                      rx_buffer;
    struct exa_socket_state *   user_page;

    struct socket *             sock;

    struct hlist_node           hash_node;

    struct exasock_stats_sock * stats;
};

static struct hlist_head *      udp_buckets;
static DEFINE_SPINLOCK(         udp_bucket_lock);

#define RX_BUFFER_SIZE          1048576

#define NUM_BUCKETS             4096

static inline enum exasock_socktype exasock_udp_stats_get_socktype(
                                                       struct exasock_udp *udp)
{
    if ((udp->peer_addr != ntohl(INADDR_ANY)) && (udp->peer_port != 0))
        return EXASOCK_SOCKTYPE_UDP_CONN;
    else
        return EXASOCK_SOCKTYPE_UDP;
}

static inline void exasock_udp_stats_set_addr(
                                     struct exasock_stats_sock_info_addr *addr,
                                     struct exasock_udp *udp)
{
    addr->local_ip   = ntohl(udp->local_addr);
    addr->peer_ip    = ntohl(udp->peer_addr);
    addr->local_port = ntohs(udp->local_port);
    addr->peer_port  = ntohs(udp->peer_port);
}

static inline void exasock_udp_stats_set_info(
                                          struct exasock_stats_sock_info *info,
                                          struct exasock_udp *udp)
{
    exasock_udp_stats_set_addr(&info->addr, udp);

    info->recv_q_recv_seq = &udp->user_page->p.udp.next_write;
    info->recv_q_read_seq = &udp->user_page->p.udp.next_read;
    info->send_q_sent_seq = NULL;
    info->send_q_ack_seq  = NULL;
    info->state           = NULL;
}

static struct exasock_stats_sock *exasock_udp_stats_init(
                                                    struct exasock_udp *udp)
{
    struct exasock_stats_sock_info info;

    exasock_udp_stats_set_info(&info, udp);

    return exasock_stats_socket_add(exasock_udp_stats_get_socktype(udp),
                                    &info);
}

static void exasock_udp_stats_update(struct exasock_udp *udp)
{
    struct exasock_stats_sock_info_addr info_addr;

    exasock_udp_stats_set_addr(&info_addr, udp);

    exasock_stats_socket_update(udp->stats, EXASOCK_SOCKTYPE_UDP,
                                exasock_udp_stats_get_socktype(udp),
                                &info_addr);
}

static unsigned exasock_udp_hash(uint32_t local_addr, uint32_t peer_addr,
                                 uint16_t local_port, uint16_t peer_port)
{
    return jhash_3words(((uint32_t)peer_port << 16) | local_port,
                        local_addr, peer_addr, 0) & (NUM_BUCKETS - 1);
}

static void exasock_udp_update_hashtbl(struct exasock_udp *udp)
{
    unsigned hash = exasock_udp_hash(udp->local_addr, udp->peer_addr,
                                     udp->local_port, udp->peer_port);
    unsigned long flags;

    spin_lock_irqsave(&udp_bucket_lock, flags);
    hlist_del_rcu(&udp->hash_node);
    hlist_add_head_rcu(&udp->hash_node, &udp_buckets[hash]);
    spin_unlock_irqrestore(&udp_bucket_lock, flags);
}

struct exasock_udp *exasock_udp_alloc(struct socket *sock)
{
    struct exasock_udp *udp = NULL;
    struct sockaddr_in local, peer;
    int slen;
    void *rx_buffer = NULL;
    struct exa_socket_state *user_page;
    int err;
    unsigned long flags;
    unsigned hash;

    /* Get local and peer addresses from native socket */
    slen = sizeof(local);
    memset(&local, 0, sizeof(local));
    err = sock->ops->getname(sock, (struct sockaddr *)&local, &slen, 0);
    if (err)
        goto err_sock_getname;

    slen = sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    err = sock->ops->getname(sock, (struct sockaddr *)&peer, &slen, 1);
    if (err == -ENOTCONN)
    {
        peer.sin_family = AF_INET;
        peer.sin_addr.s_addr = htonl(INADDR_ANY);
        peer.sin_port = 0;
    }
    else if (err)
        goto err_sock_getname;

    /* Allocate structs and buffers */
    udp = kzalloc(sizeof(struct exasock_udp), GFP_KERNEL);
    rx_buffer = vmalloc_user(RX_BUFFER_SIZE);
    user_page = vmalloc_user(PAGE_SIZE);
    if (udp == NULL || rx_buffer == NULL || user_page == NULL)
    {
        err = -ENOMEM;
        goto err_alloc;
    }

    udp->hdr.type = EXASOCK_TYPE_SOCKET;
    udp->hdr.socket.domain = AF_INET;
    udp->hdr.socket.type = SOCK_DGRAM;
    udp->local_addr = local.sin_addr.s_addr;
    udp->local_port = local.sin_port;
    udp->peer_addr = peer.sin_addr.s_addr;
    udp->peer_port = peer.sin_port;
    udp->rx_buffer = rx_buffer;
    udp->user_page = user_page;
    udp->sock = sock;

    /* Initialize stats */
    udp->stats = exasock_udp_stats_init(udp);
    if (udp->stats == NULL)
    {
        err = -ENOMEM;
        goto err_alloc;
    }

    /* Insert into hash table */
    hash = exasock_udp_hash(udp->local_addr, udp->peer_addr,
                            udp->local_port, udp->peer_port);
    spin_lock_irqsave(&udp_bucket_lock, flags);
    hlist_add_head_rcu(&udp->hash_node, &udp_buckets[hash]);
    spin_unlock_irqrestore(&udp_bucket_lock, flags);

    /* Fill out user page */
    user_page->domain = AF_INET;
    user_page->type = SOCK_DGRAM;
    user_page->rx_buffer_size = RX_BUFFER_SIZE;
    user_page->tx_buffer_size = 0;
    user_page->e.ip.local_addr = local.sin_addr.s_addr;
    user_page->e.ip.local_port = local.sin_port;
    user_page->e.ip.peer_addr = peer.sin_addr.s_addr;
    user_page->e.ip.peer_port = peer.sin_port;

    return udp;

err_alloc:
    vfree(user_page);
    vfree(rx_buffer);
    kfree(udp);
err_sock_getname:
    return ERR_PTR(err);
}

int exasock_udp_bind(struct exasock_udp *udp, uint32_t local_addr,
                     uint16_t *local_port)
{
    struct sockaddr_in sa;
    int slen;
    int err;

    BUG_ON(udp->hdr.type != EXASOCK_TYPE_SOCKET);
    BUG_ON(udp->hdr.socket.domain != AF_INET);
    BUG_ON(udp->hdr.socket.type != SOCK_DGRAM);

    /* Bind to the requested address on native socket */
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = local_addr;
    sa.sin_port = *local_port;
    err = udp->sock->ops->bind(udp->sock, (struct sockaddr *)&sa, sizeof(sa));
    if (err)
        return err;

    /* Get assigned port from native socket */
    slen = sizeof(sa);
    memset(&sa, 0, sizeof(sa));
    err = udp->sock->ops->getname(udp->sock, (struct sockaddr *)&sa, &slen, 0);
    if (err)
        return err;

    udp->user_page->e.ip.local_addr = udp->local_addr = sa.sin_addr.s_addr;
    udp->user_page->e.ip.local_port = udp->local_port = sa.sin_port;

    /* Update hash table */
    exasock_udp_update_hashtbl(udp);

    /* Update stats */
    exasock_udp_stats_update(udp);

    *local_port = sa.sin_port;
    return 0;
}

int exasock_udp_connect(struct exasock_udp *udp, uint32_t *local_addr,
                        uint16_t *local_port, uint32_t peer_addr,
                        uint16_t peer_port)
{
    struct sockaddr_in sa;
    int slen;
    int err;

    BUG_ON(udp->hdr.type != EXASOCK_TYPE_SOCKET);
    BUG_ON(udp->hdr.socket.domain != AF_INET);
    BUG_ON(udp->hdr.socket.type != SOCK_DGRAM);

    /* Connect to the requested address on native socket */
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = peer_addr;
    sa.sin_port = peer_port;
    err = udp->sock->ops->connect(udp->sock, (struct sockaddr *)&sa,
            sizeof(sa), 0);
    if (err)
        return err;

    /* Get assigned local address and port from native socket */
    slen = sizeof(sa);
    memset(&sa, 0, sizeof(sa));
    err = udp->sock->ops->getname(udp->sock, (struct sockaddr *)&sa, &slen, 0);
    if (err)
        return err;

    udp->user_page->e.ip.local_addr = udp->local_addr = sa.sin_addr.s_addr;
    udp->user_page->e.ip.local_port = udp->local_port = sa.sin_port;
    udp->user_page->e.ip.peer_addr = udp->peer_addr = peer_addr;
    udp->user_page->e.ip.peer_port = udp->peer_port = peer_port;

    /* Update hash table */
    exasock_udp_update_hashtbl(udp);

    /* Update stats */
    exasock_udp_stats_update(udp);

    *local_addr = sa.sin_addr.s_addr;
    *local_port = sa.sin_port;
    return 0;
}

void exasock_udp_free(struct exasock_udp *udp)
{
    unsigned long flags;

    BUG_ON(udp->hdr.type != EXASOCK_TYPE_SOCKET);
    BUG_ON(udp->hdr.socket.domain != AF_INET);
    BUG_ON(udp->hdr.socket.type != SOCK_DGRAM);

    exasock_stats_socket_del(udp->stats, exasock_udp_stats_get_socktype(udp));

    spin_lock_irqsave(&udp_bucket_lock, flags);
    hlist_del_rcu(&udp->hash_node);
    spin_unlock_irqrestore(&udp_bucket_lock, flags);

    synchronize_rcu();

    sockfd_put(udp->sock);
    vfree(udp->user_page);
    vfree(udp->rx_buffer);
    kfree(udp);
}

int exasock_udp_rx_mmap(struct exasock_udp *udp, struct vm_area_struct *vma)
{
    return remap_vmalloc_range(vma, udp->rx_buffer,
            vma->vm_pgoff - (EXASOCK_OFFSET_RX_BUFFER / PAGE_SIZE));
}

int exasock_udp_state_mmap(struct exasock_udp *udp, struct vm_area_struct *vma)
{
    return remap_vmalloc_range(vma, udp->user_page,
            vma->vm_pgoff - (EXASOCK_OFFSET_SOCKET_STATE / PAGE_SIZE));
}

static bool exasock_udp_intercept(struct sk_buff *skb)
{
    struct exasock_udp *udp;
#ifdef __HAS_OLD_HLIST_ITERATOR
    struct hlist_node *n;
#endif
    struct iphdr *iph;
    struct udphdr *uh;
    char *payload = skb->data;
    unsigned hash;

    if (skb->protocol != htons(ETH_P_IP))
    {
        if (skb->protocol == htons(ETH_P_8021Q)
             && ((struct vlan_hdr *)payload)->h_vlan_encapsulated_proto
                   == htons(ETH_P_IP))
            payload += sizeof(struct vlan_hdr);
       else
            return false;
    }

    iph = (struct iphdr *)payload;
    if (iph->protocol != IPPROTO_UDP)
        return false;

    /* Multicast UDP packets are always delivered to the kernel */
    if (ipv4_is_multicast(iph->daddr))
        return false;

    /* Packet is UDP, search socket table for a match */
    uh = (struct udphdr *)(payload + iph->ihl * 4);

    rcu_read_lock();

    /* Try to match (local_addr, peer_addr, local_port, peer_port) */
    hash = exasock_udp_hash(iph->daddr, iph->saddr, uh->dest, uh->source);
    hlist_for_each_entry_rcu(udp,
#ifdef __HAS_OLD_HLIST_ITERATOR
                             n,
#endif
                             &udp_buckets[hash], hash_node)
    {
        if (udp->local_addr == iph->daddr &&
            udp->peer_addr == iph->saddr &&
            udp->local_port == uh->dest &&
            udp->peer_port == uh->source)
        {
            dev_kfree_skb_any(skb);
            rcu_read_unlock();
            return true;
        }
    }

    /* Try to match (local_addr, local_port) */
    hash = exasock_udp_hash(iph->daddr, htonl(INADDR_ANY), uh->dest, 0);
    hlist_for_each_entry_rcu(udp,
#ifdef __HAS_OLD_HLIST_ITERATOR
                             n,
#endif
                             &udp_buckets[hash], hash_node)
    {
        if (udp->local_addr == iph->daddr &&
            udp->peer_addr == htonl(INADDR_ANY) &&
            udp->local_port == uh->dest &&
            udp->peer_port == 0)
        {
            dev_kfree_skb_any(skb);
            rcu_read_unlock();
            return true;
        }
    }

    /* Try to match local_port only */
    hash = exasock_udp_hash(htonl(INADDR_ANY), htonl(INADDR_ANY), uh->dest, 0);
    hlist_for_each_entry_rcu(udp,
#ifdef __HAS_OLD_HLIST_ITERATOR
                             n,
#endif
                             &udp_buckets[hash], hash_node)
    {
        if (udp->local_addr == htonl(INADDR_ANY) &&
            udp->peer_addr == htonl(INADDR_ANY) &&
            udp->local_port == uh->dest &&
            udp->peer_port == 0)
        {
            dev_kfree_skb_any(skb);
            rcu_read_unlock();
            return true;
        }
    }

    rcu_read_unlock();
    return false;
}

int exasock_udp_setsockopt(struct exasock_udp *udp, int level, int optname,
                           char __user *optval, unsigned int optlen)
{
    int ret;

    BUG_ON(udp->hdr.type != EXASOCK_TYPE_SOCKET);
    BUG_ON(udp->hdr.socket.domain != AF_INET);
    BUG_ON(udp->hdr.socket.type != SOCK_DGRAM);

    ret = udp->sock->ops->setsockopt(udp->sock, level, optname, optval, optlen);

    return ret;
}

int exasock_udp_getsockopt(struct exasock_udp *udp, int level, int optname,
                           char __user *optval, unsigned int *optlen)
{
    int ret;
    mm_segment_t old_fs;

    BUG_ON(udp->hdr.type != EXASOCK_TYPE_SOCKET);
    BUG_ON(udp->hdr.socket.domain != AF_INET);
    BUG_ON(udp->hdr.socket.type != SOCK_DGRAM);

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = udp->sock->ops->getsockopt(udp->sock, level, optname, optval, optlen);
    set_fs(old_fs);

    return ret;
}

int __init exasock_udp_init(void)
{
    udp_buckets = kzalloc(NUM_BUCKETS * sizeof(*udp_buckets), GFP_KERNEL);
    return exanic_netdev_intercept_add(&exasock_udp_intercept);
}

void exasock_udp_exit(void)
{
    exanic_netdev_intercept_remove(&exasock_udp_intercept);
    kfree(udp_buckets);
}
