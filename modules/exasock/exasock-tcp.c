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
#include <linux/tcp.h>
#include <linux/file.h>
#include <net/checksum.h>
#include <net/tcp.h>

#include "../../libs/exasock/kernel/api.h"
#include "../../libs/exasock/kernel/consts.h"
#include "../../libs/exasock/kernel/structs.h"

#include "../exanic/exanic.h"
#include "exasock.h"
#include "exasock-stats.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
#define __HAS_OLD_HLIST_ITERATOR
#define __HAS_OLD_NET_RANDOM
#endif

struct exasock_tcp_counters
{
    spinlock_t  lock;

    uint32_t    send_rounds;
    uint32_t    send_ack_rounds;
    uint32_t    recv_rounds;
    uint32_t    recv_read_rounds;

    uint32_t    retrans_bytes;
    uint32_t    retrans_segs_fast;
    uint32_t    retrans_segs_to;
};

struct exasock_tcp
{
    struct exasock_hdr              hdr;

    uint32_t                        local_addr;
    uint32_t                        peer_addr;
    uint16_t                        local_port;
    uint16_t                        peer_port;

    void *                          rx_buffer;
    void *                          tx_buffer;
    struct exa_socket_state *       user_page;

    struct socket *                 sock;

    /* Value of send_seq and send_ack at last timer tick */
    uint32_t                        last_send_seq;
    uint32_t                        last_send_ack;

    /* Retransmit timeout is triggered when count reaches 0 */
    int                             retransmit_countdown;

    /* For keeping track of duplicate acks for entering fast retransmit */
    uint32_t                        last_recv_ack_seq;
    int                             num_dup_acks;

    /* Fast retransmit state */
    bool                            fast_retransmit;
    uint32_t                        fast_retransmit_recover_seq;

    struct delayed_work             work;

    struct hlist_node               hash_node;
    bool                            dead_node;

    struct exasock_epoll_notify *   notify;
    spinlock_t                      notify_lock;

    struct kref                     refcount;
    /* Semaphore stays down until refcount goes to 0 */
    struct semaphore                dead_sema;

    /* Statistics related structures */
    struct exasock_tcp_counters     counters;
    struct exasock_stats_sock       stats;
};

struct exasock_tcp_req
{
    unsigned long               timestamp;

    uint32_t                    local_addr;
    uint32_t                    peer_addr;
    uint16_t                    local_port;
    uint16_t                    peer_port;

    uint32_t                    local_seq;
    uint32_t                    peer_seq;
    uint16_t                    window;
    uint16_t                    mss;
    uint8_t                     wscale;
    uint8_t                     state;

    struct list_head            list;
    struct hlist_node           hash_node;
};

static struct hlist_head *      tcp_buckets;
static DEFINE_SPINLOCK(         tcp_bucket_lock);

static struct sk_buff_head      tcp_packets;
static struct workqueue_struct *tcp_workqueue;
static struct delayed_work      tcp_rx_work;

static struct hlist_head *      tcp_req_buckets;
static LIST_HEAD(               tcp_req_list);
static DEFINE_SPINLOCK(         tcp_req_lock);
static struct delayed_work      tcp_req_work;

#define RX_BUFFER_SIZE          1048576
#define RX_BUFFER_MASK          (RX_BUFFER_SIZE - 1)
#define TX_BUFFER_SIZE          1048576
#define TX_BUFFER_MASK          (TX_BUFFER_SIZE - 1)

#define NUM_BUCKETS             4096

/* Timer fires once every 250ms */
#define TCP_TIMER_JIFFIES       (HZ / 4)

/* Number of timer firings until retransmit */
#define RETRANSMIT_TIMEOUT      4

/* Number of jiffies until an incomplete TCP request expires */
#define TCP_REQUEST_JIFFIES     HZ

#define SEQNUM_ROLLOVER(start, last, now)   ((now) - (last) > (now) - (start))
#define SEQNUM_TO_BYTES(start, now, rounds) \
                               (((uint64_t)(rounds) << 32) | ((now) - (start)))

static void exasock_tcp_conn_worker(struct work_struct *work);
static void exasock_tcp_retransmit(struct exasock_tcp *tcp, uint32_t seq,
                                   bool fast_retrans);
static void exasock_tcp_send_ack(struct exasock_tcp *tcp);
static void exasock_tcp_send_reset(struct exasock_tcp *tcp);
static void exasock_tcp_send_syn_ack(struct exasock_tcp_req *req);

static inline void exasock_tcp_counters_update_locked(
                                          struct exasock_tcp_counters *cnt,
                                          struct exa_tcp_state *tcp_st,
                                          uint32_t send_seq, uint32_t send_ack,
                                          uint32_t recv_seq, uint32_t read_seq)
{
    if (SEQNUM_ROLLOVER(tcp_st->stats.init_send_seq,
                        tcp_st->stats.prev_send_seq, send_seq))
        cnt->send_rounds++;

    if (SEQNUM_ROLLOVER(tcp_st->stats.init_send_seq,
                        tcp_st->stats.prev_send_ack, send_ack))
        cnt->send_ack_rounds++;

    if (SEQNUM_ROLLOVER(tcp_st->stats.init_recv_seq,
                        tcp_st->stats.prev_recv_seq, recv_seq))
        cnt->recv_rounds++;

    if (SEQNUM_ROLLOVER(tcp_st->stats.init_recv_seq,
                        tcp_st->stats.prev_read_seq, read_seq))
        cnt->recv_read_rounds++;

    tcp_st->stats.prev_send_seq = send_seq;
    tcp_st->stats.prev_send_ack = send_ack;
    tcp_st->stats.prev_recv_seq = recv_seq;
    tcp_st->stats.prev_read_seq = read_seq;
}

static inline void exasock_tcp_counters_update(struct exasock_tcp_counters *cnt,
                                               struct exa_tcp_state *tcp_st)
{
    spin_lock(&cnt->lock);
    exasock_tcp_counters_update_locked(cnt, tcp_st,
                                       tcp_st->send_seq, tcp_st->send_ack,
                                       tcp_st->recv_seq, tcp_st->read_seq);
    spin_unlock(&cnt->lock);
}

static inline struct exasock_tcp *stats_to_tcp(struct exasock_stats_sock *stats)
{
    return container_of(stats, struct exasock_tcp, stats);
}

static inline void exasock_tcp_stats_fill_addr(
                                     struct exasock_stats_sock_addr *addr,
                                     struct exasock_tcp *tcp)
{
    addr->local_ip   = tcp->local_addr;
    addr->peer_ip    = tcp->peer_addr;
    addr->local_port = tcp->local_port;
    addr->peer_port  = tcp->peer_port;
}

static inline void exasock_tcp_stats_fill_info(
                                          struct exasock_stats_sock_info *info,
                                          struct exasock_tcp *tcp, int fd)
{
    info->pid = task_tgid_nr(current);
    get_task_comm(info->prog_name, current);
    info->fd = fd;
    info->uid = exasock_current_uid();
}

static uint8_t exasock_tcp_stats_get_state(struct exasock_stats_sock *stats)
{
    struct exasock_tcp *tcp = stats_to_tcp(stats);

    return tcp->user_page->p.tcp.state;
}

static void exasock_tcp_stats_get_snapshot(struct exasock_stats_sock *stats,
                                 struct exasock_stats_sock_snapshot_brf *ssbrf,
                                 struct exasock_stats_sock_snapshot_int *ssint)
{
    struct exasock_tcp *tcp = stats_to_tcp(stats);
    struct exasock_tcp_counters *cnt = &tcp->counters;
    struct exa_tcp_state *tcp_st = &tcp->user_page->p.tcp;
    uint32_t send_seq;
    uint32_t send_ack;
    uint32_t recv_seq;
    uint32_t read_seq;
    uint8_t state;

    if (ssint != NULL)
        spin_lock(&cnt->lock);

    send_seq = tcp_st->send_seq;
    send_ack = tcp_st->send_ack;
    recv_seq = tcp_st->recv_seq;
    read_seq = tcp_st->read_seq;
    state = tcp_st->state;

    if (state == EXA_TCP_LISTEN)
    {
        ssbrf->recv_q = (recv_seq - read_seq) /
                        sizeof(struct exa_tcp_new_connection);
        ssbrf->send_q = 0;
    }
    else
    {
        ssbrf->recv_q = recv_seq - read_seq;
        ssbrf->send_q = send_seq - send_ack;
    }

    if (ssint != NULL)
    {
        if ((state != EXA_TCP_CLOSED) && (state != EXA_TCP_LISTEN) &&
            (state != EXA_TCP_SYN_SENT) && (state != EXA_TCP_SYN_RCVD))
        {
            exasock_tcp_counters_update_locked(cnt, tcp_st, send_seq, send_ack,
                                               recv_seq, read_seq);
            spin_unlock(&cnt->lock);

            ssint->tx_bytes = SEQNUM_TO_BYTES(tcp_st->stats.init_send_seq,
                                              send_seq,
                                              cnt->send_rounds);
            ssint->tx_acked_bytes = SEQNUM_TO_BYTES(tcp_st->stats.init_send_seq,
                                                    send_ack,
                                                    cnt->send_ack_rounds);
            ssint->rx_bytes = SEQNUM_TO_BYTES(tcp_st->stats.init_recv_seq,
                                              recv_seq,
                                              cnt->recv_rounds);
            ssint->rx_deliv_bytes = SEQNUM_TO_BYTES(tcp_st->stats.init_recv_seq,
                                                        read_seq,
                                                        cnt->recv_read_rounds);

            ssint->wscale_peer = tcp_st->wscale;
            ssint->wscale_local = (ssint->wscale_peer ? EXA_TCP_WSCALE : 0);
            ssint->window_peer = tcp_st->rwnd_end - send_ack;
            ssint->window_local = tcp->user_page->rx_buffer_size -
                                  (recv_seq - read_seq);
            ssint->mss_peer = tcp_st->rmss;
            ssint->mss_local = EXA_TCP_MSS;
            ssint->cwnd = tcp_st->cwnd;
            ssint->ssthresh = tcp_st->ssthresh;
        }
        else
        {
            spin_unlock(&cnt->lock);

            ssint->tx_bytes = 0;
            ssint->tx_acked_bytes = 0;
            ssint->rx_bytes = 0;
            ssint->rx_deliv_bytes = 0;

            ssint->wscale_peer = 0;
            ssint->wscale_local = 0;
            ssint->window_peer = 0;
            ssint->window_local = 0;
            ssint->mss_peer = 0;
            ssint->mss_local = 0;
            ssint->cwnd = 0;
            ssint->ssthresh = 0;
        }
        ssint->retrans_segs_fast = cnt->retrans_segs_fast;
        ssint->retrans_segs_to = cnt->retrans_segs_to;
        ssint->retrans_bytes = cnt->retrans_bytes;
    }
}

static void exasock_tcp_stats_init(struct exasock_tcp *tcp, int fd)
{
    struct exasock_stats_sock *stats = &tcp->stats;

    exasock_tcp_stats_fill_addr(&stats->addr, tcp);
    exasock_tcp_stats_fill_info(&stats->info, tcp, fd);

    stats->ops.get_state    = exasock_tcp_stats_get_state;
    stats->ops.get_snapshot = exasock_tcp_stats_get_snapshot;

    exasock_stats_socket_add(EXASOCK_SOCKTYPE_TCP, stats);

    spin_lock_init(&tcp->counters.lock);
}

static void exasock_tcp_stats_update(struct exasock_tcp *tcp)
{
    struct exasock_stats_sock_addr addr;

    exasock_tcp_stats_fill_addr(&addr, tcp);

    exasock_stats_socket_update(&tcp->stats, EXASOCK_SOCKTYPE_TCP,
                                EXASOCK_SOCKTYPE_TCP, &addr);
}

static unsigned exasock_tcp_hash(uint32_t local_addr, uint32_t peer_addr,
                                 uint16_t local_port, uint16_t peer_port)
{
    return jhash_3words(((uint32_t)peer_port << 16) | local_port,
                        local_addr, peer_addr, 0) & (NUM_BUCKETS - 1);
}

static void exasock_tcp_update_hashtbl(struct exasock_tcp *tcp)
{
    unsigned hash = exasock_tcp_hash(tcp->local_addr, tcp->peer_addr,
                                     tcp->local_port, tcp->peer_port);

    spin_lock(&tcp_bucket_lock);
    hlist_del_rcu(&tcp->hash_node);
    hlist_add_head_rcu(&tcp->hash_node, &tcp_buckets[hash]);
    spin_unlock(&tcp_bucket_lock);
}

struct exasock_tcp *exasock_tcp_alloc(struct socket *sock, int fd)
{
    struct exasock_tcp *tcp = NULL;
    struct sockaddr_in local;
    int slen;
    void *rx_buffer = NULL;
    void *tx_buffer = NULL;
    struct exa_socket_state *user_page;
    int err;
    unsigned hash;
    struct file *f;

    /* Get local address from native socket */
    slen = sizeof(local);
    memset(&local, 0, sizeof(local));
    err = sock->ops->getname(sock, (struct sockaddr *)&local, &slen, 0);
    if (err)
        goto err_sock_getname;

    /* TODO: Check that socket is not connected */

    /* Allocate structs and buffers */
    tcp = kzalloc(sizeof(struct exasock_tcp), GFP_KERNEL);
    rx_buffer = vmalloc_user(RX_BUFFER_SIZE);
    tx_buffer = vmalloc_user(TX_BUFFER_SIZE);
    user_page = vmalloc_user(PAGE_SIZE);
    if (tcp == NULL || rx_buffer == NULL || user_page == NULL)
    {
        err = -ENOMEM;
        goto err_alloc;
    }

    tcp->hdr.type = EXASOCK_TYPE_SOCKET;
    tcp->hdr.socket.domain = AF_INET;
    tcp->hdr.socket.type = SOCK_STREAM;
    tcp->local_addr = local.sin_addr.s_addr;
    tcp->local_port = local.sin_port;
    tcp->peer_addr = htonl(INADDR_ANY);
    tcp->peer_port = 0;
    tcp->rx_buffer = rx_buffer;
    tcp->tx_buffer = tx_buffer;
    tcp->user_page = user_page;
    tcp->sock = sock;
    tcp->retransmit_countdown = -1;
    tcp->dead_node = false;

    exasock_tcp_stats_init(tcp, fd);

    kref_init(&tcp->refcount);
    sema_init(&tcp->dead_sema, 0);
    spin_lock_init(&tcp->notify_lock);

    INIT_DELAYED_WORK(&tcp->work, exasock_tcp_conn_worker);
    queue_delayed_work(tcp_workqueue, &tcp->work, TCP_TIMER_JIFFIES);

    hash = exasock_tcp_hash(tcp->local_addr, tcp->peer_addr,
                            tcp->local_port, tcp->peer_port);

    spin_lock(&tcp_bucket_lock);
    hlist_add_head_rcu(&tcp->hash_node, &tcp_buckets[hash]);
    spin_unlock(&tcp_bucket_lock);

    user_page->domain = AF_INET;
    user_page->type = SOCK_STREAM;
    user_page->rx_buffer_size = RX_BUFFER_SIZE;
    user_page->tx_buffer_size = TX_BUFFER_SIZE;
    user_page->e.ip.local_addr = local.sin_addr.s_addr;
    user_page->e.ip.local_port = local.sin_port;
    user_page->e.ip.peer_addr = htonl(INADDR_ANY);
    user_page->e.ip.peer_port = 0;

    /* Initial values for various connection parameters */
    user_page->p.tcp.rmss = 536; /* RFC2581 */
    user_page->p.tcp.cwnd = 3 * EXA_TCP_MSS;
    user_page->p.tcp.ssthresh = 3 * EXA_TCP_MSS;

    /* Grab current slow_start_after_idle setting */
    user_page->p.tcp.ss_after_idle = '0';
    f = filp_open("/proc/sys/net/ipv4/tcp_slow_start_after_idle", O_RDONLY, 0);
    if (f != NULL)
    {
        vfs_read(f, &user_page->p.tcp.ss_after_idle, 1, 0);
        filp_close(f, NULL);
    }
    user_page->p.tcp.ss_after_idle -= '0';

    return tcp;

err_alloc:
    vfree(user_page);
    vfree(rx_buffer);
    vfree(tx_buffer);
    kfree(tcp);
err_sock_getname:
    return ERR_PTR(err);
}

int exasock_tcp_bind(struct exasock_tcp *tcp, uint32_t local_addr,
                     uint16_t *local_port)
{
    struct sockaddr_in sa;
    int slen;
    int err;

    BUG_ON(tcp->hdr.type != EXASOCK_TYPE_SOCKET);
    BUG_ON(tcp->hdr.socket.domain != AF_INET);
    BUG_ON(tcp->hdr.socket.type != SOCK_STREAM);

    /* Bind to the requested address on native socket */
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = local_addr;
    sa.sin_port = *local_port;
    err = tcp->sock->ops->bind(tcp->sock, (struct sockaddr *)&sa, sizeof(sa));
    if (err)
        return err;

    /* Get assigned port from native socket */
    slen = sizeof(sa);
    memset(&sa, 0, sizeof(sa));
    err = tcp->sock->ops->getname(tcp->sock, (struct sockaddr *)&sa, &slen, 0);
    if (err)
        return err;

    tcp->local_addr = sa.sin_addr.s_addr;
    tcp->local_port = sa.sin_port;

    /* Update hash table */
    exasock_tcp_update_hashtbl(tcp);

    tcp->user_page->e.ip.local_addr = tcp->local_addr;
    tcp->user_page->e.ip.local_port = tcp->local_port;

    exasock_tcp_stats_update(tcp);

    *local_port = sa.sin_port;
    return 0;
}

void exasock_tcp_update(struct exasock_tcp *tcp,
                        uint32_t local_addr, uint16_t local_port,
                        uint32_t peer_addr, uint16_t peer_port)
{
    BUG_ON(tcp->hdr.type != EXASOCK_TYPE_SOCKET);
    BUG_ON(tcp->hdr.socket.domain != AF_INET);
    BUG_ON(tcp->hdr.socket.type != SOCK_STREAM);

    /* Update kernel struct with provided addresses and ports */
    tcp->local_addr = local_addr;
    tcp->local_port = local_port;
    tcp->peer_addr = peer_addr;
    tcp->peer_port = peer_port;

    /* Update hash table */
    exasock_tcp_update_hashtbl(tcp);

    /* Update user page */
    tcp->user_page->e.ip.local_addr = tcp->local_addr;
    tcp->user_page->e.ip.local_port = tcp->local_port;
    tcp->user_page->e.ip.peer_addr = tcp->peer_addr;
    tcp->user_page->e.ip.peer_port = tcp->peer_port;

    exasock_tcp_stats_update(tcp);
}

void exasock_tcp_dead(struct kref *ref)
{
    struct exasock_tcp *tcp = container_of(ref, struct exasock_tcp, refcount);
    up(&tcp->dead_sema);
}

void exasock_tcp_free(struct exasock_tcp *tcp)
{
    BUG_ON(tcp->hdr.type != EXASOCK_TYPE_SOCKET);
    BUG_ON(tcp->hdr.socket.domain != AF_INET);
    BUG_ON(tcp->hdr.socket.type != SOCK_STREAM);

    /* Close stats */
    exasock_stats_socket_del(&tcp->stats, EXASOCK_SOCKTYPE_TCP);

    /* Send reset packet */
    exasock_tcp_send_reset(tcp);

    /* If there are still any packets pending in destination table queue,
     * it means the socket does not have a valid neighbour. These packets
     * need to be removed now. */
    exasock_dst_remove_socket(tcp->local_addr, tcp->peer_addr,
                              tcp->local_port, tcp->peer_port);

    /* Remove from hash table */
    spin_lock(&tcp_bucket_lock);
    hlist_del_rcu(&tcp->hash_node);
    spin_unlock(&tcp_bucket_lock);
    tcp->dead_node = true;

    synchronize_rcu();

    /* Wait for refcount to go to 0 */
    kref_put(&tcp->refcount, exasock_tcp_dead);
    down(&tcp->dead_sema);

    cancel_delayed_work_sync(&tcp->work);

    /* No readers left, it is now safe to free everything */
    sockfd_put(tcp->sock);
    vfree(tcp->user_page);
    vfree(tcp->rx_buffer);
    vfree(tcp->tx_buffer);
    kfree(tcp);
}

int exasock_tcp_rx_mmap(struct exasock_tcp *tcp, struct vm_area_struct *vma)
{
    return remap_vmalloc_range(vma, tcp->rx_buffer,
            vma->vm_pgoff - (EXASOCK_OFFSET_RX_BUFFER / PAGE_SIZE));
}

int exasock_tcp_tx_mmap(struct exasock_tcp *tcp, struct vm_area_struct *vma)
{
    return remap_vmalloc_range(vma, tcp->tx_buffer,
            vma->vm_pgoff - (EXASOCK_OFFSET_TX_BUFFER / PAGE_SIZE));
}

int exasock_tcp_state_mmap(struct exasock_tcp *tcp, struct vm_area_struct *vma)
{
    return remap_vmalloc_range(vma, tcp->user_page,
            vma->vm_pgoff - (EXASOCK_OFFSET_SOCKET_STATE / PAGE_SIZE));
}

/* Looks up exasock_tcp struct for a listening socket in hashtable.
 * RCU read lock must be held. */
static struct exasock_tcp *exasock_tcp_listen_lookup(uint32_t local_addr,
                                              uint16_t local_port)
{
    struct exasock_tcp *tcp;
#ifdef __HAS_OLD_HLIST_ITERATOR
    struct hlist_node *n;
#endif
    unsigned hash;

    /* Try to match (local_addr, local_port) */
    hash = exasock_tcp_hash(local_addr, htonl(INADDR_ANY), local_port, 0);
    hlist_for_each_entry_rcu(tcp,
#ifdef __HAS_OLD_HLIST_ITERATOR
                             n,
#endif
                             &tcp_buckets[hash], hash_node)
    {
        if (tcp->local_addr == local_addr &&
            tcp->peer_addr == htonl(INADDR_ANY) &&
            tcp->local_port == local_port &&
            tcp->peer_port == 0)
        {
            return tcp;
        }
    }

    /* Try to match local_port only */
    hash = exasock_tcp_hash(htonl(INADDR_ANY), htonl(INADDR_ANY), local_port,
                            0);
    hlist_for_each_entry_rcu(tcp,
#ifdef __HAS_OLD_HLIST_ITERATOR
                             n,
#endif
                             &tcp_buckets[hash], hash_node)
    {
        if (tcp->local_addr == htonl(INADDR_ANY) &&
            tcp->peer_addr == htonl(INADDR_ANY) &&
            tcp->local_port == local_port &&
            tcp->peer_port == 0)
        {
            return tcp;
        }
    }

    return NULL;
}

/* Looks up exasock_tcp struct in hashtable.
 * RCU read lock must be held. */
static struct exasock_tcp *exasock_tcp_lookup(uint32_t local_addr,
                                              uint32_t peer_addr,
                                              uint16_t local_port,
                                              uint16_t peer_port)
{
    struct exasock_tcp *tcp;
#ifdef __HAS_OLD_HLIST_ITERATOR
    struct hlist_node *n;
#endif
    unsigned hash;

    /* Try to match (local_addr, peer_addr, local_port, peer_port) */
    hash = exasock_tcp_hash(local_addr, peer_addr, local_port, peer_port);
    hlist_for_each_entry_rcu(tcp,
#ifdef __HAS_OLD_HLIST_ITERATOR
                             n,
#endif
                             &tcp_buckets[hash], hash_node)
    {
        if (tcp->local_addr == local_addr &&
            tcp->peer_addr == peer_addr &&
            tcp->local_port == local_port &&
            tcp->peer_port == peer_port)
        {
            return tcp;
        }
    }

    /* Try to match (local_addr, local_port) */
    hash = exasock_tcp_hash(local_addr, htonl(INADDR_ANY), local_port, 0);
    hlist_for_each_entry_rcu(tcp,
#ifdef __HAS_OLD_HLIST_ITERATOR
                             n,
#endif
                             &tcp_buckets[hash], hash_node)
    {
        if (tcp->local_addr == local_addr &&
            tcp->peer_addr == htonl(INADDR_ANY) &&
            tcp->local_port == local_port &&
            tcp->peer_port == 0)
        {
            return tcp;
        }
    }

    /* Try to match local_port only */
    hash = exasock_tcp_hash(htonl(INADDR_ANY), htonl(INADDR_ANY), local_port,
                            0);
    hlist_for_each_entry_rcu(tcp,
#ifdef __HAS_OLD_HLIST_ITERATOR
                             n,
#endif
                             &tcp_buckets[hash], hash_node)
    {
        if (tcp->local_addr == htonl(INADDR_ANY) &&
            tcp->peer_addr == htonl(INADDR_ANY) &&
            tcp->local_port == local_port &&
            tcp->peer_port == 0)
        {
            return tcp;
        }
    }

    return NULL;
}

static bool exasock_tcp_intercept(struct sk_buff *skb)
{
    struct exasock_tcp *tcp;
    struct iphdr *iph;
    struct tcphdr *th;
    char *payload = skb->data;

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
    if (iph->protocol != IPPROTO_TCP)
        return false;

    /* Packet is TCP, search socket table for a match */
    th = (struct tcphdr *)(payload + iph->ihl * 4);
    rcu_read_lock();
    tcp = exasock_tcp_lookup(iph->daddr, iph->saddr, th->dest, th->source);
    rcu_read_unlock();
    if (tcp == NULL)
        return false;

    /* Queue the packet to be processed after a short delay */
    skb_queue_head(&tcp_packets, skb);
    queue_delayed_work(tcp_workqueue, &tcp_rx_work, 1);
    return true;
}

static int exasock_tcp_conn_process(struct exasock_tcp *tcp,
                                    struct iphdr *iph, struct tcphdr *th,
                                    char *data, unsigned datalen)
{
    struct exa_socket_state *state = tcp->user_page;
    uint32_t ack_seq = ntohl(th->ack_seq);

    /* TODO: Packet receive processing goes here */

    if (th->ack)
    {
        /* Duplicate ACK processing for fast retransmit */
        if (ack_seq == tcp->last_recv_ack_seq)
        {
            /* Duplicate ACK */
            uint32_t send_seq = state->p.tcp.send_seq;

            if (ack_seq != send_seq)
                tcp->num_dup_acks++;
        }
        else
        {
            /* Non-duplicate ACK */
            uint32_t cwnd = state->p.tcp.cwnd;
            uint32_t ssthresh = state->p.tcp.ssthresh;

            if (cwnd <= ssthresh)
            {
                /* Slow-start mode */
                cwnd += EXA_TCP_MSS;
            }
            else
            {
                /* Congestion avoidance mode */
                cwnd += EXA_TCP_MSS * EXA_TCP_MSS / cwnd;
            }

            state->p.tcp.cwnd = cwnd;

            tcp->num_dup_acks = 0;
        }

        if (tcp->fast_retransmit && after(ack_seq, tcp->last_recv_ack_seq))
            exasock_tcp_retransmit(tcp, ack_seq, true);

        if (tcp->num_dup_acks >= 3 && !tcp->fast_retransmit)
        {
            uint32_t flight_size, ssthresh, send_seq, send_ack;

            send_seq = state->p.tcp.send_seq;
            send_ack = state->p.tcp.send_ack;

            /* Adjust cwnd and ssthresh */
            flight_size = send_seq - send_ack;
            ssthresh = flight_size / 2;
            if (ssthresh < 2 * EXA_TCP_MSS)
                ssthresh = 2 * EXA_TCP_MSS;

            state->p.tcp.cwnd = 2 * EXA_TCP_MSS;
            state->p.tcp.ssthresh = ssthresh;

            /* Enter fast retransmit state */
            tcp->fast_retransmit = true;
            tcp->fast_retransmit_recover_seq = send_seq;

            exasock_tcp_retransmit(tcp, ack_seq, true);
        }

        if (!before(ack_seq, tcp->fast_retransmit_recover_seq))
        {
            /* Leave fast retransmit state */
            tcp->fast_retransmit = false;
        }

        tcp->last_recv_ack_seq = ack_seq;
    }

    /* Send ACK if needed */
    if (state->p.tcp.ack_pending)
        exasock_tcp_send_ack(tcp);

    return 0;
}

static void exasock_tcp_req_worker(struct work_struct *work)
{
    struct exasock_tcp_req *req, *tmp;

    /* Expire old TCP connection requests */
    spin_lock(&tcp_req_lock);
    list_for_each_entry_safe(req, tmp, &tcp_req_list, list)
    {
        if (time_after(jiffies, req->timestamp + TCP_REQUEST_JIFFIES))
        {
            hlist_del(&req->hash_node);
            list_del(&req->list);
            kfree(req);
        }
    }
    spin_unlock(&tcp_req_lock);

    queue_delayed_work(tcp_workqueue, &tcp_req_work, TCP_TIMER_JIFFIES);
}

static struct exasock_tcp_req *exasock_tcp_req_lookup(uint32_t local_addr,
                                                      uint32_t peer_addr,
                                                      uint16_t local_port,
                                                      uint16_t peer_port)
{
    struct exasock_tcp_req *req;
#ifdef __HAS_OLD_HLIST_ITERATOR
    struct hlist_node *n;
#endif
    unsigned hash;

    hash = exasock_tcp_hash(local_addr, peer_addr, local_port, peer_port);
    hlist_for_each_entry(req,
#ifdef __HAS_OLD_HLIST_ITERATOR
                         n,
#endif
                         &tcp_req_buckets[hash], hash_node)
    {
        if (req->local_addr == local_addr &&
            req->peer_addr == peer_addr &&
            req->local_port == local_port &&
            req->peer_port == peer_port)
        {
            return req;
        }
    }
    return NULL;
}

static int exasock_tcp_req_process(struct exasock_tcp *tcp,
                                   struct iphdr *iph, struct tcphdr *th,
                                   uint8_t *tcpopt, unsigned tcpoptlen)
{
    struct exa_socket_state *state = tcp->user_page;
    struct exa_tcp_new_connection *conn;
    struct exasock_tcp_req *req;
    uint32_t recv_seq, read_seq, offs;
    unsigned hash, i;

    if (th->rst)
    {
        /* RST packet */

        /* Remove connection from queue */
        spin_lock(&tcp_req_lock);
        req = exasock_tcp_req_lookup(iph->daddr, iph->saddr,
                                     th->dest, th->source);
        if (req != NULL)
        {
            hlist_del(&req->hash_node);
            list_del(&req->list);
        }
        spin_unlock(&tcp_req_lock);
        return 0;
    }
    else if (th->syn)
    {
        /* SYN packet */
        if (th->ack)
            return 0;

        /* Create new connection */
        req = kzalloc(sizeof(*req), GFP_KERNEL);
        if (req == NULL)
            return 0;

        req->timestamp = jiffies;

        req->local_addr = iph->daddr;
        req->peer_addr = iph->saddr;
        req->local_port = th->dest;
        req->peer_port = th->source;
#ifdef __HAS_OLD_NET_RANDOM
        req->local_seq = net_random();
#else
        req->local_seq = prandom_u32();
#endif
        req->peer_seq = ntohl(th->seq) + 1;
        req->window = ntohs(th->window);
        req->state = EXA_TCP_SYN_RCVD;

        /* Default values for options */
        req->mss = EXA_TCP_MSS;
        req->wscale = 0;

        /* Parse TCP options */
        for (i = 0; i < tcpoptlen && tcpopt[i] != TCPOPT_EOL;
             i += (tcpopt[i] == TCPOPT_NOP) ? 1 : tcpopt[i + 1])
        {
            switch (tcpopt[i])
            {
            case TCPOPT_MSS:
                req->mss = ((uint16_t)tcpopt[i + 2] << 8) | tcpopt[i + 3];
                break;
            case TCPOPT_WINDOW:
                req->wscale = tcpopt[i + 2];
                break;
            }
        }

        /* Send SYN ACK packet */
        exasock_tcp_send_syn_ack(req);

        /* Insert into hash table and lists */
        hash = exasock_tcp_hash(req->local_addr, req->peer_addr,
                                req->local_port, req->peer_port);
        spin_lock(&tcp_req_lock);
        hlist_add_head(&req->hash_node, &tcp_req_buckets[hash]);
        list_add(&req->list, &tcp_req_list);
        spin_unlock(&tcp_req_lock);
        return 0;
    }
    else if (th->ack)
    {
        /* ACK packet */
        spin_lock(&tcp_req_lock);
        req = exasock_tcp_req_lookup(iph->daddr, iph->saddr,
                                     th->dest, th->source);
        if (req == NULL)
        {
            spin_unlock(&tcp_req_lock);
            return 0;
        }

        if (req->state != EXA_TCP_SYN_RCVD ||
            req->local_seq != ntohl(th->ack_seq) ||
            req->peer_seq != ntohl(th->seq))
        {
            /* Sequence numbers don't match */
            spin_unlock(&tcp_req_lock);
            return 0;
        }

        /* Insert into accepted queue */
        if (exasock_trylock(&state->rx_lock) == 0)
        {
            /* Lock failed, retry later */
            spin_unlock(&tcp_req_lock);
            return -1;
        }

        read_seq = state->p.tcp.read_seq;
        recv_seq = state->p.tcp.recv_seq;
        offs = recv_seq & RX_BUFFER_MASK;

        if (recv_seq - read_seq >= RX_BUFFER_SIZE ||
            offs + sizeof(struct exa_tcp_new_connection) > RX_BUFFER_SIZE)
        {
            /* No space in buffer */
            spin_unlock(&tcp_req_lock);
            return 0;
        }

        conn = (struct exa_tcp_new_connection *)(tcp->rx_buffer + offs);

        conn->local_addr = req->local_addr;
        conn->peer_addr = req->peer_addr;
        conn->local_port = req->local_port;
        conn->peer_port = req->peer_port;
        conn->local_seq = req->local_seq;
        conn->peer_seq = req->peer_seq;
        conn->peer_window = req->window;
        conn->peer_mss = req->mss;
        conn->peer_wscale = req->wscale;

        state->p.tcp.recv_seq = recv_seq +
                                sizeof(struct exa_tcp_new_connection);

        exasock_unlock(&state->rx_lock);

        spin_lock(&tcp->notify_lock);
        if (tcp->notify)
            exasock_epoll_update(tcp->notify);
        spin_unlock(&tcp->notify_lock);

        /* Remove from incomplete connections */
        hlist_del(&req->hash_node);
        list_del(&req->list);
        kfree(req);

        spin_unlock(&tcp_req_lock);
        return 0;
    }
    else
        return 0;
}

static bool exasock_tcp_process_packet(struct sk_buff *skb)
{
    struct exasock_tcp *tcp;
    struct iphdr *iph;
    struct tcphdr *th;
    char *payload = skb->data;
    char *data;
    uint8_t *tcpopt;
    unsigned tcplen, tcpoptlen, datalen;
    int ret;

    if (skb->protocol == htons(ETH_P_8021Q))
        payload += sizeof(struct vlan_hdr);

    iph = (struct iphdr *)payload;
    th = (struct tcphdr *)(payload + iph->ihl * 4);
    tcplen = ntohs(iph->tot_len) - (iph->ihl * 4);

    /* Discard packet if checksums are invalid */
    if (ip_fast_csum(iph, iph->ihl))
        return true;
    if (csum_tcpudp_magic(iph->saddr, iph->daddr, tcplen, IPPROTO_TCP,
                          csum_partial(th, tcplen, 0)))
        return true;

    /* Look up socket */
    rcu_read_lock();
    tcp = exasock_tcp_lookup(iph->daddr, iph->saddr, th->dest, th->source);
    if (tcp == NULL)
    {
        rcu_read_unlock();
        return true;
    }
    kref_get(&tcp->refcount);
    rcu_read_unlock();

    data = payload + (iph->ihl * 4) + (th->doff * 4);
    datalen = tcplen - (th->doff * 4);

    tcpopt = (uint8_t *)(payload + (iph->ihl * 4) + sizeof(struct tcphdr));
    tcpoptlen = (th->doff * 4) > sizeof(struct tcphdr) ?
                (th->doff * 4) - sizeof(struct tcphdr) : 0;

    /* Process packet */
    if (tcp->user_page->p.tcp.state == EXA_TCP_LISTEN)
        ret = exasock_tcp_req_process(tcp, iph, th, tcpopt, tcpoptlen);
    else
        ret = exasock_tcp_conn_process(tcp, iph, th, data, datalen);

    kref_put(&tcp->refcount, exasock_tcp_dead);
    return ret == 0;
}

static void exasock_tcp_rx_worker(struct work_struct *work)
{
    struct sk_buff *skb;
    struct sk_buff_head tmp_queue;

    skb_queue_head_init(&tmp_queue);

    while ((skb = skb_dequeue_tail(&tcp_packets)) != NULL)
    {
        /* Re-queue packet if exasock_tcp_process_packet() returns false */
        if (exasock_tcp_process_packet(skb))
            dev_kfree_skb_any(skb);
        else
            skb_queue_head(&tmp_queue, skb);
    }

    /* Add a delay before running worker again */
    if (!skb_queue_empty(&tmp_queue))
        queue_delayed_work(tcp_workqueue, &tcp_rx_work, 1);

    skb_queue_splice(&tmp_queue, &tcp_packets);
}

static void exasock_tcp_conn_worker(struct work_struct *work)
{
    struct exasock_tcp *tcp = container_of(work, struct exasock_tcp, work.work);
    struct exa_socket_state *state = tcp->user_page;
    uint32_t send_ack, send_seq;
    uint8_t tcp_state;

    rcu_read_lock();
    if (tcp->dead_node)
    {
        /* This exasock_tcp struct is being deleted */
        rcu_read_unlock();
        return;
    }
    kref_get(&tcp->refcount);
    rcu_read_unlock();

    send_ack = state->p.tcp.send_ack;
    send_seq = state->p.tcp.send_seq;
    tcp_state = state->p.tcp.state;

    if (tcp->retransmit_countdown > 0)
        tcp->retransmit_countdown--;

    if (tcp->retransmit_countdown == 0)
    {
        /* ACK timeout */
        tcp->retransmit_countdown = -1;
        state->p.tcp.cwnd = EXA_TCP_MSS;
        exasock_tcp_retransmit(tcp, send_ack, false);
    }
    else if (state->p.tcp.ack_pending)
    {
        exasock_tcp_send_ack(tcp);
    }

    if (tcp_state == EXA_TCP_CLOSED || tcp_state == EXA_TCP_LISTEN)
    {
        /* No retransmissions in these states */
        tcp->retransmit_countdown = -1;
    }
    else if (tcp_state == EXA_TCP_SYN_RCVD || tcp_state == EXA_TCP_SYN_SENT ||
             tcp_state == EXA_TCP_FIN_WAIT_1)
    {
        /* ACKs are pending from the remote host */
        if (tcp->retransmit_countdown == -1)
        {
            tcp->retransmit_countdown = RETRANSMIT_TIMEOUT;
        }
    }
    else if (send_ack != send_seq)
    {
        /* ACKs are pending from the remote host, reset retransmit countdown
         * if it is not set, or if progress has been made */
        if (tcp->retransmit_countdown == -1 ||
            tcp->last_send_ack != send_ack)
        {
            tcp->retransmit_countdown = RETRANSMIT_TIMEOUT;
        }
    }
    else
    {
        /* No ACKs pending, disable timeout */
        tcp->retransmit_countdown = -1;
    }

    if (state->p.tcp.ss_after_idle &&
        send_ack == send_seq && 
        tcp->last_send_seq == send_seq)
    {
        /* Connection is idle, returns congestion control to slow-start state */
        state->p.tcp.cwnd = 3 * EXA_TCP_MSS;
    }

    tcp->last_send_ack = send_ack;
    tcp->last_send_seq = send_seq;

    if ((tcp_state != EXA_TCP_CLOSED) && (tcp_state != EXA_TCP_LISTEN) &&
        (tcp_state != EXA_TCP_SYN_SENT) && (tcp_state != EXA_TCP_SYN_RCVD))
    {
        exasock_tcp_counters_update(&tcp->counters, &state->p.tcp);
    }

    queue_delayed_work(tcp_workqueue, &tcp->work, TCP_TIMER_JIFFIES);
    kref_put(&tcp->refcount, exasock_tcp_dead);
}

static uint16_t exasock_tcp_calc_window(struct exasock_tcp *tcp)
{
    struct exa_socket_state *state = tcp->user_page;
    uint32_t rx_space;

    /* Calculate window size from remaining space in buffer */
    rx_space = state->rx_buffer_size -
               (state->p.tcp.recv_seq - state->p.tcp.read_seq);

    /* Window scaling is enabled if remote host gave a non-zero window scale */
    if (state->p.tcp.wscale != 0)
        rx_space >>= EXA_TCP_WSCALE;

    return rx_space < 0xFFFF ? rx_space : 0xFFFF;
}

static int exasock_tcp_tx_buffer_get(struct exasock_tcp *tcp, char *data,
                                     uint32_t seq, uint32_t len)
{
    struct exa_socket_state *state = tcp->user_page;
    uint32_t seq_end = seq + len;

    if (after(seq_end, state->p.tcp.send_seq))
        return -1;

    if ((seq & ~TX_BUFFER_MASK) == ((seq_end - 1) & ~TX_BUFFER_MASK))
    {
        memcpy(data, tcp->tx_buffer + (seq & TX_BUFFER_MASK), len);
    }
    else
    {
        memcpy(data, tcp->tx_buffer + (seq & TX_BUFFER_MASK),
               TX_BUFFER_SIZE - (seq & TX_BUFFER_MASK));
        memcpy(data + (TX_BUFFER_SIZE - (seq & TX_BUFFER_MASK)),
               tcp->tx_buffer, (seq_end & TX_BUFFER_MASK));
    }

    if (before(seq, state->p.tcp.send_ack))
        return -1;

    return 0;
}

static void exasock_tcp_retransmit_packet(struct exasock_tcp *tcp,
                                          uint32_t seq, uint32_t len)
{
    struct exa_socket_state *state = tcp->user_page;
    struct sk_buff *skb;
    struct tcphdr *th;
    uint8_t tcp_state;
    uint32_t send_seq, recv_seq;
    bool data_allowed = false;

    /* We are just reading so don't need any locks */
    tcp_state = state->p.tcp.state;
    send_seq = state->p.tcp.send_seq;
    recv_seq = state->p.tcp.recv_seq;

    /* Clear ack_pending flag because an ACK is about to be sent */
    state->p.tcp.ack_pending = false;

    skb = alloc_skb(MAX_TCP_HEADER + len, GFP_KERNEL);
    if (skb == NULL)
        return;
    skb_reserve(skb, VLAN_ETH_HLEN + sizeof(struct iphdr));

    th = (struct tcphdr *)skb_put(skb, sizeof(struct tcphdr));

    memset(th, 0, sizeof(struct tcphdr));
    th->source = tcp->local_port;
    th->dest = tcp->peer_port;

    switch (tcp_state)
    {
    case EXA_TCP_SYN_SENT:
        /* Send SYN */
        th->seq = htonl(send_seq - 1);
        th->ack_seq = 0;
        th->syn = 1;
        break;

    case EXA_TCP_SYN_RCVD:
        /* Send SYN ACK */
        th->seq = htonl(send_seq - 1);
        th->ack_seq = htonl(recv_seq);
        th->syn = 1;
        th->ack = 1;
        break;

    case EXA_TCP_ESTABLISHED:
        /* Send ACK */
        th->seq = htonl(seq);
        th->ack_seq = htonl(recv_seq);
        th->ack = 1;
        data_allowed = true;
        break;

    case EXA_TCP_CLOSE_WAIT:
        /* Send ACK for remote FIN */
        th->seq = htonl(seq);
        th->ack_seq = htonl(recv_seq + 1);
        th->ack = 1;
        data_allowed = true;
        break;

    case EXA_TCP_FIN_WAIT_1:
        /* Send FIN */
        th->seq = htonl(seq);
        th->ack_seq = htonl(recv_seq);
        if (send_seq == seq)
            th->fin = 1;
        th->ack = 1;
        data_allowed = true;
        break;

    case EXA_TCP_FIN_WAIT_2:
        /* Send ACK */
        th->seq = htonl(seq);
        th->ack_seq = htonl(recv_seq);
        th->ack = 1;
        break;

    case EXA_TCP_CLOSING:
        /* Send ACK for remote FIN */
        th->seq = htonl(seq);
        th->ack_seq = htonl(recv_seq + 1);
        th->ack = 1;
        data_allowed = true;
        break;

    case EXA_TCP_LAST_ACK:
        /* Send FIN */
        th->seq = htonl(seq);
        th->ack_seq = htonl(recv_seq + 1);
        th->fin = 1;
        th->ack = 1;
        data_allowed = true;
        break;

    case EXA_TCP_TIME_WAIT:
        /* Send ACK for remote FIN */
        th->seq = htonl(send_seq + 1);
        th->ack_seq = htonl(recv_seq + 1);
        th->ack = 1;
        break;

    default:
        /* Don't send a packet */
        goto abort_packet;
    }

    if (tcp_state == EXA_TCP_SYN_SENT || tcp_state == EXA_TCP_SYN_RCVD)
    {
        uint8_t *opts = (uint8_t *)skb_put(skb, 8);

        /* Add MSS and window scale options to header */
        opts[0] = TCPOPT_MSS;
        opts[1] = TCPOLEN_MSS;
        opts[2] = EXA_TCP_MSS >> 8;
        opts[3] = EXA_TCP_MSS & 0xFF;
        opts[4] = TCPOPT_NOP;
        opts[5] = TCPOPT_WINDOW;
        opts[6] = TCPOLEN_WINDOW;
        opts[7] = EXA_TCP_WSCALE;
    }

    th->doff = skb->len / 4;
    th->window = htons(exasock_tcp_calc_window(tcp));

    if (data_allowed && len > 0)
    {
        char *data = skb_put(skb, len);
        if (exasock_tcp_tx_buffer_get(tcp, data, seq, len) == -1)
            goto abort_packet;
    }

    th->check = csum_tcpudp_magic(tcp->peer_addr, tcp->local_addr, skb->len,
                                  IPPROTO_TCP, csum_partial(th, skb->len, 0));

    exasock_ip_send(IPPROTO_TCP, tcp->peer_addr, tcp->local_addr, skb);
    return;

abort_packet:
    kfree_skb(skb);
}

/* Retransmit one MSS of data at the given sequence number */
static void exasock_tcp_retransmit(struct exasock_tcp *tcp, uint32_t seq,
                                   bool fast_retrans)
{
    struct exa_socket_state *state = tcp->user_page;
    uint32_t rmss, send_seq;
    uint32_t len;
    uint8_t tcp_state;

    rmss = state->p.tcp.rmss;
    send_seq = state->p.tcp.send_seq;
    tcp_state = state->p.tcp.state;

    if (tcp_state == EXA_TCP_SYN_RCVD || tcp_state == EXA_TCP_SYN_SENT)
    {
        /* Data retransmissions are only allowed in a synchronised state */
        len = 0;
    }
    else
    {
        len = send_seq - seq;

        if (len > EXA_TCP_MSS)
            len = EXA_TCP_MSS;

        if (len > rmss)
            len = rmss;
    }

    /* No need to lock counters as long as updated from the single-thread
     * workqueue only */
    tcp->counters.retrans_bytes += len;
    if (fast_retrans)
        tcp->counters.retrans_segs_fast++;
    else
        tcp->counters.retrans_segs_to++;

    exasock_tcp_retransmit_packet(tcp, seq, len);
}

static void exasock_tcp_send_ack(struct exasock_tcp *tcp)
{
    struct exa_socket_state *state = tcp->user_page;

    exasock_tcp_retransmit_packet(tcp, state->p.tcp.send_seq, 0);
}

static void exasock_tcp_send_reset(struct exasock_tcp *tcp)
{
    struct exa_socket_state *state = tcp->user_page;
    struct sk_buff *skb;
    struct tcphdr *th;
    uint8_t tcp_state;
    uint32_t send_seq, recv_seq;

    tcp_state = state->p.tcp.state;
    send_seq = state->p.tcp.send_seq;
    recv_seq = state->p.tcp.recv_seq;

    skb = alloc_skb(MAX_TCP_HEADER, GFP_KERNEL);
    if (skb == NULL)
        return;
    skb_reserve(skb, VLAN_ETH_HLEN + sizeof(struct iphdr));

    th = (struct tcphdr *)skb_put(skb, sizeof(struct tcphdr));

    memset(th, 0, sizeof(struct tcphdr));
    th->source = tcp->local_port;
    th->dest = tcp->peer_port;
    th->doff = skb->len / 4;
    th->rst = 1;
    th->ack = 1;

    switch (tcp_state)
    {
    case EXA_TCP_SYN_RCVD:
    case EXA_TCP_ESTABLISHED:
        th->seq = htonl(send_seq);
        th->ack_seq = htonl(recv_seq);
        break;

    case EXA_TCP_CLOSE_WAIT:
        th->seq = htonl(send_seq);
        th->ack_seq = htonl(recv_seq + 1);
        break;

    case EXA_TCP_FIN_WAIT_1:
    case EXA_TCP_FIN_WAIT_2:
        th->seq = htonl(send_seq + 1);
        th->ack_seq = htonl(recv_seq);
        break;

    case EXA_TCP_CLOSING:
    case EXA_TCP_LAST_ACK:
    case EXA_TCP_TIME_WAIT:
        th->seq = htonl(send_seq + 1);
        th->ack_seq = htonl(recv_seq + 1);
        break;

    default:
        /* Don't send a RST packet in these states */
        goto abort_packet;
    }

    th->check = csum_tcpudp_magic(tcp->peer_addr, tcp->local_addr, skb->len,
                                  IPPROTO_TCP, csum_partial(th, skb->len, 0));

    exasock_ip_send(IPPROTO_TCP, tcp->peer_addr, tcp->local_addr, skb);
    return;

abort_packet:
    kfree_skb(skb);
}

static void exasock_tcp_send_syn_ack(struct exasock_tcp_req *req)
{
    struct sk_buff *skb;
    struct tcphdr *th;
    uint8_t *opts;

    skb = alloc_skb(MAX_TCP_HEADER, GFP_KERNEL);
    if (skb == NULL)
        return;
    skb_reserve(skb, VLAN_ETH_HLEN + sizeof(struct iphdr));

    /* Construct TCP header */
    th = (struct tcphdr *)skb_put(skb, sizeof(struct tcphdr));

    memset(th, 0, sizeof(struct tcphdr));
    th->source = req->local_port;
    th->dest = req->peer_port;
    th->seq = htonl(req->local_seq - 1);
    th->ack_seq = htonl(req->peer_seq);
    th->window = htons(32000); /* Smaller than the real window size */
    th->syn = 1;
    th->ack = 1;

    opts = (uint8_t *)skb_put(skb, 8);

    /* Add MSS and window scale options to header */
    opts[0] = TCPOPT_MSS;
    opts[1] = TCPOLEN_MSS;
    opts[2] = EXA_TCP_MSS >> 8;
    opts[3] = EXA_TCP_MSS & 0xFF;
    opts[4] = TCPOPT_NOP;
    opts[5] = TCPOPT_WINDOW;
    opts[6] = TCPOLEN_WINDOW;
    opts[7] = EXA_TCP_WSCALE;

    th->doff = skb->len / 4;
    th->check = csum_tcpudp_magic(req->peer_addr, req->local_addr, skb->len,
                                  IPPROTO_TCP, csum_partial(th, skb->len, 0));

    exasock_ip_send(IPPROTO_TCP, req->peer_addr, req->local_addr, skb);
}

int exasock_tcp_notify_add(uint32_t local_addr, uint16_t local_port,
                           struct exasock_epoll_notify *notify)
{
    struct exasock_tcp *tcp;
    int ret = 0;

    /* Look up socket */
    rcu_read_lock();
    tcp = exasock_tcp_listen_lookup(local_addr, local_port);
    if (tcp == NULL)
    {
        rcu_read_unlock();
        return -ENOENT;
    }
    kref_get(&tcp->refcount);
    rcu_read_unlock();

    spin_lock(&tcp->notify_lock);

    if (tcp->notify != NULL)
    {
        /* This socket is already a member of an epoll */
        ret = -EINVAL;
        goto exit;
    }
    tcp->notify = notify;

exit:
    spin_unlock(&tcp->notify_lock);
    kref_put(&tcp->refcount, exasock_tcp_dead);
    return ret;
}

int exasock_tcp_notify_del(uint32_t local_addr, uint16_t local_port,
                           struct exasock_epoll_notify **notify)
{
    struct exasock_tcp *tcp;
    int ret = 0;

    /* Look up socket */
    rcu_read_lock();
    tcp = exasock_tcp_listen_lookup(local_addr, local_port);
    if (tcp == NULL)
    {
        *notify = NULL;
        rcu_read_unlock();
        return -ENOENT;
    }
    kref_get(&tcp->refcount);
    rcu_read_unlock();

    spin_lock(&tcp->notify_lock);

    *notify = tcp->notify;
    if (tcp->notify == NULL)
    {
        spin_unlock(&tcp->notify_lock);
        ret = -EINVAL;
        goto exit;
    }
    tcp->notify = NULL;

exit:
    spin_unlock(&tcp->notify_lock);
    kref_put(&tcp->refcount, exasock_tcp_dead);
    return ret;
}

int exasock_tcp_setsockopt(struct exasock_tcp *tcp, int level, int optname,
                           char __user *optval, unsigned int optlen)
{
    int ret;

    BUG_ON(tcp->hdr.type != EXASOCK_TYPE_SOCKET);
    BUG_ON(tcp->hdr.socket.domain != AF_INET);
    BUG_ON(tcp->hdr.socket.type != SOCK_STREAM);

    ret = tcp->sock->ops->setsockopt(tcp->sock, level, optname, optval, optlen);

    return ret;
}

int exasock_tcp_getsockopt(struct exasock_tcp *tcp, int level, int optname,
                           char __user *optval, unsigned int *optlen)
{
    int ret;
    mm_segment_t old_fs;

    BUG_ON(tcp->hdr.type != EXASOCK_TYPE_SOCKET);
    BUG_ON(tcp->hdr.socket.domain != AF_INET);
    BUG_ON(tcp->hdr.socket.type != SOCK_STREAM);

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = tcp->sock->ops->getsockopt(tcp->sock, level, optname, optval, optlen);
    set_fs(old_fs);

    return ret;
}

int __init exasock_tcp_init(void)
{
    tcp_buckets = kzalloc(NUM_BUCKETS * sizeof(*tcp_buckets), GFP_KERNEL);
    tcp_req_buckets = kzalloc(NUM_BUCKETS * sizeof(*tcp_req_buckets), GFP_KERNEL);
    skb_queue_head_init(&tcp_packets);
    tcp_workqueue = create_singlethread_workqueue("exasock_tcp");
    INIT_DELAYED_WORK(&tcp_rx_work, exasock_tcp_rx_worker);
    INIT_DELAYED_WORK(&tcp_req_work, exasock_tcp_req_worker);
    queue_delayed_work(tcp_workqueue, &tcp_req_work, TCP_TIMER_JIFFIES);
    return exanic_netdev_intercept_add(&exasock_tcp_intercept);
}

void exasock_tcp_exit(void)
{
    exanic_netdev_intercept_remove(&exasock_tcp_intercept);
    cancel_delayed_work_sync(&tcp_req_work);
    flush_workqueue(tcp_workqueue);
    destroy_workqueue(tcp_workqueue);
    skb_queue_purge(&tcp_packets);
    kfree(tcp_req_buckets);
    kfree(tcp_buckets);
}
