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
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#include "exasock-siphash.h"
#else
#include <linux/siphash.h>
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#define __GETNAME_NO_SOCKLEN_PARAM
#endif

struct exasock_tcp_conn_counters
{
    bool        initialized;

    uint32_t    send_rounds;
    uint32_t    send_ack_rounds;
    uint32_t    recv_rounds;
    uint32_t    recv_read_rounds;

    uint32_t    prev_send_seq;
    uint32_t    prev_send_ack;
    uint32_t    prev_recv_seq;
    uint32_t    prev_read_seq;

    uint32_t    retrans_bytes;
    uint32_t    retrans_segs_fast;
    uint32_t    retrans_segs_to;
};

struct exasock_tcp_listen_counters
{
    uint32_t    reqs_rcvd;
    uint32_t    reqs_estab;
};

struct exasock_tcp_counters
{
    spinlock_t  lock;

    union
    {
        struct exasock_tcp_conn_counters    conn;
        struct exasock_tcp_listen_counters  listen;
    } s;
};

/* Element of the list of received segments */
struct exasock_tcp_seg_el
{
    char *data;
    unsigned len;
    struct list_head node;
    struct sk_buff *skb;
};

/* List of contiguous received segments */
struct exasock_tcp_rx_seg
{
    uint32_t begin;
    uint32_t end;
    struct list_head seg_list;
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

    /* Local storage for received segments */
    struct exasock_tcp_rx_seg       rx_seg[EXA_TCP_MAX_RX_SEGMENTS];

    /* Value of send_seq and send_ack at last timer tick */
    uint32_t                        last_send_seq;
    uint32_t                        last_send_ack;

    /* Number of times the last seen ACK hasn't changed */
    uint32_t                        last_ack_counter;

    /* Last advertised window */
    struct
    {
        uint32_t                    end;
        bool                        valid;
    } adv_win;

    /* Counters for out of order segments received without progress in recv_seq
     */
    struct
    {
        /* Count of out of order segments received in kernel */
        unsigned                    cnt;
        /* Number of duplicate ACKs sent */
        unsigned                    acks_sent;
        /* Ack Num value in the duplicate ACK */
        uint32_t                    ack_seq;
        bool                        valid;
    } out_of_order;

    /* Retransmit timeout is triggered when count reaches 0 */
    int                             retransmit_countdown;
    /* Exit timewait state when count reaches 0 */
    int                             timewait_countdown;

    /* Received duplicate acks state. Used for entering fast retransmit. */
    struct
    {
        unsigned                    cnt;
        uint32_t                    ack_seq;
        uint32_t                    win_end;
    } dup_acks;

    /* Fast retransmit state */
    bool                            fast_retransmit;
    uint32_t                        fast_retransmit_recover_seq;

    /* Keep-alive counters */
    struct
    {
        unsigned                    timer;
        unsigned                    probe_cnt;
    } keepalive;

    struct delayed_work             work;

    /* Window space availability monitoring */
    struct delayed_work             win_work;
    unsigned                        win_work_on;

    /* fin handshake and garbage collection work */
    struct delayed_work             fin_work;
    struct delayed_work             gc_work;
    /* list node for queueing on the tw death row */
    struct list_head                death_link;

    struct hlist_node               hash_node;
    bool                            dead_node;

    struct exasock_epoll_notify     notify;

    struct kref                     refcount;
    /* Semaphore stays down until refcount goes to 0 */
    struct semaphore                dead_sema;

    /* Statistics related structures */
    struct exasock_tcp_counters     counters;
    struct exasock_stats_sock       stats;

    /* user has called close() on this connection */
    bool                            user_closed;

    /* the final ack lost during timewait */
    bool                            timewait_dupfin;

    /* whether a reset should be sent on free() */
    bool                            reset_on_free;
};

struct exasock_tcp_req
{
    unsigned long               timestamp;

    /* number of syn-ack retransmissions attempted */
    unsigned                    synack_attempts;

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
/* for running deferred calls to exasock_tcp_gc_worker() */
static struct workqueue_struct *tcp_gc_workqueue;
static struct delayed_work      tcp_rx_work;

static struct hlist_head *      tcp_req_buckets;
static LIST_HEAD(               tcp_req_list);
static DEFINE_SPINLOCK(         tcp_req_lock);
static struct delayed_work      tcp_req_work;
/*
 * list of tcp sessions that have been closed by the user
 * but pending cleanup
 */
static LIST_HEAD(               tcp_wait_death_list);
static DEFINE_SPINLOCK(         tcp_wait_death_lock);
/*
 * random key for generating initial sequence numbers,
 * initialised once and lives until driver unloaded
 */
static siphash_key_t            tcp_secret;

#define RX_BUFFER_SIZE          1048576
#define RX_BUFFER_MASK          (RX_BUFFER_SIZE - 1)
#define TX_BUFFER_SIZE          1048576
#define TX_BUFFER_MASK          (TX_BUFFER_SIZE - 1)

#define NUM_BUCKETS             4096

/* Timer fires once every 250ms */
#define TCP_TIMER_PER_SEC       4
#define TCP_TIMER_JIFFIES       (HZ / TCP_TIMER_PER_SEC)

/* Number of timer firings until retransmit */
#define RETRANSMIT_TIMEOUT      TCP_TIMER_PER_SEC

/* Number of syn-ack retransmissions we will attempt */
#define SYNACK_ATTEMPTS_MAX     5

/* Use the Linux default, TODO: make configurable */
#define TIMEWAIT_SECONDS        60
#define TIMEWAIT_TIMEOUT        TCP_TIMER_PER_SEC * TIMEWAIT_SECONDS

/* Number of timer firings until window update monitoring expires */
#define WIN_WORK_TIMEOUT        (TCP_TIMER_PER_SEC / 2)

/* Number of jiffies until an incomplete TCP request expires */
#define TCP_REQUEST_JIFFIES     HZ

/* Number of jiffies before we retransmit syn-ack */
#define TCP_SYNACK_JIFFIES      (HZ / 2)

#define SEQNUM_ROLLOVER(start, last, now)   ((now) - (last) > (now) - (start))
#define SEQNUM_TO_BYTES(start, now, rounds) \
                               (((uint64_t)(rounds) << 32) | ((now) - (start)))

#define TCP_STATE_CMPXCHG(ts, old, new) \
                                       (cmpxchg(&(ts)->state, old, new) == old)

static void exasock_tcp_send_segment(struct exasock_tcp *tcp, uint32_t seq,
                                     uint32_t len, bool dup);
static void exasock_tcp_conn_worker(struct work_struct *work);
static void exasock_tcp_conn_win_worker(struct work_struct *work);
static void exasock_tcp_close_worker(struct work_struct *work);

static void exasock_tcp_retransmit(struct exasock_tcp *tcp, bool fast_retrans);
static void exasock_tcp_send_ack(struct exasock_tcp *tcp, bool dup);
static void exasock_tcp_send_reset(struct exasock_tcp *tcp);
uint32_t exasock_tcp_req_get_isn(struct exasock_tcp_req *req);
static void exasock_tcp_send_syn_ack(struct exasock_tcp *tcp, struct exasock_tcp_req *req);
static void exasock_tcp_send_probe(struct exasock_tcp *tcp);
static struct exasock_tcp *exasock_tcp_lookup(uint32_t local_addr,
                                              uint32_t peer_addr,
                                              uint16_t local_port,
                                              uint16_t peer_port);

/* this work reclaims all resources allocated for a
 * tcp connection. this function may sleep.
 * note: do not call it directly, only run on
 *       tcp_gc_workqueue */
static void exasock_tcp_gc_worker(struct work_struct *work);
static void exasock_tcp_dead(struct kref *ref);

/* this function performs some clean-up before
 * deferring exasock_tcp_gc_worker to the cleanup workqueue */
static void exasock_tcp_free(struct exasock_tcp *tcp);

/*
 * free all "stray" sessions, i.e.
 * those connections that the user has closed
 * but not yet cleaned up, e.g. in TIME_WAIT
 */
static inline void exasock_tcp_kill_stray(void)
{
    /* by this point everything on the death row should
     * be dormant and safe to kill. */
    struct exasock_tcp *tcp;
    rcu_read_lock();
    list_for_each_entry_rcu(tcp, &tcp_wait_death_list, death_link)
    {
        tcp->reset_on_free =
            tcp->user_page->p.tcp.state != EXA_TCP_TIME_WAIT;
        exasock_tcp_free(tcp);
    }
    rcu_read_unlock();
    flush_workqueue(tcp_gc_workqueue);
    destroy_workqueue(tcp_gc_workqueue);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
static inline void exasock_tcp_secret_init(void)
{
    net_get_random_once(&tcp_secret, sizeof(tcp_secret));
}
#else
static DEFINE_SPINLOCK(isn_lock);
static inline void exasock_tcp_secret_init(void)
{
    static bool done = false;
    if (likely(done))
        return;

    spin_lock(&isn_lock);
    if (!done)
    {
        get_random_bytes(&tcp_secret, sizeof(tcp_secret));
        done = true;
    }
    spin_unlock(&isn_lock);
}
#endif

static inline uint32_t exasock_tcp_isn_hash(uint32_t local_addr,
                                            uint32_t peer_addr,
                                            uint16_t local_port,
                                            uint16_t peer_port)
{
    uint32_t hash;
    exasock_tcp_secret_init();
    hash = siphash_3u32(local_addr, peer_addr,
                       ((uint32_t)local_port) << 16 | (uint32_t)peer_port,
                       &tcp_secret);
    return hash;
}

/* the Linux function for secure, monotonically increasing isn
 * is not available for use here unless the newest kernel is installed
 *
 * however the algorithm is simple so just lifted it all here instead */
uint32_t exasock_tcp_get_isn(struct exasock_tcp *tcp)
{
    return (ktime_to_ns(ktime_get_real()) >> 6) +
            exasock_tcp_isn_hash(tcp->local_addr, tcp->peer_addr,
                                 tcp->local_port, tcp->peer_port);
}

/* for syn-ack segments */
uint32_t exasock_tcp_req_get_isn(struct exasock_tcp_req *req)
{
    return (ktime_to_ns(ktime_get_real()) >> 6) +
            exasock_tcp_isn_hash(req->local_addr, req->peer_addr,
                                 req->local_port, req->peer_port);
}

static inline void exasock_tcp_counters_update_locked(
                                          struct exasock_tcp_conn_counters *cnt,
                                          struct exa_tcp_state *tcp_st,
                                          uint32_t send_seq, uint32_t send_ack,
                                          uint32_t recv_seq, uint32_t read_seq)
{
    if (!cnt->initialized)
    {
        cnt->prev_send_seq = tcp_st->stats.init_send_seq;
        cnt->prev_send_ack = tcp_st->stats.init_send_seq;
        cnt->prev_recv_seq = tcp_st->stats.init_recv_seq;
        cnt->prev_read_seq = tcp_st->stats.init_recv_seq;

        cnt->initialized = true;
    }

    if (SEQNUM_ROLLOVER(tcp_st->stats.init_send_seq, cnt->prev_send_seq,
                        send_seq))
        cnt->send_rounds++;

    if (SEQNUM_ROLLOVER(tcp_st->stats.init_send_seq, cnt->prev_send_ack,
                        send_ack))
        cnt->send_ack_rounds++;

    if (SEQNUM_ROLLOVER(tcp_st->stats.init_recv_seq, cnt->prev_recv_seq,
                        recv_seq))
        cnt->recv_rounds++;

    if (SEQNUM_ROLLOVER(tcp_st->stats.init_recv_seq, cnt->prev_read_seq,
                        read_seq))
        cnt->recv_read_rounds++;

    cnt->prev_send_seq = send_seq;
    cnt->prev_send_ack = send_ack;
    cnt->prev_recv_seq = recv_seq;
    cnt->prev_read_seq = read_seq;
}

static inline void exasock_tcp_counters_update(struct exasock_tcp_counters *cnt,
                                               struct exa_tcp_state *tcp_st)
{
    spin_lock(&cnt->lock);
    exasock_tcp_counters_update_locked(&cnt->s.conn, tcp_st,
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

static inline bool before_eq(uint32_t seq1, uint32_t seq2)
{
    return (int32_t)(seq1 - seq2) <= 0;
}

static inline bool after_eq(uint32_t seq1, uint32_t seq2)
{
    return (int32_t)(seq1 - seq2) >= 0;
}

static inline uint32_t get_last_win_end(struct exasock_tcp *tcp,
                                        struct exa_socket_state *state)
{
    return (after(tcp->adv_win.end, state->p.tcp.adv_wnd_end) &&
                 tcp->adv_win.valid) ?
                 tcp->adv_win.end : state->p.tcp.adv_wnd_end;
}

static inline void exasock_tcp_seg_list_cleanup(struct list_head *seg_list)
{
    struct exasock_tcp_seg_el *elem, *_elem;

    list_for_each_entry_safe(elem, _elem, seg_list, node)
    {
        list_del(&elem->node);
        dev_kfree_skb_any(elem->skb);
        kfree(elem);
    }
}

static uint8_t exasock_tcp_stats_get_state(struct exasock_stats_sock *stats)
{
    struct exasock_tcp *tcp = stats_to_tcp(stats);

    return tcp->user_page->p.tcp.state;
}

static void exasock_tcp_stats_get_snapshot_conn(struct exasock_tcp *tcp,
                             struct exasock_stats_sock_snapshot_brf *ssbrf,
                             struct exasock_stats_sock_snapshot_intconn *ssconn,
                             struct exa_tcp_state *tcp_st)
{
    struct exasock_tcp_conn_counters *cnt = &tcp->counters.s.conn;
    uint32_t send_seq;
    uint32_t send_ack;
    uint32_t recv_seq;
    uint32_t read_seq;
    uint8_t state;

    if (ssconn != NULL)
        spin_lock(&tcp->counters.lock);

    send_seq = tcp_st->send_seq;
    send_ack = tcp_st->send_ack;
    recv_seq = tcp_st->recv_seq;
    read_seq = tcp_st->read_seq;
    state = tcp_st->state;

    ssbrf->recv_q = recv_seq - read_seq;
    ssbrf->send_q = send_seq - send_ack;

    if (ssconn != NULL)
    {
        if ((state != EXA_TCP_CLOSED) && (state != EXA_TCP_SYN_SENT) &&
            (state != EXA_TCP_SYN_RCVD))
        {
            exasock_tcp_counters_update_locked(cnt, tcp_st, send_seq, send_ack,
                                               recv_seq, read_seq);
            spin_unlock(&tcp->counters.lock);

            ssconn->tx_bytes = SEQNUM_TO_BYTES(tcp_st->stats.init_send_seq,
                                               send_seq,
                                               cnt->send_rounds);
            ssconn->tx_acked_bytes = SEQNUM_TO_BYTES(tcp_st->stats.init_send_seq,
                                                     send_ack,
                                                     cnt->send_ack_rounds);
            ssconn->rx_bytes = SEQNUM_TO_BYTES(tcp_st->stats.init_recv_seq,
                                               recv_seq,
                                               cnt->recv_rounds);
            ssconn->rx_deliv_bytes = SEQNUM_TO_BYTES(tcp_st->stats.init_recv_seq,
                                                     read_seq,
                                                     cnt->recv_read_rounds);

            ssconn->wscale_peer = tcp_st->wscale;
            ssconn->wscale_local = (ssconn->wscale_peer ? EXA_TCP_WSCALE : 0);
            ssconn->window_peer = tcp_st->rwnd_end - send_ack;
            ssconn->window_local = tcp->user_page->rx_buffer_size -
                                  (recv_seq - read_seq);
            ssconn->mss_peer = tcp_st->rmss;
            ssconn->mss_local = EXA_TCP_MSS;
            ssconn->cwnd = tcp_st->cwnd;
            ssconn->ssthresh = tcp_st->ssthresh;
        }
        else
        {
            spin_unlock(&tcp->counters.lock);

            ssconn->tx_bytes = 0;
            ssconn->tx_acked_bytes = 0;
            ssconn->rx_bytes = 0;
            ssconn->rx_deliv_bytes = 0;

            ssconn->wscale_peer = 0;
            ssconn->wscale_local = 0;
            ssconn->window_peer = 0;
            ssconn->window_local = 0;
            ssconn->mss_peer = 0;
            ssconn->mss_local = 0;
            ssconn->cwnd = 0;
            ssconn->ssthresh = 0;
        }
        ssconn->retrans_segs_fast = cnt->retrans_segs_fast;
        ssconn->retrans_segs_to = cnt->retrans_segs_to;
        ssconn->retrans_bytes = cnt->retrans_bytes;
    }
}

static void exasock_tcp_stats_get_snapshot_listen(struct exasock_tcp *tcp,
                                 struct exasock_stats_sock_snapshot_brf *ssbrf,
                                 struct exasock_stats_sock_snapshot_intlis *sslis,
                                 struct exa_tcp_state *tcp_st)
{
    struct exasock_tcp_listen_counters *cnt = &tcp->counters.s.listen;

    ssbrf->recv_q = (tcp_st->recv_seq - tcp_st->read_seq) /
                    sizeof(struct exa_tcp_new_connection);
    ssbrf->send_q = 0;

    if (sslis != NULL)
    {
        sslis->reqs_rcvd = cnt->reqs_rcvd;
        sslis->reqs_estab = cnt->reqs_estab;
    }
}

static void exasock_tcp_stats_get_snapshot(struct exasock_stats_sock *stats,
                                 struct exasock_stats_sock_snapshot_brf *ssbrf,
                                 struct exasock_stats_sock_snapshot_int *ssint)
{
    struct exasock_tcp *tcp = stats_to_tcp(stats);
    struct exa_tcp_state *tcp_st = &tcp->user_page->p.tcp;
    void *ssintc = NULL;

    if (tcp_st->state == EXA_TCP_LISTEN)
    {
        if (ssint != NULL)
        {
            ssint->contents = EXASOCK_STATS_SOCK_SSINT_LISTEN;
            ssintc = &ssint->c.listen;
        }
        exasock_tcp_stats_get_snapshot_listen(tcp, ssbrf, ssintc, tcp_st);
    }
    else
    {
        if (ssint != NULL)
        {
            ssint->contents = EXASOCK_STATS_SOCK_SSINT_CONN;
            ssintc = &ssint->c.conn;
        }
        exasock_tcp_stats_get_snapshot_conn(tcp, ssbrf, ssintc, tcp_st);
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
    int i;

    /* Get local address from native socket */
    slen = sizeof(local);
    memset(&local, 0, sizeof(local));
#ifdef __GETNAME_NO_SOCKLEN_PARAM
    err = slen = sock->ops->getname(sock, (struct sockaddr *)&local, 0);
#else
    err = sock->ops->getname(sock, (struct sockaddr *)&local, &slen, 0);
#endif
    if (err < 0)
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
    tcp->timewait_countdown = -1;
    tcp->dead_node = false;

    for (i = 0; i < EXA_TCP_MAX_RX_SEGMENTS; i++)
        INIT_LIST_HEAD(&tcp->rx_seg[i].seg_list);

    exasock_tcp_stats_init(tcp, fd);

    kref_init(&tcp->refcount);
    sema_init(&tcp->dead_sema, 0);
    spin_lock_init(&tcp->notify.lock);

    INIT_DELAYED_WORK(&tcp->work, exasock_tcp_conn_worker);
    queue_delayed_work(tcp_workqueue, &tcp->work, TCP_TIMER_JIFFIES);

    INIT_DELAYED_WORK(&tcp->win_work, exasock_tcp_conn_win_worker);
    INIT_DELAYED_WORK(&tcp->fin_work, exasock_tcp_close_worker);
    INIT_DELAYED_WORK(&tcp->gc_work,  exasock_tcp_gc_worker);
    INIT_LIST_HEAD(&tcp->death_link);

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

    /* Invalidate duplicate ACKs trigger */
    user_page->p.tcp.dup_acks_seq = user_page->p.tcp.recv_seq - 1;

    /* Set tx consistency flag */
    user_page->p.tcp.tx_consistent = 1;

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
#ifdef __GETNAME_NO_SOCKLEN_PARAM
    err = slen = tcp->sock->ops->getname(tcp->sock, (struct sockaddr *)&sa, 0);
#else
    err = tcp->sock->ops->getname(tcp->sock, (struct sockaddr *)&sa, &slen, 0);
#endif
    if (err < 0)
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

static void exasock_tcp_dead(struct kref *ref)
{
    struct exasock_tcp *tcp = container_of(ref, struct exasock_tcp, refcount);
    up(&tcp->dead_sema);
}

/* need biglock for this one function to avoid race condition */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
static DECLARE_MUTEX(update_biglock);
#else
static DEFINE_SEMAPHORE(update_biglock);
#endif
int exasock_tcp_update(struct exasock_tcp *tcp,
                       uint32_t local_addr, uint16_t local_port,
                       uint32_t peer_addr, uint16_t peer_port)
{
    struct exasock_tcp *old;
    int err;
    BUG_ON(tcp->hdr.type != EXASOCK_TYPE_SOCKET);
    BUG_ON(tcp->hdr.socket.domain != AF_INET);
    BUG_ON(tcp->hdr.socket.type != SOCK_STREAM);

    err = down_interruptible(&update_biglock);
    if (err)
        return err;
    /* Update kernel struct with provided addresses and ports */
    tcp->local_addr = local_addr;
    tcp->local_port = local_port;
    tcp->peer_addr = peer_addr;
    tcp->peer_port = peer_port;

    /*
     * Make sure that the (saddr, daddr, sport, dport) tuple
     * is not in use, either as an active connection or is
     * in TIME_WAIT
     *
     */
    rcu_read_lock();
    old = exasock_tcp_lookup(local_addr, peer_addr,
                             local_port, peer_port);
    if (old && old != tcp)
    {
        if (old->local_addr == tcp->local_addr &&
            old->peer_addr  == tcp->peer_addr  &&
            old->local_port == tcp->local_port &&
            old->peer_port  == tcp->peer_port)
        {
            rcu_read_unlock();
            up(&update_biglock);
            return -EADDRNOTAVAIL;
        }
    }
    rcu_read_unlock();
    /* Update hash table */
    exasock_tcp_update_hashtbl(tcp);
    up(&update_biglock);

    /* Update user page */
    tcp->user_page->e.ip.local_addr = tcp->local_addr;
    tcp->user_page->e.ip.local_port = tcp->local_port;
    tcp->user_page->e.ip.peer_addr = tcp->peer_addr;
    tcp->user_page->e.ip.peer_port = tcp->peer_port;

    /* Initialize duplicate ACKs context */
    tcp->dup_acks.ack_seq = tcp->user_page->p.tcp.send_ack;
    tcp->dup_acks.win_end = tcp->user_page->p.tcp.rwnd_end;

    exasock_tcp_stats_update(tcp);
    return 0;
}

static void exasock_tcp_close_worker(struct work_struct *work)
{
    struct delayed_work *dwork = container_of(work, struct delayed_work, work);
    struct exasock_tcp *tcp = container_of(dwork, struct exasock_tcp, fin_work);

    struct exa_socket_state *sock_state = tcp->user_page;
    struct exa_tcp_state *tcp_st;
    bool   send_fin = false;

    tcp_st = &sock_state->p.tcp;
    tcp->user_closed = true;

    spin_lock(&tcp_wait_death_lock);
    list_add_rcu(&tcp->death_link, &tcp_wait_death_list);
    spin_unlock(&tcp_wait_death_lock);

    if (tcp->peer_addr == htonl(INADDR_ANY) ||
        tcp->user_page->p.tcp.state == EXA_TCP_CLOSED ||
        tcp->user_page->p.tcp.state == EXA_TCP_SYN_SENT ||
        tcp->user_page->p.tcp.state == EXA_TCP_SYN_RCVD)
    {
        exasock_tcp_free(tcp);
        return;
    }

    /*
     * if we are in close_wait, i.e. peer has closed the connection, or
     * we are in established, then send a fin packet over.
     *
     * in the case that the connection is in established state, we make
     * no distinction whether a fin is already received and queued. we
     * treat it as simultaneous close instead for simplicity.
     *
     * since all userspace processes have called close() on the socket,
     * the driver now has the only handle to the tcp connection, hence
     * the lack of compare-and-swap below
     *
     */
    if (tcp_st->state == EXA_TCP_ESTABLISHED)
    {
        tcp_st->state = EXA_TCP_FIN_WAIT_1;
        send_fin = true;
    }
    else if (tcp_st->state == EXA_TCP_CLOSE_WAIT)
    {
        tcp_st->state = EXA_TCP_LAST_ACK;
        send_fin = true;
    }

    if (send_fin)
    {
        exasock_tcp_send_segment(tcp, tcp_st->send_seq, 0, false);
    }
}

void exasock_tcp_close(struct exasock_tcp *tcp)
{
    /* don't enter fin handshake if the user app's
     * tx state is inconsistent,
     * e.g. killed in the middle of send() */
    if (likely(tcp->user_page->p.tcp.tx_consistent))
        queue_delayed_work(tcp_workqueue, &tcp->fin_work, 0);
    else
    {
        tcp->reset_on_free = true;
        exasock_tcp_free(tcp);
    }
}

/* note: this function can be run either on the main tcp_workqueue
 *       or from a user app's context */
static void exasock_tcp_free(struct exasock_tcp *tcp)
{
    struct net *net = sock_net(tcp->sock->sk);
    BUG_ON(tcp->hdr.type != EXASOCK_TYPE_SOCKET);
    BUG_ON(tcp->hdr.socket.domain != AF_INET);
    BUG_ON(tcp->hdr.socket.type != SOCK_STREAM);

    /* prevent double-free from tcp_workqueue
     * e.g. time-wait timeout immediately following recycle
     * no race condition in the check because the workqueue
     * is single threaded.
     *
     * if this function is called from user's context,
     * it will not have entered FIN handshake, therefore
     * no double free issue */

    if (tcp->dead_node)
        return;

    /* Close stats */
    exasock_stats_socket_del(&tcp->stats, EXASOCK_SOCKTYPE_TCP);

    /* Send reset packet */
    if (tcp->reset_on_free)
        exasock_tcp_send_reset(tcp);

    /* If there are still any packets pending in destination table queue,
     * it means the socket does not have a valid neighbour. These packets
     * need to be removed now. */
    exasock_dst_remove_socket(net,
                              tcp->local_addr, tcp->peer_addr,
                              tcp->local_port, tcp->peer_port);

    /* Remove from epoll notify */
    exasock_epoll_notify_del(&tcp->notify);

    /* Remove from hash table. */
    spin_lock(&tcp_bucket_lock);
    hlist_del_rcu(&tcp->hash_node);
    spin_unlock(&tcp_bucket_lock);

    tcp->dead_node = true;
    /* defer blocking operations to the GC workqueue */
    queue_delayed_work(tcp_gc_workqueue, &tcp->gc_work, 0);
}

static void exasock_tcp_gc_worker(struct work_struct *work)
{
    struct delayed_work *dwork = container_of(work, struct delayed_work, work);
    struct exasock_tcp *tcp = container_of(dwork, struct exasock_tcp, gc_work);
    int i;

    spin_lock(&tcp_wait_death_lock);
    list_del_rcu(&tcp->death_link);
    spin_unlock(&tcp_wait_death_lock);

    synchronize_rcu();

    /* Wait for refcount to go to 0 */
    kref_put(&tcp->refcount, exasock_tcp_dead);
    down(&tcp->dead_sema);

    cancel_delayed_work_sync(&tcp->work);
    cancel_delayed_work_sync(&tcp->win_work);

    /* No readers left, it is now safe to free everything */
    for (i = 0; i < EXA_TCP_MAX_RX_SEGMENTS; i++)
        exasock_tcp_seg_list_cleanup(&tcp->rx_seg[i].seg_list);

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

static inline uint16_t exasock_tcp_scale_window(uint32_t rx_space,
                                                struct exa_socket_state *state)
{
    /* Window scaling is enabled if remote host gave a non-zero window scale */
    if (state->p.tcp.wscale != 0)
        rx_space >>= EXA_TCP_WSCALE;

    return rx_space < 0xFFFF ? rx_space : 0xFFFF;
}

static uint16_t exasock_tcp_calc_window(struct exasock_tcp *tcp,
                                        uint32_t recv_seq)
{
    struct exa_socket_state *state = tcp->user_page;
    uint32_t rx_space;

    /* Calculate window size from remaining space in buffer */
    rx_space = state->rx_buffer_size - (recv_seq - state->p.tcp.read_seq);

    return exasock_tcp_scale_window(rx_space, state);
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

static void exasock_tcp_update_state(volatile struct exa_tcp_state *tcp_st,
                                     struct exasock_tcp *tcp, uint32_t seq,
                                     unsigned len, bool th_ack, bool th_fin)
{
    bool fw1_fin = false, fw1_ack = false;

    if (before(seq, tcp_st->recv_seq))
        tcp_st->ack_pending = true;
update_state:
    switch (tcp_st->state)
    {
    case EXA_TCP_ESTABLISHED:
        if (th_fin && before_eq(seq + len, tcp_st->recv_seq))
        {
            /* Remote peer has closed the connection */
            if (!TCP_STATE_CMPXCHG(tcp_st, EXA_TCP_ESTABLISHED, EXA_TCP_CLOSE_WAIT))
                goto update_state;
            tcp_st->ack_pending = true;
        }
        break;

    case EXA_TCP_FIN_WAIT_1:
        /*
         * if the passive closer is ready to close,
         * it will set both flags high
         */
        fw1_fin = (th_fin && before_eq(seq + len, tcp_st->recv_seq));
        fw1_ack = (th_ack && before(tcp_st->send_seq, tcp_st->send_ack));

        if (fw1_fin && fw1_ack)
        {
            /* Received ACK for our FIN, remote peer is also closed */
            if (!TCP_STATE_CMPXCHG(tcp_st, EXA_TCP_FIN_WAIT_1, EXA_TCP_TIME_WAIT))
                goto update_state;
            tcp_st->ack_pending = true;
        }
        else if (fw1_fin)
        {
            /* Simultaneous close */
            if (!TCP_STATE_CMPXCHG(tcp_st, EXA_TCP_FIN_WAIT_1, EXA_TCP_CLOSING))
                goto update_state;
            tcp_st->ack_pending = true;
        }
        else if (fw1_ack)
        {
            /* Received ACK for our FIN, but remote peer is not closed */
            if (!TCP_STATE_CMPXCHG(tcp_st, EXA_TCP_FIN_WAIT_1, EXA_TCP_FIN_WAIT_2))
                goto update_state;
        }
        break;

    case EXA_TCP_FIN_WAIT_2:
        if (th_fin && before_eq(seq + len, tcp_st->recv_seq))
        {
            /* Remote peer has closed the connection */
            if (!TCP_STATE_CMPXCHG(tcp_st, EXA_TCP_FIN_WAIT_2, EXA_TCP_TIME_WAIT))
                goto update_state;
            tcp_st->ack_pending = true;
        }
        break;

    case EXA_TCP_CLOSING:
        if (th_ack && before(tcp_st->send_seq, tcp_st->send_ack))
        {
            if (!TCP_STATE_CMPXCHG(tcp_st, EXA_TCP_CLOSING, EXA_TCP_TIME_WAIT))
                goto update_state;
            tcp_st->ack_pending = true;
        }
        break;

    case EXA_TCP_CLOSE_WAIT:
        if (th_fin && before_eq(seq + len, tcp_st->recv_seq))
        {
            tcp_st->ack_pending = true;
        }
        break;

    case EXA_TCP_LAST_ACK:
        if (th_ack && before(tcp_st->send_seq, tcp_st->send_ack))
        {
            if (!TCP_STATE_CMPXCHG(tcp_st, EXA_TCP_LAST_ACK, EXA_TCP_CLOSED))
                goto update_state;
        }
        break;

    case EXA_TCP_TIME_WAIT:
        if (th_fin && before_eq(seq + len, tcp_st->recv_seq))
        {
            tcp->timewait_dupfin = true;
            tcp_st->ack_pending = true;
        }
        break;
    }
}

static void exasock_tcp_rx_buffer_write(struct exa_tcp_state *tcp_st,
                                        struct exasock_tcp_rx_seg *rx_seg,
                                        char *buf1, unsigned buf1_len,
                                        char *buf2, unsigned buf2_len)
{
    struct exasock_tcp_seg_el *elem, *_elem;
    unsigned copy_len = buf1_len + buf2_len;
    unsigned len;
    int i;

    list_for_each_entry_safe(elem, _elem, &rx_seg[0].seg_list, node)
    {
        while (elem->len)
        {
            len = (buf1_len > elem->len) ? elem->len : buf1_len;
            memcpy(buf1, elem->data, len);
            elem->data += len;
            elem->len -= len;
            buf1 += len;
            buf1_len -= len;
            if (buf1_len == 0 && buf2_len)
            {
                buf1 = buf2;
                buf1_len = buf2_len;
                buf2_len = 0;
            }
        }
        list_del(&elem->node);
        dev_kfree_skb_any(elem->skb);
        kfree(elem);
    }

    /* The data segment has been locked for processing in kernel, so recv_seq
     * can be safely updated */
    tcp_st->recv_seq += copy_len;

    /* Move remaining segments to the beginning of the list */
    for (i = 1; i < EXA_TCP_MAX_RX_SEGMENTS &&
         rx_seg[i].end - rx_seg[i].begin != 0; i++)
    {
        list_splice_tail_init(&rx_seg[i].seg_list, &rx_seg[i - 1].seg_list);
        rx_seg[i - 1].begin = rx_seg[i].begin;
        rx_seg[i - 1].end = rx_seg[i].end;
    }
    rx_seg[i - 1].begin = rx_seg[i - 1].end = 0;
}

static void exasock_tcp_rx_seg_cleanup(struct exasock_tcp_rx_seg *rx_seg,
                                       uint32_t recv_seq)
{
    int i, j;

    /* Identify segments to be freed */
    for (i = 0; i < EXA_TCP_MAX_RX_SEGMENTS &&
         rx_seg[i].end - rx_seg[i].begin != 0 &&
         before_eq(rx_seg[i].end, recv_seq); i++)
        ;

    /* Partially free the first remaining segment if needed */
    if (i < EXA_TCP_MAX_RX_SEGMENTS &&
        rx_seg[i].end - rx_seg[i].begin != 0 &&
        before(rx_seg[i].begin, recv_seq))
    {
        struct exasock_tcp_seg_el *elem, *_elem;
        uint32_t elem_end = rx_seg[i].begin;

        list_for_each_entry_safe(elem, _elem, &rx_seg[i].seg_list, node)
        {
            elem_end += elem->len;
            if (before_eq(elem_end, recv_seq))
            {
                list_del(&elem->node);
                dev_kfree_skb_any(elem->skb);
                kfree(elem);
            }
            else
            {
                elem->data += elem->len - (elem_end - recv_seq);
                elem->len = elem_end - recv_seq;
                break;
            }
        }
        rx_seg[i].begin = recv_seq;
    }

    if (i > 0)
    {
        /* Release segments we do not need to keep anymore */
        for (j = 0; j < i; j++)
            exasock_tcp_seg_list_cleanup(&rx_seg[j].seg_list);

        /* Move remaining segments to the beginning of the list */
        for (j = 0; i < EXA_TCP_MAX_RX_SEGMENTS &&
             rx_seg[i].end - rx_seg[i].begin != 0; j++, i++)
        {
            list_splice_tail_init(&rx_seg[i].seg_list, &rx_seg[j].seg_list);
            rx_seg[j].begin = rx_seg[i].begin;
            rx_seg[j].end = rx_seg[i].end;
        }
        for (; j < EXA_TCP_MAX_RX_SEGMENTS &&
             rx_seg[j].end - rx_seg[j].begin != 0; j++)
        {
            rx_seg[j].begin = rx_seg[j].end = 0;
        }
    }
}

static void exasock_tcp_rx_seg_write(struct exasock_tcp_rx_seg *rx_seg,
                                     uint32_t recv_seq, char *data, unsigned len,
                                     uint32_t seq, struct exasock_tcp_seg_el *elem)
{
    unsigned skip_len;
    int i, j, k;

    if (len == 0)
        goto drop_elem;

    if (after(recv_seq, seq))
    {
        /* Packet overlaps with already acked region */
        skip_len = recv_seq - seq;
    }
    else
    {
        /* Packet does not overlap with acked region */
        skip_len = 0;
    }
    data += skip_len;
    len -= skip_len;
    seq += skip_len;

    /* Find place to insert into out of order segment list */
    for (i = 0; i < EXA_TCP_MAX_RX_SEGMENTS &&
         rx_seg[i].end - rx_seg[i].begin != 0 &&
         before(rx_seg[i].end, seq); i++)
        ;

    if (i >= EXA_TCP_MAX_RX_SEGMENTS)
    {
        /* Too many out of order segments, we will drop this one */
        goto drop_elem;
    }
    else if (rx_seg[i].end - rx_seg[i].begin == 0)
    {
        /* Insert as new segment at end of list */
        elem->data = data;
        elem->len = len;
        list_add_tail(&elem->node, &rx_seg[i].seg_list);
        rx_seg[i].begin = seq;
        rx_seg[i].end = seq + len;
    }
    else if (before(seq + len, rx_seg[i].begin))
    {
        /* Insert as separate segment
         * If there are too many segments, last segment is discarded */
        elem->data = data;
        elem->len = len;
        j = EXA_TCP_MAX_RX_SEGMENTS - 1;
        exasock_tcp_seg_list_cleanup(&rx_seg[j].seg_list);
        for (; j > i; j--)
        {
             list_splice_tail_init(&rx_seg[j - 1].seg_list, &rx_seg[j].seg_list);
             rx_seg[j].begin = rx_seg[j - 1].begin;
             rx_seg[j].end = rx_seg[j - 1].end;
        }
        list_add_tail(&elem->node, &rx_seg[i].seg_list);
        rx_seg[i].begin = seq;
        rx_seg[i].end = seq + len;
    }
    else
    {
        /* Expand current segment */
        if (before(seq, rx_seg[i].begin) && before(rx_seg[i].end, seq + len))
        {
            elem->data = data;
            elem->len = len;
            rx_seg[i].begin = seq;
            rx_seg[i].end = seq + len;
            exasock_tcp_seg_list_cleanup(&rx_seg[i].seg_list);
            list_add_tail(&elem->node, &rx_seg[i].seg_list);
        }
        else if (before(seq, rx_seg[i].begin))
        {
            elem->data = data;
            elem->len = rx_seg[i].begin - seq;
            rx_seg[i].begin = seq;
            list_add(&elem->node, &rx_seg[i].seg_list);
        }
        else if (before(rx_seg[i].end, seq + len))
        {
            elem->data = data + (rx_seg[i].end - seq);
            elem->len = len - (rx_seg[i].end - seq);
            rx_seg[i].end = seq + len;
            list_add_tail(&elem->node, &rx_seg[i].seg_list);
        }
        else
        {
            /* We already have this segment */
            goto drop_elem;
        }

        /* Merge segments into current segment */
        for (j = i + 1; j < EXA_TCP_MAX_RX_SEGMENTS &&
             rx_seg[j].end - rx_seg[j].begin != 0 &&
             before_eq(rx_seg[j].begin, rx_seg[i].end); j++)
            ;
        if (before(rx_seg[i].end, rx_seg[j - 1].end))
        {
            uint32_t elem_end = rx_seg[j - 1].begin;
            struct list_head temp_list;

            list_for_each_entry(elem, &rx_seg[j - 1].seg_list, node)
            {
                elem_end += elem->len;
                if (after(elem_end, rx_seg[i].end))
                    break;
            }
            elem->data += elem->len - (elem_end - rx_seg[i].end);
            elem->len = elem_end - rx_seg[i].end;
            list_cut_position(&temp_list, &rx_seg[j - 1].seg_list,
                              elem->node.prev);
            exasock_tcp_seg_list_cleanup(&temp_list);
            list_splice_tail_init(&rx_seg[j - 1].seg_list, &rx_seg[i].seg_list);
            rx_seg[i].end = rx_seg[j - 1].end;
        }

        if (j > i + 1)
        {
            /* Move remaining segments */
            for (k = i + 1; k < j; k++)
                exasock_tcp_seg_list_cleanup(&rx_seg[k].seg_list);
            for (k = i + 1; j < EXA_TCP_MAX_RX_SEGMENTS &&
                 rx_seg[j].end - rx_seg[j].begin != 0; j++, k++)
            {
                list_splice_tail_init(&rx_seg[j].seg_list, &rx_seg[k].seg_list);
                rx_seg[k].begin = rx_seg[j].begin;
                rx_seg[k].end = rx_seg[j].end;
            }
            for (; k < EXA_TCP_MAX_RX_SEGMENTS &&
                 rx_seg[k].end - rx_seg[k].begin != 0; k++)
                rx_seg[k].begin = rx_seg[k].end = 0;
        }
    }

    return;

drop_elem:
    dev_kfree_skb_any(elem->skb);
    kfree(elem);
}

/* Calculate total length of data which is ready to be copied to the socket's
 * receive buffer */
static unsigned exasock_tcp_data_length(struct exasock_tcp_rx_seg *rx_seg,
                                      uint32_t seq, uint32_t end_seq,
                                      uint32_t recv_seq)
{
    unsigned len;
    int i;

    if (rx_seg[0].begin == recv_seq && rx_seg[0].end - rx_seg[0].begin != 0)
    {
        /* We already have the next expected data stored locally */
        if (before(rx_seg[0].end, seq))
        {
            /* New segment is not going to be copied to the receive buffer yet */
            return rx_seg[0].end - rx_seg[0].begin;
        }
    }
    else if (after(seq, recv_seq))
    {
        /* We don't have the next expected data yet */
        return 0;
    }

    /* New segment is a part of data ready to be copied to the receive buffer */
    len = end_seq - recv_seq;

    /* Include additional data from remaining segments stored locally now good
     * to be copied to the receive buffer */
    for (i = 0; i < EXA_TCP_MAX_RX_SEGMENTS &&
         rx_seg[i].end - rx_seg[i].begin != 0 &&
         before_eq(rx_seg[i].end, end_seq); i++)
        ;
    if (i < EXA_TCP_MAX_RX_SEGMENTS &&
        rx_seg[i].end - rx_seg[i].begin != 0 &&
        before_eq(rx_seg[i].begin, end_seq))
    {
        len += rx_seg[i].end - end_seq;
    }

    return len;
}

static inline void exasock_tcp_out_of_order_update(struct exasock_tcp *tcp,
                                                   uint32_t recv_seq)
{
    if (!tcp->out_of_order.valid || tcp->out_of_order.ack_seq != recv_seq)
    {
        tcp->out_of_order.ack_seq = recv_seq;
        tcp->out_of_order.cnt = 0;
        tcp->out_of_order.acks_sent = 0;
        tcp->out_of_order.valid = true;
    }
}

static inline void exasock_tcp_send_pending_dup_acks(struct exasock_tcp *tcp)
{
    int i;

    for (i = tcp->out_of_order.acks_sent; i < EXA_TCP_FAST_RETRANS_THRESH; i++)
    {
        exasock_tcp_send_ack(tcp, true);
        tcp->out_of_order.acks_sent++;
    }
}

static inline void exasock_tcp_check_dup_acks_pending(struct exasock_tcp *tcp,
                                                 struct exa_socket_state *state)
{
    uint32_t recv_seq = state->p.tcp.recv_seq;

    exasock_tcp_out_of_order_update(tcp, recv_seq);

    /* If libexasock has processed at least three out of order segments
     * without advancing of recv_seq, we make sure at least that many duplicate
     * ACKs get generated */
    if (state->p.tcp.dup_acks_seq == recv_seq)
        exasock_tcp_send_pending_dup_acks(tcp);
}

static void exasock_tcp_process_out_of_order(struct exasock_tcp *tcp,
                                             struct exa_socket_state *state,
                                             bool out_of_order)
{
    uint32_t recv_seq = state->p.tcp.recv_seq;

    exasock_tcp_out_of_order_update(tcp, recv_seq);

    /* Send duplicate ACK if out-of-order segment has been received */
    if (out_of_order)
    {
        tcp->out_of_order.cnt++;
        if (tcp->out_of_order.cnt > tcp->out_of_order.acks_sent)
        {
            exasock_tcp_send_ack(tcp, true);
            tcp->out_of_order.acks_sent++;
        }
    }

    /* Process out of order segments seen in libexasock */
    if (state->p.tcp.dup_acks_seq == recv_seq)
        exasock_tcp_send_pending_dup_acks(tcp);
}

static int exasock_tcp_process_data(struct sk_buff *skb,
                                    struct exa_socket_state *state,
                                    struct exasock_tcp *tcp,
                                    void *rx_buffer,
                                    struct exasock_tcp_rx_seg *rx_seg,
                                    char *data, unsigned seg_len, struct tcphdr *th,
                                    bool *out_of_order, bool *new_data)
{
    struct exa_tcp_state *tcp_st = &state->p.tcp;
    volatile uint32_t *tcp_st_recv_seq = &tcp_st->recv_seq;
    uint32_t recv_seq = *tcp_st_recv_seq;
    uint32_t read_seq = tcp_st->read_seq;
    uint32_t proc_seq = tcp_st->proc_seq;
    uint32_t seg_seq = ntohl(th->seq);
    uint32_t seg_end_seq = seg_seq + seg_len;
    uint32_t copy_end_seq;
    uint32_t wrap_seq;
    uint32_t rx_buffer_mask;
    struct exasock_tcp_seg_el *elem;
    unsigned buf1_len, buf2_len;
    char *buf1, *buf2;
    unsigned copy_len;
    bool th_ack;
    bool th_fin;

    if (tcp_st->state == EXA_TCP_CLOSED ||
        tcp_st->state == EXA_TCP_SYN_SENT ||
        tcp_st->state == EXA_TCP_SYN_RCVD)
        goto skip_proc;

    /* FIXME: When we do graceful shutdown instead of closing with RST,
     *        the condition for processing RST should be updated.
     *        A reset is valid if its sequence number is in the window. */
    /* NOTE: after a FIN, the RST we receive will have seq=recv_seq + 1 */
    if (th->rst && before_eq(seg_seq, recv_seq + 1))
    {
        /* Connection reset, move to CLOSED state */
        state->error = ECONNRESET;
        tcp_st->state = EXA_TCP_CLOSED;

        /* TODO: Flush send and receive buffers */

        goto skip_proc;
    }

    /* Check for space in the socket's ring buffer */
    if (seg_end_seq - read_seq > state->rx_buffer_size)
        goto skip_proc;

proc_check:
    /* Release all data already copied to the ring buffer by the library */
    exasock_tcp_rx_seg_cleanup(rx_seg, recv_seq);

    if (after(recv_seq, seg_end_seq) ||
        (recv_seq == seg_end_seq && seg_len > 0))
    {
       /* packet does not give us any new data */
        goto skip_proc;
    }
    else if (after(seg_seq, recv_seq))
    {
        /* out of order segment */
        *out_of_order = true;
    }

    /* If the library has currently locked the segment for processing,
     * we assume the library is ahead. Kernel will defer its processing
     * just to re-check later if there was a progress in received data,
     * or just an out-of-order segment has been processed.
     * If there is any data beyond what the library is processing now,
     * we assume kernel is ahead of the user space side and will continue
     * processing all the data not locked by the library */
    if (seg_len > 0 && after_eq(proc_seq, seg_end_seq))
        return -1;

    elem = kmalloc(sizeof(*elem), GFP_KERNEL);
    if (elem == NULL)
        goto skip_proc;
    elem->skb = skb;

    if (recv_seq == proc_seq &&
        (copy_len = exasock_tcp_data_length(rx_seg, seg_seq,
                                            seg_end_seq, recv_seq)) > 0)
    {
        /* The library is not receiving any new packets for the socket at
         * the moment, so we are locking all the new data available now
         * for processing in kernel */
        copy_end_seq = recv_seq + copy_len;
        proc_seq = cmpxchg(&tcp_st->proc_seq, proc_seq, copy_end_seq);
        if (proc_seq == recv_seq)
        {
            /* Locking succeeded */
            rx_buffer_mask = state->rx_buffer_size - 1;
            wrap_seq = copy_end_seq & ~rx_buffer_mask;

            if (after(wrap_seq, recv_seq))
            {
                /* Region is wrapped */
                buf1 = rx_buffer + (recv_seq & rx_buffer_mask);
                buf1_len = wrap_seq - recv_seq;
                buf2 = rx_buffer;
                buf2_len = copy_end_seq - wrap_seq;
            }
            else
            {
                /* Region is not wrapped */
                buf1 = rx_buffer + (recv_seq & rx_buffer_mask);
                buf1_len = copy_end_seq - recv_seq;
                buf2 = NULL;
                buf2_len = 0;
            }
        }
        else
        {
            /* Locking failed - need to re-check with updated proc_seq and
             * recv_seq */
            recv_seq = *tcp_st_recv_seq;
            goto proc_check;
        }
    }
    else
    {
        copy_len = 0;
    }

    th_ack = th->ack ? true : false;
    th_fin = th->fin ? true : false;

    /* Socket buffer gets consumed by exasock_tcp_rx_seg_write()
     * so neither skb nor th should be referred beyond this point. */
    exasock_tcp_rx_seg_write(rx_seg, recv_seq, data, seg_len, seg_seq, elem);

    if (copy_len)
    {
        exasock_tcp_rx_buffer_write(tcp_st, rx_seg, buf1, buf1_len, buf2, buf2_len);
        *new_data = true;
    }

    exasock_tcp_update_state(tcp_st, tcp, seg_seq, seg_len, th_ack, th_fin);
    /* make special case to get rid of spurious dup ack */
    if (tcp_st->state == EXA_TCP_TIME_WAIT ||
        tcp_st->state == EXA_TCP_CLOSING ||
        tcp_st->state == EXA_TCP_LAST_ACK ||
        tcp_st->state == EXA_TCP_CLOSE_WAIT)
    {
        *out_of_order = false;
    }

    return 0;

skip_proc:
    dev_kfree_skb_any(skb);
    return 0;
}

static int exasock_tcp_conn_process(struct sk_buff *skb,
                                    struct exasock_tcp *tcp, struct tcphdr *th,
                                    char *data, unsigned datalen)
{
    struct exa_socket_state *state = tcp->user_page;
    uint32_t ack_seq = ntohl(th->ack_seq);
    uint8_t wscale = th->syn ? 0 : state->p.tcp.wscale;
    uint32_t win_end = ack_seq + (ntohs(th->window) << wscale);
    bool out_of_order = false, new_data = false;
    int err;

    /* time_wait recycle
     * accept SYN if isn > tcp->....->recv_seq
     */
    if (unlikely(tcp->user_closed && state->p.tcp.state == EXA_TCP_TIME_WAIT &&
                 th->syn && after(ntohl(th->seq), state->p.tcp.recv_seq)))
    {
        /*
         * put the packet back in the queue for reprocessing,
         * schedule socket for closing
         */
        exasock_tcp_free(tcp);
        return -1;
    }

    if (th->ack)
    {
        /* Duplicate ACK processing for fast retransmit */
        if (ack_seq == tcp->dup_acks.ack_seq &&
            win_end == tcp->dup_acks.win_end)
        {
            /* Duplicate ACK */
            uint32_t send_seq = state->p.tcp.send_seq;

            if (ack_seq != send_seq && datalen == 0)
                tcp->dup_acks.cnt++;
        }
        else
        {
            /* Non-duplicate ACK */
            uint32_t send_ack = state->p.tcp.send_ack;
            uint32_t rwnd_end = state->p.tcp.rwnd_end;

            /* If this packet has not been processed by user space yet, kernel
             * needs to update TCP state with new ACK and/or receiver buffer
             * space.
             */
            while (after(ack_seq, send_ack))
                send_ack = cmpxchg(&state->p.tcp.send_ack, send_ack, ack_seq);
            while (after(win_end, rwnd_end))
                rwnd_end = cmpxchg(&state->p.tcp.rwnd_end, rwnd_end, win_end);

            if (after(ack_seq, tcp->dup_acks.ack_seq))
            {
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

                tcp->dup_acks.cnt = 0;
                tcp->dup_acks.ack_seq = ack_seq;

                if (tcp->fast_retransmit)
                {
                    /* Retransmit data still missing at receivers end or leave
                     * fast retransmit state */
                    if (before(ack_seq, tcp->fast_retransmit_recover_seq))
                        exasock_tcp_retransmit(tcp, true);
                    else
                        tcp->fast_retransmit = false;
                }
            }
            if (after(win_end, tcp->dup_acks.win_end))
                tcp->dup_acks.win_end = win_end;
        }

        if (tcp->dup_acks.cnt >= EXA_TCP_FAST_RETRANS_THRESH &&
            !tcp->fast_retransmit)
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

            exasock_tcp_retransmit(tcp, true);
        }
    }

    err = exasock_tcp_process_data(skb, state, tcp, tcp->rx_buffer, tcp->rx_seg,
                                   data, datalen, th, &out_of_order, &new_data);
    if (err < 0)
        return -1; /* Segment locked, retry later */

    /* Send ACK if needed */
    if (state->p.tcp.ack_pending)
    {
        exasock_tcp_send_ack(tcp, false);
    }

    /* Send duplicate ACK if out-of-order segment received */
    exasock_tcp_process_out_of_order(tcp, state, out_of_order);

    /* Reset keep-alive timer */
    tcp->keepalive.timer = state->p.tcp.keepalive.time * TCP_TIMER_PER_SEC;
    tcp->keepalive.probe_cnt = 0;

    if (exasock_tcp_calc_window(tcp, state->p.tcp.recv_seq) == 0 &&
        tcp->win_work_on == 0)
    {
        /* The last sent window size was 0. Start monitoring to make sure
         * the peer gets updated as soon as the window space gets available
         * again. */
        tcp->win_work_on = WIN_WORK_TIMEOUT;
        queue_delayed_work(tcp_workqueue, &tcp->win_work, 1);
    }

    if (new_data)
        exasock_epoll_update(&tcp->notify);

    return 0;
}

static void exasock_tcp_req_worker(struct work_struct *work)
{
    struct exasock_tcp_req *req, *tmp;

    /* Expire old TCP connection requests */
    spin_lock(&tcp_req_lock);
    list_for_each_entry_safe(req, tmp, &tcp_req_list, list)
    {
        if (req->state == EXA_TCP_ESTABLISHED)
            continue;

        if (time_after(jiffies, req->timestamp + TCP_REQUEST_JIFFIES))
        {
            hlist_del(&req->hash_node);
            list_del(&req->list);
            kfree(req);
            continue;
        }

        /* retransmit SYN-ACK as long as connection is incomplete
         * and has not yet expired */
        if (req->synack_attempts < SYNACK_ATTEMPTS_MAX &&
            time_after(jiffies, req->timestamp +
                    TCP_SYNACK_JIFFIES))
        {
            req->timestamp = jiffies;
            ++req->synack_attempts;
            exasock_tcp_send_syn_ack(NULL, req);
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

static int exasock_tcp_req_process(struct sk_buff *skb, struct exasock_tcp *tcp,
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
    }
    else if (th->syn)
    {
        /* SYN packet */
        if (th->ack)
            goto finish_proc;

        /* New connection request received - increment counter */
        tcp->counters.s.listen.reqs_rcvd++;

        /* Create new connection */
        req = kzalloc(sizeof(*req), GFP_KERNEL);
        if (req == NULL)
            goto finish_proc;

        req->timestamp = jiffies;
        req->synack_attempts = 1;

        req->local_addr = iph->daddr;
        req->peer_addr = iph->saddr;
        req->local_port = th->dest;
        req->peer_port = th->source;
        req->local_seq = exasock_tcp_req_get_isn(req);

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
        exasock_tcp_send_syn_ack(tcp, req);

        /* Insert into hash table and lists */
        hash = exasock_tcp_hash(req->local_addr, req->peer_addr,
                                req->local_port, req->peer_port);
        spin_lock(&tcp_req_lock);
        hlist_add_head(&req->hash_node, &tcp_req_buckets[hash]);
        list_add(&req->list, &tcp_req_list);
        spin_unlock(&tcp_req_lock);
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
            goto finish_proc;
        }

        /* accept final ack if the sequence is correct and
         * 1. we've just sent syn-ack
         * 2. connection is already established - this can happen if the
         *    accepted queue was full when the first ack was received */
        if ((req->state != EXA_TCP_SYN_RCVD &&
             req->state != EXA_TCP_ESTABLISHED)  ||
            req->local_seq != ntohl(th->ack_seq) ||
            req->peer_seq != ntohl(th->seq))
        {
            /* Sequence numbers don't match */
            spin_unlock(&tcp_req_lock);
            goto finish_proc;
        }

        req->state = EXA_TCP_ESTABLISHED;

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
            goto finish_proc;
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

        exasock_epoll_update(&tcp->notify);

        /* Remove from incomplete connections */
        hlist_del(&req->hash_node);
        list_del(&req->list);
        kfree(req);

        /* New connection established - increment counter */
        tcp->counters.s.listen.reqs_estab++;

        spin_unlock(&tcp_req_lock);
    }

finish_proc:
    dev_kfree_skb_any(skb);
    return 0;
}

static bool exasock_tcp_process_packet(struct sk_buff *skb)
{
    struct exasock_tcp *tcp;
    struct iphdr *iph;
    struct tcphdr *th;
    char *payload = skb->data;
    unsigned len = skb->len;
    char *data;
    uint8_t *tcpopt;
    unsigned tcplen, tcpoptlen, datalen;
    int ret;

    if (skb->protocol == htons(ETH_P_8021Q))
    {
        if (unlikely(len < sizeof(struct vlan_hdr)))
            goto drop_packet;
        payload += sizeof(struct vlan_hdr);
        len -= sizeof(struct vlan_hdr);
    }

    iph = (struct iphdr *)payload;

    /* Length sanity checks */
    if (unlikely(len < sizeof(struct iphdr) ||
                 len < (iph->ihl * 4 + sizeof(struct tcphdr)) ||
                 len < ntohs(iph->tot_len)))
        goto drop_packet;

    /* IPv4 only */
    if (unlikely (iph->version != 4))
        goto drop_packet;

    /* Drop IP fragments */
    if (iph->frag_off & htons(IP_MF | IP_OFFSET))
        goto drop_packet;

    th = (struct tcphdr *)(payload + iph->ihl * 4);
    tcplen = ntohs(iph->tot_len) - (iph->ihl * 4);

    /* Discard packet if checksums are invalid */
    if (ip_fast_csum(iph, iph->ihl))
        goto drop_packet;
    if (csum_tcpudp_magic(iph->saddr, iph->daddr, tcplen, IPPROTO_TCP,
                          csum_partial(th, tcplen, 0)))
        goto drop_packet;

    /* Look up socket */
    rcu_read_lock();
    tcp = exasock_tcp_lookup(iph->daddr, iph->saddr, th->dest, th->source);
    if (tcp == NULL)
    {
        rcu_read_unlock();
        goto drop_packet;
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
        ret = exasock_tcp_req_process(skb, tcp, iph, th, tcpopt, tcpoptlen);
    else
        ret = exasock_tcp_conn_process(skb, tcp, th, data, datalen);

    kref_put(&tcp->refcount, exasock_tcp_dead);

    return ret == 0;

drop_packet:
    dev_kfree_skb_any(skb);
    return true;
}

static void exasock_tcp_rx_worker(struct work_struct *work)
{
    struct sk_buff *skb;
    struct sk_buff_head tmp_queue;
    unsigned long irqflags;

    skb_queue_head_init(&tmp_queue);

    while ((skb = skb_dequeue_tail(&tcp_packets)) != NULL)
    {
        /* Re-queue packet if exasock_tcp_process_packet() returns false */
        if (!exasock_tcp_process_packet(skb))
            skb_queue_head(&tmp_queue, skb);
    }

    /* Add a delay before running worker again */
    if (!skb_queue_empty(&tmp_queue))
    {
        queue_delayed_work(tcp_workqueue, &tcp_rx_work, 1);
    }

    spin_lock_irqsave(&tcp_packets.lock, irqflags);
    skb_queue_splice(&tmp_queue, &tcp_packets);
    spin_unlock_irqrestore(&tcp_packets.lock, irqflags);
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

    if (tcp_state != EXA_TCP_TIME_WAIT)
        tcp->timewait_countdown = -1;

    /* reset timewait counter if our last ack was lost */
    if (tcp->timewait_dupfin == true)
    {
        tcp->timewait_dupfin = false;
        tcp->timewait_countdown = TIMEWAIT_TIMEOUT;
    }
    else if (tcp->timewait_countdown > 0)
        tcp->timewait_countdown--;
    else if (tcp_state == EXA_TCP_TIME_WAIT)
        tcp->timewait_countdown = TIMEWAIT_TIMEOUT;

    tcp->last_ack_counter++;

    if (tcp_state == EXA_TCP_CLOSED || tcp_state == EXA_TCP_LISTEN ||
        tcp_state == EXA_TCP_TIME_WAIT)
    {
        /* No retransmissions in these states */
        tcp->retransmit_countdown = -1;
    }
    else if (tcp_state == EXA_TCP_SYN_RCVD || tcp_state == EXA_TCP_SYN_SENT ||
             tcp_state == EXA_TCP_FIN_WAIT_1 || tcp_state == EXA_TCP_LAST_ACK ||
             tcp_state == EXA_TCP_CLOSING)
    {
        /* ACKs are pending from the remote host */
        if (tcp->retransmit_countdown == -1)
        {
            tcp->retransmit_countdown = RETRANSMIT_TIMEOUT;
        }
    }
     /*
     * Note: after transmitting all payload bytes, send_seq stops
     *       updating, but send_ack continues to update
     *
     * With that in mind, the ugly boolean expression below says:
     *
     * if send_ack equals send_seq when we are sending payload,
     * or send_ack == send_seq + 1 when we have received an ack
     * in FIN handshake, then no acks are pending; otherwise...
     */
    else if (!(tcp_state == EXA_TCP_ESTABLISHED && send_ack == send_seq) &&
             !(tcp_state == EXA_TCP_FIN_WAIT_2 && send_ack == send_seq + 1))
    {
        /* ACKs are pending from the remote host, reset retransmit countdown
         * if it is not set, or if progress has been made */
        if (tcp->retransmit_countdown == -1 ||
            tcp->last_send_ack != send_ack)
        {
            tcp->retransmit_countdown = RETRANSMIT_TIMEOUT;
        }

        /* By getting into this if clause, we have outstanding un-ACKed
         * data. So, if tcp->last_send_ack == send_ack, then we haven't seen
         * ACK progress despite having data. We've already moved the "last ack
         * counter" forward, so check that the timeout has been reached. */
        if (state->p.tcp.user_timeout_ms != 0
            && tcp->last_send_ack == send_ack
            && (tcp->last_ack_counter * 1000 / TCP_TIMER_PER_SEC
                >= state->p.tcp.user_timeout_ms))
        {
            state->error = ETIMEDOUT;
            state->p.tcp.state = EXA_TCP_CLOSED;
        }
    }
    else
    {
        /* No ACKs pending, disable timeouts */
        tcp->retransmit_countdown = -1;
        tcp->last_ack_counter = 0;
    }

    if (tcp->retransmit_countdown == 0)
    {
        /* ACK timeout */
        tcp->retransmit_countdown = -1;
        state->p.tcp.cwnd = EXA_TCP_MSS;
        exasock_tcp_retransmit(tcp, false);
    }
    else if (state->p.tcp.ack_pending)
    {
        exasock_tcp_send_ack(tcp, false);
    }

    if (tcp->timewait_countdown == 0)
    {
        state->p.tcp.state = EXA_TCP_CLOSED;
    }

    exasock_tcp_check_dup_acks_pending(tcp, state);

    if (state->p.tcp.ss_after_idle &&
        send_ack == send_seq &&
        tcp->last_send_seq == send_seq)
    {
        /* Connection is idle, returns congestion control to slow-start state */
        state->p.tcp.cwnd = 3 * EXA_TCP_MSS;
    }

    tcp->last_send_ack = send_ack;
    tcp->last_send_seq = send_seq;

    /* Check if window update monitoring has expired */
    if (tcp->win_work_on > 0)
    {
        tcp->win_work_on--;
        if (tcp->win_work_on == 0)
            cancel_delayed_work_sync(&tcp->win_work);
    }

    if ((tcp_state != EXA_TCP_CLOSED) && (tcp_state != EXA_TCP_LISTEN) &&
        (tcp_state != EXA_TCP_SYN_SENT) && (tcp_state != EXA_TCP_SYN_RCVD) &&
        (tcp_state != EXA_TCP_TIME_WAIT))
    {
        /* Check keep-alive counters */
        if (tcp->keepalive.timer > 0)
        {
            tcp->keepalive.timer--;
            if (tcp->keepalive.timer == 0)
            {
                if (tcp->keepalive.probe_cnt < state->p.tcp.keepalive.probes)
                {
                    /* Send keep-alive probe */
                    exasock_tcp_send_probe(tcp);
                    tcp->keepalive.probe_cnt++;
                    tcp->keepalive.timer = state->p.tcp.keepalive.intvl *
                                           TCP_TIMER_PER_SEC;
                }
                else
                {
                    /* Connection timed out, move to CLOSED state */
                    state->error = ETIMEDOUT;
                    state->p.tcp.state = EXA_TCP_CLOSED;

                    /* TODO: Flush send and receive buffers */
                }
            }
        }

        /* Update stats */
        exasock_tcp_counters_update(&tcp->counters, &state->p.tcp);
    }

    /*
     * if connection is shut down and user has called close(),
     * then schedule the close worker to run again to perform cleanup
     */
    if (tcp->user_page->p.tcp.state == EXA_TCP_CLOSED &&
        tcp->user_closed)
        exasock_tcp_free(tcp);
    else if (!module_removed)
        queue_delayed_work(tcp_workqueue, &tcp->work, TCP_TIMER_JIFFIES);

    kref_put(&tcp->refcount, exasock_tcp_dead);
}

static void exasock_tcp_conn_win_worker(struct work_struct *work)
{
    struct exasock_tcp *tcp = container_of(work, struct exasock_tcp,
                                           win_work.work);
    struct exa_socket_state *state = tcp->user_page;

    rcu_read_lock();
    if (tcp->dead_node)
    {
        /* This exasock_tcp struct is being deleted */
        rcu_read_unlock();
        return;
    }
    kref_get(&tcp->refcount);
    rcu_read_unlock();

    /* If there was window space update, ack_pending has been set */
    if (state->p.tcp.ack_pending)
        exasock_tcp_send_ack(tcp, false);

    /* Continue monitoring only if there is still no space in the window */
    if (exasock_tcp_calc_window(tcp, state->p.tcp.recv_seq) > 0)
        tcp->win_work_on = 0;
    else if (!module_removed)
        queue_delayed_work(tcp_workqueue, &tcp->win_work, 1);

    kref_put(&tcp->refcount, exasock_tcp_dead);
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

static void exasock_tcp_send_segment(struct exasock_tcp *tcp, uint32_t seq,
                                     uint32_t len, bool dup)
{
    struct exa_socket_state *state = tcp->user_page;
    struct net *net = sock_net(tcp->sock->sk);
    struct sk_buff *skb;
    struct tcphdr *th;
    uint8_t tcp_state;
    uint32_t send_seq, recv_seq;
    uint16_t window;
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
        data_allowed = true;
        break;

    case EXA_TCP_CLOSING:
        /*
         * send ack for remote fin
         * or retransmit fin
         */
        th->seq = htonl(seq);
        if (send_seq == seq)
            th->fin = 1;
        th->ack_seq = htonl(recv_seq + 1);
        th->ack = 1;
        data_allowed = true;
        break;

    case EXA_TCP_LAST_ACK:
        /* Send FIN */
        th->seq = htonl(seq);
        th->ack_seq = htonl(recv_seq + 1);
        if (send_seq == seq)
            th->fin = 1;
        th->ack = 1;
        data_allowed = true;
        break;

    case EXA_TCP_TIME_WAIT:
        /* Send ACK for remote FIN */
        th->seq = htonl(seq);
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

    if (dup)
    {
        window = exasock_tcp_scale_window(
                                        get_last_win_end(tcp, state) - recv_seq,
                                        state);
    }
    else
    {
        uint32_t adv_wnd_end = state->p.tcp.adv_wnd_end;

        window = exasock_tcp_calc_window(tcp, recv_seq);
        tcp->adv_win.end = recv_seq +
                        (window << (state->p.tcp.wscale ? EXA_TCP_WSCALE : 0));
        tcp->adv_win.valid = true;

        /* Prevent libexasock's adv_wnd_end from being left too far behind if
         * no data gets sent to the peer for a long time */
        while (tcp->adv_win.end - adv_wnd_end > 0x3FFFFFFF)
            adv_wnd_end = cmpxchg(&state->p.tcp.adv_wnd_end, adv_wnd_end,
                                  tcp->adv_win.end);
    }
    th->window = htons(window);

    if (data_allowed && len > 0)
    {
        char *data = skb_put(skb, len);
        if (exasock_tcp_tx_buffer_get(tcp, data, seq, len) == -1)
            goto abort_packet;
    }

    th->check = csum_tcpudp_magic(tcp->peer_addr, tcp->local_addr, skb->len,
                                  IPPROTO_TCP, csum_partial(th, skb->len, 0));

    exasock_ip_send(net, IPPROTO_TCP, tcp->peer_addr, tcp->local_addr, skb);
    return;

abort_packet:
    kfree_skb(skb);
}

/* Retransmit one MSS of data not acknowledged yet */
static void exasock_tcp_retransmit(struct exasock_tcp *tcp, bool fast_retrans)
{
    struct exa_socket_state *state = tcp->user_page;
    uint32_t send_ack = state->p.tcp.send_ack;
    uint32_t send_seq = state->p.tcp.send_seq;
    uint32_t rmss = state->p.tcp.rmss;
    uint8_t tcp_state = state->p.tcp.state;
    uint32_t len;

    bool fin_retransmit = (send_ack == send_seq) &&
        (tcp_state == EXA_TCP_FIN_WAIT_1 || tcp_state == EXA_TCP_LAST_ACK ||
         tcp_state == EXA_TCP_CLOSING);

    if (tcp_state == EXA_TCP_SYN_RCVD || tcp_state == EXA_TCP_SYN_SENT)
    {
        /* Data retransmissions are only allowed in a synchronised state */
        len = 0;
    }
    else if (fin_retransmit)
    {
        len = 0;
    }
    else
    {
        len = send_seq - send_ack;

        if (len == 0)
            return;

        if (len > EXA_TCP_MSS)
            len = EXA_TCP_MSS;

        if (len > rmss)
            len = rmss;
    }

    /* No need to lock counters as long as updated from the single-thread
     * workqueue only */
    tcp->counters.s.conn.retrans_bytes += len;
    if (fast_retrans)
        tcp->counters.s.conn.retrans_segs_fast++;
    else
        tcp->counters.s.conn.retrans_segs_to++;

    exasock_tcp_send_segment(tcp, send_ack, len, false);
}

static void exasock_tcp_send_ack(struct exasock_tcp *tcp, bool dup)
{
    struct exa_socket_state *state = tcp->user_page;
    uint32_t seq = state->p.tcp.send_seq;
    if (state->p.tcp.state == EXA_TCP_TIME_WAIT ||
        state->p.tcp.state == EXA_TCP_CLOSING)
    {
        seq++;
    }
    exasock_tcp_send_segment(tcp, seq, 0, dup);
}

static void exasock_tcp_send_reset(struct exasock_tcp *tcp)
{
    struct exa_socket_state *state = tcp->user_page;
    struct net *net = sock_net(tcp->sock->sk);
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

    exasock_ip_send(net, IPPROTO_TCP, tcp->peer_addr, tcp->local_addr, skb);
    return;

abort_packet:
    kfree_skb(skb);
}

static void exasock_tcp_send_syn_ack(struct exasock_tcp *tcp, struct exasock_tcp_req *req)
{
    struct net *net = tcp != NULL ? sock_net(tcp->sock->sk) : NULL;
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
    th->window = htons(EXA_TCP_SYNACK_WIN); /* Smaller than the real window size */
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

    exasock_ip_send(net, IPPROTO_TCP, req->peer_addr, req->local_addr, skb);
}

static void exasock_tcp_send_probe(struct exasock_tcp *tcp)
{
    struct exa_socket_state *state = tcp->user_page;

    exasock_tcp_send_segment(tcp, state->p.tcp.send_ack - 1, 0, false);
}

int exasock_tcp_epoll_add(struct exasock_tcp *tcp, struct exasock_epoll *epoll,
                          int fd)
{
    return exasock_epoll_notify_add(epoll, &tcp->notify, fd);
}

int exasock_tcp_epoll_del(struct exasock_tcp *tcp, struct exasock_epoll *epoll)
{
    return exasock_epoll_notify_del_check(epoll, &tcp->notify);
}

int exasock_tcp_setsockopt(struct exasock_tcp *tcp, int level, int optname,
                           char __user *optval, unsigned int optlen)
{
    int ret;

    BUG_ON(tcp->hdr.type != EXASOCK_TYPE_SOCKET);
    BUG_ON(tcp->hdr.socket.domain != AF_INET);
    BUG_ON(tcp->hdr.socket.type != SOCK_STREAM);

    if (level == SOL_SOCKET)
        ret = sock_setsockopt(tcp->sock, level, optname, optval, optlen);
    else
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
    int err = 0;
    tcp_buckets = kzalloc(NUM_BUCKETS * sizeof(*tcp_buckets), GFP_KERNEL);
    if (tcp_buckets == NULL)
    {
        err = -ENOMEM;
        goto tcp_buckets_null;
    }

    tcp_req_buckets = kzalloc(NUM_BUCKETS * sizeof(*tcp_req_buckets), GFP_KERNEL);
    if (tcp_req_buckets == NULL)
    {
        err = -ENOMEM;
        goto req_buckets_null;
    }

    skb_queue_head_init(&tcp_packets);
    tcp_workqueue = create_singlethread_workqueue("exasock_tcp");
    if (tcp_workqueue == NULL)
    {
        err = -ENOMEM;
        goto main_wq_null;
    }

    tcp_gc_workqueue = create_workqueue("exasock_tcp_gc");
    if (tcp_gc_workqueue == NULL)
    {
        err = -ENOMEM;
        goto gc_wq_null;
    }

    INIT_DELAYED_WORK(&tcp_rx_work, exasock_tcp_rx_worker);
    INIT_DELAYED_WORK(&tcp_req_work, exasock_tcp_req_worker);
    queue_delayed_work(tcp_workqueue, &tcp_req_work, TCP_TIMER_JIFFIES);
    err = exanic_netdev_intercept_add(&exasock_tcp_intercept);
    if (err)
        goto intercept_failed;

    return 0;

intercept_failed:
    cancel_delayed_work(&tcp_req_work);
    destroy_workqueue(tcp_gc_workqueue);
gc_wq_null:
    destroy_workqueue(tcp_workqueue);
main_wq_null:
    kfree(tcp_req_buckets);
req_buckets_null:
    kfree(tcp_buckets);
tcp_buckets_null:
    return err;
}

void exasock_tcp_exit(void)
{
    exanic_netdev_intercept_remove(&exasock_tcp_intercept);
    cancel_delayed_work_sync(&tcp_req_work);
    flush_workqueue(tcp_workqueue);
    exasock_tcp_kill_stray();
    destroy_workqueue(tcp_workqueue);
    skb_queue_purge(&tcp_packets);
    kfree(tcp_req_buckets);
    kfree(tcp_buckets);
}
