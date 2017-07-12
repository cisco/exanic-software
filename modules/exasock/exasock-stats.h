/**
 * Kernel support for the ExaSock library
 * Copyright (C) 2011-2017 Exablaze Pty Ltd and its licensors
 */

#include <linux/version.h>
#include <linux/sched.h>

enum exasock_socktype
{
    EXASOCK_SOCKTYPE_TCP,
    EXASOCK_SOCKTYPE_UDP,
    EXASOCK_SOCKTYPE_UDP_CONN,

    __EXASOCK_SOCKTYPE_MAX,
};
#define EXASOCK_SOCKTYPE_MAX (__EXASOCK_SOCKTYPE_MAX - 1)

struct exasock_stats_sock_snapshot_brf
{
    uint32_t recv_q;
    uint32_t send_q;
};

struct exasock_stats_sock_snapshot_intconn
{
    uint64_t tx_bytes;
    uint64_t tx_acked_bytes;
    uint64_t rx_bytes;
    uint64_t rx_deliv_bytes;

    uint32_t retrans_segs_fast;
    uint32_t retrans_segs_to;
    uint32_t retrans_bytes;

    uint8_t wscale_peer;
    uint8_t wscale_local;
    uint32_t window_peer;
    uint32_t window_local;

    uint16_t mss_peer;
    uint16_t mss_local;
    uint32_t cwnd;
    uint32_t ssthresh;
};

struct exasock_stats_sock_snapshot_intlis
{
    uint32_t    reqs_rcvd;
    uint32_t    reqs_estab;
};

enum exasock_stats_sock_snapshotint_contents
{
    EXASOCK_STATS_SOCK_SSINT_NONE,
    EXASOCK_STATS_SOCK_SSINT_CONN,
    EXASOCK_STATS_SOCK_SSINT_LISTEN,
};

struct exasock_stats_sock_snapshot_int
{
    enum exasock_stats_sock_snapshotint_contents contents;
    union
    {
        struct exasock_stats_sock_snapshot_intconn conn;
        struct exasock_stats_sock_snapshot_intlis listen;
    } c;
};

struct exasock_stats_sock_addr
{
    uint32_t local_ip;
    uint32_t peer_ip;
    uint16_t local_port;
    uint16_t peer_port;
};

struct exasock_stats_sock_info
{
    pid_t pid;
    char prog_name[TASK_COMM_LEN];
    int fd;
    uid_t uid;
};

struct exasock_stats_sock;

struct exasock_stats_sock_ops
{
    uint8_t (*get_state)(struct exasock_stats_sock *sk_stats);
    void    (*get_snapshot)(struct exasock_stats_sock *sk_stats,
                            struct exasock_stats_sock_snapshot_brf *ssbrf,
                            struct exasock_stats_sock_snapshot_int *ssint);
};

struct exasock_stats_sock
{
    struct exasock_stats_sock_addr addr;
    struct exasock_stats_sock_info info;
    struct exasock_stats_sock_ops  ops;
    struct list_head               node;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
#define exasock_current_uid()  from_kuid(current_user_ns(), current_uid())
#else
#define exasock_current_uid()  current_uid()
#endif

int __init exasock_stats_init(void);
void exasock_stats_exit(void);
void exasock_stats_socket_add(enum exasock_socktype type,
                              struct exasock_stats_sock *sk_stats);
void exasock_stats_socket_update(struct exasock_stats_sock *sk_stats,
                                 enum exasock_socktype prev_type,
                                 enum exasock_socktype type,
                                 struct exasock_stats_sock_addr *addr);
void exasock_stats_socket_del(struct exasock_stats_sock *sk_stats,
                              enum exasock_socktype type);
