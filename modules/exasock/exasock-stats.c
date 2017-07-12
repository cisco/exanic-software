/**
 * Kernel support for the ExaSock library
 * Copyright (C) 2011-2017 Exablaze Pty Ltd and its licensors
 */

#include <linux/version.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <net/genetlink.h>
#include <net/netlink.h>

#include "../../libs/exasock/kernel/structs.h"

#include "exasock-stats.h"
#include "exasock-genl.h"

#ifndef GENLMSG_DEFAULT_SIZE
#define GENLMSG_DEFAULT_SIZE (NLMSG_DEFAULT_SIZE - GENL_HDRLEN)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
static int exasock_genl_register_family(struct genl_family *family,
                                        struct genl_ops *ops, int size)
{
    int err;
    int i;

    err = genl_register_family(family);
    if (err)
        return err;
    for (i = 0; i < size; i++)
    {
        err = genl_register_ops(family, &ops[i]);
        if (err)
        {
            genl_unregister_family(family);
            break;
        }
    }
    return 0;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
    #define exasock_genl_register_family(family, ops, size) \
        genl_register_family(family)
    #define __HAS_STATIC_GENL_INIT
    #define __HAS_NO_STATIC_GENL_ID
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)) && \
       !defined(genl_register_family_with_ops)
    #define exasock_genl_register_family(family, ops, size) \
        genl_register_family_with_ops(family, ops, size)
#else
    #define exasock_genl_register_family(family, ops, size) \
        genl_register_family_with_ops(family, ops)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#define genl_info_snd_portid(info)  info->snd_portid
#else
#define genl_info_snd_portid(info)  info->snd_pid
#endif

struct exasock_stats_sock_list
{
    struct list_head    list;
    struct mutex        lock;
};

struct exasock_stats
{
    struct exasock_stats_sock_list tcp;
    struct exasock_stats_sock_list udp;
    struct exasock_stats_sock_list udp_conn;
};

static struct exasock_stats exa_stats;

static inline struct exasock_stats_sock_list *get_stats_sock_list(
                                                    enum exasock_socktype type)
{
    switch (type)
    {
    case EXASOCK_SOCKTYPE_TCP:
        return &exa_stats.tcp;
    case EXASOCK_SOCKTYPE_UDP:
        return &exa_stats.udp;
    case EXASOCK_SOCKTYPE_UDP_CONN:
        return &exa_stats.udp_conn;
    default:
        return NULL;
    }
}

static inline enum exasock_socktype genl_sock_type_to_socktype(
                                            enum exasock_genl_sock_type type)
{
    switch (type)
    {
    case EXASOCK_GENL_SOCKTYPE_TCP_LISTEN:
    case EXASOCK_GENL_SOCKTYPE_TCP_CONN:
        return EXASOCK_SOCKTYPE_TCP;
    case EXASOCK_GENL_SOCKTYPE_UDP_LISTEN:
        return EXASOCK_SOCKTYPE_UDP;
    case EXASOCK_GENL_SOCKTYPE_UDP_CONN:
        return EXASOCK_SOCKTYPE_UDP_CONN;
    default:
        return -1;
    }
}

static inline enum exasock_genl_conn_state tcp_state_to_genl_connstate(
                                                                    int state)
{
    switch (state)
    {
    case EXA_TCP_CLOSED:
        return EXASOCK_GENL_CONNSTATE_CLOSED;
    case EXA_TCP_LISTEN:
        return EXASOCK_GENL_CONNSTATE_LISTEN;
    case EXA_TCP_SYN_SENT:
        return EXASOCK_GENL_CONNSTATE_SENT;
    case EXA_TCP_SYN_RCVD:
        return EXASOCK_GENL_CONNSTATE_RCVD;
    case EXA_TCP_ESTABLISHED:
        return EXASOCK_GENL_CONNSTATE_ESTABLISHED;
    case EXA_TCP_CLOSE_WAIT:
        return EXASOCK_GENL_CONNSTATE_CLOSE_WAIT;
    case EXA_TCP_FIN_WAIT_1:
        return EXASOCK_GENL_CONNSTATE_FIN_WAIT_1;
    case EXA_TCP_FIN_WAIT_2:
        return EXASOCK_GENL_CONNSTATE_FIN_WAIT_2;
    case EXA_TCP_CLOSING:
        return EXASOCK_GENL_CONNSTATE_CLOSING;
    case EXA_TCP_LAST_ACK:
        return EXASOCK_GENL_CONNSTATE_LAST_ACK;
    case EXA_TCP_TIME_WAIT:
        return EXASOCK_GENL_CONNSTATE_TIME_WAIT;
    default:
        return EXASOCK_GENL_CONNSTATE_NONE;
    }
}

static inline uint8_t get_sock_state(struct exasock_stats_sock *sk_stats)
{
    if (sk_stats->ops.get_state == NULL)
        return EXASOCK_GENL_CONNSTATE_NONE;
    else
        return tcp_state_to_genl_connstate(sk_stats->ops.get_state(sk_stats));
}

/**************************************
 * Generic Netlink API
 **************************************/

static struct genl_family exasock_genl_family;

/* Attribute policy */

static const struct nla_policy exasock_genl_policy[EXASOCK_GENL_A_MAX + 1] =
{
    [EXASOCK_GENL_A_UNSPEC]         = { .type = NLA_UNSPEC },
    [EXASOCK_GENL_A_SOCK_TYPE]      = { .type = NLA_U8 },
    [EXASOCK_GENL_A_SOCK_EXTENDED]  = { .type = NLA_FLAG },
    [EXASOCK_GENL_A_SOCK_INTERNAL]  = { .type = NLA_FLAG },
    [EXASOCK_GENL_A_LIST_SOCK]      = { .type = NLA_NESTED },
};

static inline int exasock_genl_msg_set_sockelem_intconn(struct sk_buff *msg,
                                 struct exasock_stats_sock_snapshot_intconn *ss)
{
    struct nlattr *attr;

    attr = nla_nest_start(msg, EXASOCK_GENL_A_SKINFO_INTERN_CONN);
    if (attr == NULL)
        return -EMSGSIZE;

    if (nla_put_u64_64bit(msg, EXASOCK_GENL_A_SKINFOINTC_TX_BYTES,
                          ss->tx_bytes, EXASOCK_GENL_A_SKINFOINTC_PAD))
        goto err_nla_put;
    if (nla_put_u64_64bit(msg, EXASOCK_GENL_A_SKINFOINTC_TX_ACK_BYTES,
                          ss->tx_acked_bytes, EXASOCK_GENL_A_SKINFOINTC_PAD))
        goto err_nla_put;
    if (nla_put_u64_64bit(msg, EXASOCK_GENL_A_SKINFOINTC_RX_BYTES,
                          ss->rx_bytes, EXASOCK_GENL_A_SKINFOINTC_PAD))
        goto err_nla_put;
    if (nla_put_u64_64bit(msg, EXASOCK_GENL_A_SKINFOINTC_RX_DLVR_BYTES,
                          ss->rx_deliv_bytes, EXASOCK_GENL_A_SKINFOINTC_PAD))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFOINTC_RETRANS_SEGS_FAST,
                    ss->retrans_segs_fast))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFOINTC_RETRANS_SEGS_TO,
                    ss->retrans_segs_to))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFOINTC_RETRANS_BYTES,
                    ss->retrans_bytes))
        goto err_nla_put;
    if (nla_put_u8(msg, EXASOCK_GENL_A_SKINFOINTC_PEER_WSCALE,
                   ss->wscale_peer))
        goto err_nla_put;
    if (nla_put_u8(msg, EXASOCK_GENL_A_SKINFOINTC_LOCAL_WSCALE,
                   ss->wscale_local))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFOINTC_PEER_WIN,
                    ss->window_peer))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFOINTC_LOCAL_WIN,
                    ss->window_local))
        goto err_nla_put;
    if (nla_put_u16(msg, EXASOCK_GENL_A_SKINFOINTC_PEER_MSS,
                    ss->mss_peer))
        goto err_nla_put;
    if (nla_put_u16(msg, EXASOCK_GENL_A_SKINFOINTC_LOCAL_MSS,
                    ss->mss_local))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFOINTC_CWND,
                    ss->cwnd))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFOINTC_SSTHRESH,
                    ss->ssthresh))
        goto err_nla_put;

    nla_nest_end(msg, attr);

    return 0;

err_nla_put:
    nla_nest_cancel(msg, attr);
    return -EMSGSIZE;
}

static inline int exasock_genl_msg_set_sockelem_intlis(struct sk_buff *msg,
                                  struct exasock_stats_sock_snapshot_intlis *ss)
{
    struct nlattr *attr;

    attr = nla_nest_start(msg, EXASOCK_GENL_A_SKINFO_INTERN_LISTEN);
    if (attr == NULL)
        return -EMSGSIZE;

    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFOINTL_REQS_RCV,
                    ss->reqs_rcvd))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFOINTL_REQS_ESTAB,
                    ss->reqs_estab))
        goto err_nla_put;

    nla_nest_end(msg, attr);

    return 0;

err_nla_put:
    nla_nest_cancel(msg, attr);
    return -EMSGSIZE;
}

static inline int exasock_genl_msg_set_sockelem_extend(struct sk_buff *msg,
                                          struct exasock_stats_sock *sk_stats)
{
    struct nlattr *attr;

    attr = nla_nest_start(msg, EXASOCK_GENL_A_SKINFO_EXTENDED);
    if (attr == NULL)
        return -EMSGSIZE;

    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFOEXT_UID,
                    sk_stats->info.uid))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFOEXT_PID,
                    sk_stats->info.pid))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFOEXT_FD,
                    sk_stats->info.fd))
        goto err_nla_put;
    if (nla_put_string(msg, EXASOCK_GENL_A_SKINFOEXT_PROG,
                    sk_stats->info.prog_name))
        goto err_nla_put;

    nla_nest_end(msg, attr);

    return 0;

err_nla_put:
    nla_nest_cancel(msg, attr);
    return -EMSGSIZE;
}

static inline int exasock_genl_msg_set_sockelem(struct sk_buff *msg,
                                          struct exasock_stats_sock *sk_stats,
                                          uint8_t state, bool extended,
                                          bool internal)
{
    struct nlattr *attr;
    struct exasock_stats_sock_snapshot_brf ssbrf;
    union exasock_stats_sock_snapshot_int ssint;
    int err = -EMSGSIZE;

    sk_stats->ops.get_snapshot(sk_stats, &ssbrf,
                               internal ? &ssint : NULL);

    attr = nla_nest_start(msg, EXASOCK_GENL_A_ELEM_SOCK);
    if (attr == NULL)
        return -EMSGSIZE;

    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFO_LOCAL_ADDR,
                    sk_stats->addr.local_ip))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFO_PEER_ADDR,
                    sk_stats->addr.peer_ip))
        goto err_nla_put;
    if (nla_put_u16(msg, EXASOCK_GENL_A_SKINFO_LOCAL_PORT,
                    sk_stats->addr.local_port))
        goto err_nla_put;
    if (nla_put_u16(msg, EXASOCK_GENL_A_SKINFO_PEER_PORT,
                    sk_stats->addr.peer_port))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFO_RECV_Q, ssbrf.recv_q))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SKINFO_SEND_Q, ssbrf.send_q))
        goto err_nla_put;
    if (nla_put_u8(msg, EXASOCK_GENL_A_SKINFO_STATE, state))
        goto err_nla_put;

    if (extended)
    {
        err = exasock_genl_msg_set_sockelem_extend(msg, sk_stats);
        if (err)
            goto err_nla_put;
    }

    if (internal)
    {
        if (state == EXASOCK_GENL_CONNSTATE_LISTEN)
            err = exasock_genl_msg_set_sockelem_intlis(msg, &ssint.listen);
        else
            err = exasock_genl_msg_set_sockelem_intconn(msg, &ssint.conn);
        if (err)
            goto err_nla_put;
    }

    nla_nest_end(msg, attr);

    return 0;

err_nla_put:
    nla_nest_cancel(msg, attr);
    return err;
}

static struct exasock_stats_sock *exasock_genl_msg_fill_tcp_listen_list(
                                     struct exasock_stats_sock_list *sk_list,
                                     struct exasock_stats_sock *sk_stats,
                                     struct sk_buff *msg, bool extended,
                                     bool internal)
{
    uint8_t state;

    list_for_each_entry_from(sk_stats, &sk_list->list, node)
    {
        state = get_sock_state(sk_stats);

        if (state != EXASOCK_GENL_CONNSTATE_LISTEN)
            continue;

        if (exasock_genl_msg_set_sockelem(msg, sk_stats, state,
                                          extended, internal) == -EMSGSIZE)
            return sk_stats;
    }
    return NULL;
}

static struct exasock_stats_sock *exasock_genl_msg_fill_tcp_conn_list(
                                     struct exasock_stats_sock_list *sk_list,
                                     struct exasock_stats_sock *sk_stats,
                                     struct sk_buff *msg, bool extended,
                                     bool internal)
{
    uint8_t state;

    list_for_each_entry_from(sk_stats, &sk_list->list, node)
    {
        state = get_sock_state(sk_stats);

        if (state == EXASOCK_GENL_CONNSTATE_LISTEN)
            continue;

        if (exasock_genl_msg_set_sockelem(msg, sk_stats, state,
                                          extended, internal) == -EMSGSIZE)
            return sk_stats;
    }
    return NULL;
}

static struct exasock_stats_sock *exasock_genl_msg_fill_udp_list(
                                     struct exasock_stats_sock_list *sk_list,
                                     struct exasock_stats_sock *sk_stats,
                                     struct sk_buff *msg,
                                     enum exasock_genl_conn_state state,
                                     bool extended)
{
    list_for_each_entry_from(sk_stats, &sk_list->list, node)
        if (exasock_genl_msg_set_sockelem(msg, sk_stats, state,
                                          extended, false) == -EMSGSIZE)
            return sk_stats;
    return NULL;
}

static int exasock_genl_cmd_get_socklist(struct sk_buff *skb,
                                         struct genl_info *info)
{
    enum exasock_genl_sock_type genl_sock_type;
    struct exasock_stats_sock_list *sk_list;
    struct exasock_stats_sock *next_sock;
    struct nlattr *attr_socklist;
    struct sk_buff *resp_skb;
    void *resp_hdr;
    bool extended;
    bool internal;
    int err = 0;

    if (!info->attrs[EXASOCK_GENL_A_SOCK_TYPE])
        return -EINVAL;

    extended = info->attrs[EXASOCK_GENL_A_SOCK_EXTENDED] ? true : false;
    internal = info->attrs[EXASOCK_GENL_A_SOCK_INTERNAL] ? true : false;

    genl_sock_type = nla_get_u8(info->attrs[EXASOCK_GENL_A_SOCK_TYPE]);
    if ((uint8_t)genl_sock_type > EXASOCK_GENL_SOCKTYPE_MAX)
        return -EINVAL;

    sk_list = get_stats_sock_list(genl_sock_type_to_socktype(genl_sock_type));
    if (sk_list == NULL)
        return -EINVAL;

    mutex_lock(&sk_list->lock);

    next_sock = list_first_entry(&sk_list->list, struct exasock_stats_sock,
                                 node);

    do
    {
        resp_skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
        if (resp_skb == NULL)
            return -ENOMEM;

        resp_hdr = genlmsg_put(resp_skb, genl_info_snd_portid(info),
                               info->snd_seq, &exasock_genl_family,
                               NLM_F_MULTI, EXASOCK_GENL_C_GET_SOCKLIST);
        if (resp_hdr == NULL)
        {
            err = -EMSGSIZE;
            goto err_genlmsg_put;
        }

        if (nla_put_u8(resp_skb, EXASOCK_GENL_A_SOCK_TYPE, genl_sock_type))
        {
            err = -EMSGSIZE;
            goto err_nla_put;
        }

        attr_socklist = nla_nest_start(resp_skb, EXASOCK_GENL_A_LIST_SOCK);
        if (attr_socklist == NULL)
        {
            err = -EMSGSIZE;
            goto err_nla_put;
        }

        switch (genl_sock_type)
        {
        case EXASOCK_GENL_SOCKTYPE_TCP_LISTEN:
            next_sock = exasock_genl_msg_fill_tcp_listen_list(sk_list,
                                                              next_sock,
                                                              resp_skb,
                                                              extended,
                                                              internal);
            break;
        case EXASOCK_GENL_SOCKTYPE_TCP_CONN:
            next_sock = exasock_genl_msg_fill_tcp_conn_list(sk_list,
                                                            next_sock,
                                                            resp_skb,
                                                            extended,
                                                            internal);
            break;
        case EXASOCK_GENL_SOCKTYPE_UDP_LISTEN:
            next_sock = exasock_genl_msg_fill_udp_list(sk_list, next_sock,
                                        resp_skb, EXASOCK_GENL_CONNSTATE_NONE,
                                        extended);
            break;
        case EXASOCK_GENL_SOCKTYPE_UDP_CONN:
            next_sock = exasock_genl_msg_fill_udp_list(sk_list, next_sock,
                                 resp_skb, EXASOCK_GENL_CONNSTATE_ESTABLISHED,
                                 extended);
            break;
        default:
            mutex_unlock(&sk_list->lock);
            err = -EINVAL;
            goto err_nla_put;
        }

        nla_nest_end(resp_skb, attr_socklist);

        genlmsg_end(resp_skb, resp_hdr);
        err = genlmsg_reply(resp_skb, info);
        if (err)
            return err;
    }
    while (next_sock);

    mutex_unlock(&sk_list->lock);

    /* Send NLMSG_DONE message to indicate end of multipart messages */
    resp_skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (resp_skb == NULL)
        return -ENOMEM;
    resp_hdr = nlmsg_put(resp_skb, genl_info_snd_portid(info),
                         info->snd_seq, NLMSG_DONE, 0, NLM_F_MULTI);
    if (resp_hdr == NULL)
    {
        err = -EMSGSIZE;
        goto err_genlmsg_put;
    }
    err = genlmsg_reply(resp_skb, info);
    if (err)
        return err;

    return 0;

err_nla_put:
    genlmsg_cancel(resp_skb, resp_hdr);
err_genlmsg_put:
    nlmsg_free(resp_skb);
    return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
static const struct genl_ops exasock_genl_ops[] =
#else
static struct genl_ops exasock_genl_ops[] =
#endif
{
    {
        .cmd    = EXASOCK_GENL_C_GET_SOCKLIST,
        .doit   = exasock_genl_cmd_get_socklist,
        .policy = exasock_genl_policy,
    },
};

/* Family */
static struct genl_family exasock_genl_family =
{
#ifndef __HAS_NO_STATIC_GENL_ID
    .id         = GENL_ID_GENERATE,
#endif
    .hdrsize    = 0,
    .name       = EXASOCK_GENL_NAME,
    .version    = EXASOCK_GENL_VER,
    .maxattr    = EXASOCK_GENL_A_MAX,
#ifdef __HAS_STATIC_GENL_INIT
    .module     = THIS_MODULE,
    .ops        = exasock_genl_ops,
    .n_ops      = ARRAY_SIZE(exasock_genl_ops),
#endif
};

/**************************************
 * ExaSock statistics API
 **************************************/

void exasock_stats_socket_add(enum exasock_socktype type,
                              struct exasock_stats_sock *sk_stats)
{
    struct exasock_stats_sock_list *sk_list = get_stats_sock_list(type);

    mutex_lock(&sk_list->lock);
    list_add_tail(&sk_stats->node, &sk_list->list);
    mutex_unlock(&sk_list->lock);
}

void exasock_stats_socket_update(struct exasock_stats_sock *sk_stats,
                                 enum exasock_socktype prev_type,
                                 enum exasock_socktype type,
                                 struct exasock_stats_sock_addr *addr)
{
    struct exasock_stats_sock_list *sk_list = get_stats_sock_list(type);
    struct exasock_stats_sock_list *prev_sk_list = NULL;

    mutex_lock(&sk_list->lock);

    if (type != prev_type)
    {
        prev_sk_list = get_stats_sock_list(prev_type);
        mutex_lock(&prev_sk_list->lock);
        list_del(&sk_stats->node);
        list_add_tail(&sk_stats->node, &sk_list->list);
    }

    sk_stats->addr = *addr;

    if (type != prev_type)
        mutex_unlock(&prev_sk_list->lock);

    mutex_unlock(&sk_list->lock);
}

void exasock_stats_socket_del(struct exasock_stats_sock *sk_stats,
                              enum exasock_socktype type)
{
    struct exasock_stats_sock_list *sk_list = get_stats_sock_list(type);

    mutex_lock(&sk_list->lock);
    list_del(&sk_stats->node);
    mutex_unlock(&sk_list->lock);
}

int __init exasock_stats_init(void)
{
    int err;

    err = exasock_genl_register_family(&exasock_genl_family, exasock_genl_ops,
                                       ARRAY_SIZE(exasock_genl_ops));
    if (err)
        return err;

    INIT_LIST_HEAD(&exa_stats.tcp.list);
    mutex_init(&exa_stats.tcp.lock);

    INIT_LIST_HEAD(&exa_stats.udp.list);
    mutex_init(&exa_stats.udp.lock);

    INIT_LIST_HEAD(&exa_stats.udp_conn.list);
    mutex_init(&exa_stats.udp_conn.lock);

    return 0;
}

void exasock_stats_exit(void)
{
    genl_unregister_family(&exasock_genl_family);
}
