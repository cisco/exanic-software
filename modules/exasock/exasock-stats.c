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

#include "exasock.h"
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

static inline uint8_t get_sock_state(uint8_t *state)
{
    if (state == NULL)
        return EXASOCK_GENL_CONNSTATE_NONE;
    else
        return tcp_state_to_genl_connstate(*state);
}

static inline uint32_t get_sock_recv_q(struct exasock_stats_sock_info *info)
{
    uint32_t recv_q_bytes;

    if ((info->recv_q_recv_seq == NULL) || (info->recv_q_read_seq == NULL))
        return 0;

    recv_q_bytes = *(info->recv_q_recv_seq) - *(info->recv_q_read_seq);

    if (get_sock_state(info->state) == EXASOCK_GENL_CONNSTATE_LISTEN)
        return (recv_q_bytes / sizeof(struct exa_tcp_new_connection));
    else
        /* FIXME: for UDP this count of bytes includes headers, footers
         * and alignment padding */
        return recv_q_bytes;
}

static inline uint32_t get_sock_send_q(struct exasock_stats_sock_info *info)
{
    if ((info->send_q_sent_seq == NULL) || (info->send_q_ack_seq == NULL))
        return 0;
    if (get_sock_state(info->state) == EXASOCK_GENL_CONNSTATE_LISTEN)
        return 0;
    return (*(info->send_q_sent_seq) - *(info->send_q_ack_seq));
}

/**************************************
 * Generic Netlink API
 **************************************/

static struct genl_family exasock_genl_family;

/* Attribute policy */

static const struct nla_policy exasock_genl_policy[EXASOCK_GENL_A_MAX + 1] =
{
    [EXASOCK_GENL_A_UNSPEC]     = { .type = NLA_UNSPEC },
    [EXASOCK_GENL_A_SOCK_TYPE]  = { .type = NLA_U8 },
    [EXASOCK_GENL_A_LIST_SOCK]  = { .type = NLA_NESTED },
};

static inline int exasock_genl_msg_set_sockelem(struct sk_buff *msg,
                                          struct exasock_stats_sock_info *info,
                                          uint8_t state)
{
    struct nlattr *attr_sockelem;

    attr_sockelem = nla_nest_start(msg, EXASOCK_GENL_A_ELEM_SOCK);
    if (attr_sockelem == NULL)
        return -EMSGSIZE;

    if (nla_put_u32(msg, EXASOCK_GENL_A_SOCK_LOCAL_ADDR, info->addr.local_ip))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SOCK_PEER_ADDR, info->addr.peer_ip))
        goto err_nla_put;
    if (nla_put_u16(msg, EXASOCK_GENL_A_SOCK_LOCAL_PORT, info->addr.local_port))
        goto err_nla_put;
    if (nla_put_u16(msg, EXASOCK_GENL_A_SOCK_PEER_PORT, info->addr.peer_port))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SOCK_RECV_Q, get_sock_recv_q(info)))
        goto err_nla_put;
    if (nla_put_u32(msg, EXASOCK_GENL_A_SOCK_SEND_Q, get_sock_send_q(info)))
        goto err_nla_put;
    if (nla_put_u8(msg, EXASOCK_GENL_A_SOCK_STATE, state))
        goto err_nla_put;

    nla_nest_end(msg, attr_sockelem);

    return 0;

err_nla_put:
    nla_nest_cancel(msg, attr_sockelem);
    return -EMSGSIZE;
}

static struct exasock_stats_sock *exasock_genl_msg_fill_tcp_listen_list(
                                     struct exasock_stats_sock_list *sock_list,
                                     struct exasock_stats_sock *sock_stats,
                                     struct sk_buff *msg)
{
    uint8_t state;

    list_for_each_entry_from(sock_stats, &sock_list->list, node)
    {
        state = get_sock_state(sock_stats->info.state);

        if (state != EXASOCK_GENL_CONNSTATE_LISTEN)
            continue;

        if (exasock_genl_msg_set_sockelem(msg, &sock_stats->info, state) ==
                -EMSGSIZE)
            return sock_stats;
    }
    return NULL;
}

static struct exasock_stats_sock *exasock_genl_msg_fill_tcp_conn_list(
                                     struct exasock_stats_sock_list *sock_list,
                                     struct exasock_stats_sock *sock_stats,
                                     struct sk_buff *msg)
{
    uint8_t state;

    list_for_each_entry_from(sock_stats, &sock_list->list, node)
    {
        state = get_sock_state(sock_stats->info.state);

        if (state == EXASOCK_GENL_CONNSTATE_LISTEN)
            continue;

        if (exasock_genl_msg_set_sockelem(msg, &sock_stats->info, state) ==
                -EMSGSIZE)
            return sock_stats;
    }
    return NULL;
}

static struct exasock_stats_sock *exasock_genl_msg_fill_udp_list(
                                     struct exasock_stats_sock_list *sock_list,
                                     struct exasock_stats_sock *sock_stats,
                                     struct sk_buff *msg,
                                     enum exasock_genl_conn_state state)
{
    list_for_each_entry_from(sock_stats, &sock_list->list, node)
        if (exasock_genl_msg_set_sockelem(msg, &sock_stats->info, state) ==
                -EMSGSIZE)
            return sock_stats;
    return NULL;
}

static int exasock_genl_cmd_get_socklist(struct sk_buff *skb,
                                         struct genl_info *info)
{
    enum exasock_genl_sock_type genl_sock_type;
    struct exasock_stats_sock_list *sock_list;
    struct exasock_stats_sock *next_sock;
    struct nlattr *attr_socklist;
    struct sk_buff *resp_skb;
    void *resp_hdr;
    int err = 0;

    if (!info->attrs[EXASOCK_GENL_A_SOCK_TYPE])
        return -EINVAL;

    genl_sock_type = nla_get_u8(info->attrs[EXASOCK_GENL_A_SOCK_TYPE]);
    if ((uint8_t)genl_sock_type > EXASOCK_GENL_SOCKTYPE_MAX)
        return -EINVAL;

    sock_list = get_stats_sock_list(genl_sock_type_to_socktype(genl_sock_type));
    if (sock_list == NULL)
        return -EINVAL;

    mutex_lock(&sock_list->lock);

    next_sock = list_first_entry(&sock_list->list, struct exasock_stats_sock,
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
            next_sock = exasock_genl_msg_fill_tcp_listen_list(sock_list,
                                                              next_sock,
                                                              resp_skb);
            break;
        case EXASOCK_GENL_SOCKTYPE_TCP_CONN:
            next_sock = exasock_genl_msg_fill_tcp_conn_list(sock_list,
                                                            next_sock,
                                                            resp_skb);
            break;
        case EXASOCK_GENL_SOCKTYPE_UDP_LISTEN:
            next_sock = exasock_genl_msg_fill_udp_list(sock_list, next_sock,
                                        resp_skb, EXASOCK_GENL_CONNSTATE_NONE);
            break;
        case EXASOCK_GENL_SOCKTYPE_UDP_CONN:
            next_sock = exasock_genl_msg_fill_udp_list(sock_list, next_sock,
                                 resp_skb, EXASOCK_GENL_CONNSTATE_ESTABLISHED);
            break;
        default:
            mutex_unlock(&sock_list->lock);
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

    mutex_unlock(&sock_list->lock);

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

struct exasock_stats_sock *exasock_stats_socket_add(enum exasock_socktype type,
                                          struct exasock_stats_sock_info *info)
{
    struct exasock_stats_sock_list *sock_list = get_stats_sock_list(type);
    struct exasock_stats_sock *sock_stats;

    sock_stats = kzalloc(sizeof(struct exasock_stats_sock), GFP_KERNEL);
    if (sock_stats == NULL)
        return NULL;

    sock_stats->info = *info;

    mutex_lock(&sock_list->lock);
    list_add_tail(&sock_stats->node, &sock_list->list);
    mutex_unlock(&sock_list->lock);

    return sock_stats;
}

void exasock_stats_socket_update(struct exasock_stats_sock *sock_stats,
                                 enum exasock_socktype prev_type,
                                 enum exasock_socktype type,
                                 struct exasock_stats_sock_info_addr *addr)
{
    struct exasock_stats_sock_list *sock_list = get_stats_sock_list(type);
    struct exasock_stats_sock_list *prev_sock_list = NULL;

    mutex_lock(&sock_list->lock);

    if (type != prev_type)
    {
        prev_sock_list = get_stats_sock_list(prev_type);
        mutex_lock(&prev_sock_list->lock);
        list_del(&sock_stats->node);
        list_add_tail(&sock_stats->node, &sock_list->list);
    }

    sock_stats->info.addr = *addr;

    if (type != prev_type)
        mutex_unlock(&prev_sock_list->lock);

    mutex_unlock(&sock_list->lock);
}

void exasock_stats_socket_del(struct exasock_stats_sock *sock_stats,
                              enum exasock_socktype type)
{
    struct exasock_stats_sock_list *sock_list = get_stats_sock_list(type);

    mutex_lock(&sock_list->lock);
    list_del(&sock_stats->node);
    mutex_unlock(&sock_list->lock);

    kfree(sock_stats);
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
