#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>
#include <pwd.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <arpa/inet.h>

#include <exasock/exasock-genl.h>

#define EXASOCK_STAT_BUF_SIZE 24

struct exasock_stat_sock_id
{
    uint32_t pid;
    uint32_t fd;
};

struct exasock_stat_config
{
    bool show_connected;
    bool show_listening;
    bool show_tcp;
    bool show_udp;
    bool show_more;
    bool show_tcp_diags;
    bool single_socket;
    struct exasock_stat_sock_id sock_id;
};

struct exasock_stat_genl
{
    int family;
    struct nl_sock *sock;
};

static struct exasock_stat_genl exasock_genl;

static inline char * print_sock_proto(enum exasock_genl_sock_type type)
{
    switch (type)
    {
    case EXASOCK_GENL_SOCKTYPE_TCP_CONN:
    case EXASOCK_GENL_SOCKTYPE_TCP_LISTEN:
        return "TCP";
    case EXASOCK_GENL_SOCKTYPE_UDP_LISTEN:
    case EXASOCK_GENL_SOCKTYPE_UDP_CONN:
        return "UDP";
    default:
        return "Unknown";
    }
}

static inline char * print_sock_state(enum exasock_genl_conn_state state)
{
    switch (state)
    {
    case EXASOCK_GENL_CONNSTATE_CLOSED:
        return "CLOSED";
    case EXASOCK_GENL_CONNSTATE_LISTEN:
        return "LISTEN";
    case EXASOCK_GENL_CONNSTATE_SENT:
        return "SYN-SENT";
    case EXASOCK_GENL_CONNSTATE_RCVD:
        return "SYN-RECEIVED";
    case EXASOCK_GENL_CONNSTATE_ESTABLISHED:
        return "ESTABLISHED";
    case EXASOCK_GENL_CONNSTATE_CLOSE_WAIT:
        return "CLOSE-WAIT";
    case EXASOCK_GENL_CONNSTATE_FIN_WAIT_1:
        return "FIN-WAIT-1";
    case EXASOCK_GENL_CONNSTATE_FIN_WAIT_2:
        return "FIN-WAIT-2";
    case EXASOCK_GENL_CONNSTATE_CLOSING:
        return "CLOSING";
    case EXASOCK_GENL_CONNSTATE_LAST_ACK:
        return "LAST-ACK";
    case EXASOCK_GENL_CONNSTATE_TIME_WAIT:
        return "TIME-WAIT";
    case EXASOCK_GENL_CONNSTATE_NONE:
    default:
        return "-";
    }
}

static inline char * print_sock_addr(char buf[], struct in_addr ip,
                                     uint16_t port)
{
    if (port == 0)
        snprintf(buf, EXASOCK_STAT_BUF_SIZE, "%s:*",
                 (ip.s_addr == 0) ? "*" : inet_ntoa(ip));
    else
        snprintf(buf, EXASOCK_STAT_BUF_SIZE, "%s:%i",
                 (ip.s_addr == 0) ? "*" : inet_ntoa(ip), ntohs(port));
    return buf;
}

static inline char * print_username(char buf[], uint32_t uid)
{
    struct passwd *pwd = getpwuid(uid);
    if (pwd)
        return pwd->pw_name;
    snprintf(buf, EXASOCK_STAT_BUF_SIZE, "%i", uid);
    return buf;
}

static inline char * print_pid_fd(char buf[], uint32_t pid, uint32_t fd)
{
    snprintf(buf, EXASOCK_STAT_BUF_SIZE, "%i:%i", pid, fd);
    return buf;
}

static void print_socket_info_internal_conn(struct nlattr *attr[], bool single)
{
    uint64_t tx_bytes;
    uint64_t tx_acked_bytes;
    uint64_t rx_bytes;
    uint64_t rx_deliv_bytes;
    uint32_t retr_segs_f;
    uint32_t retr_segs_t;
    uint32_t retr_bytes;
    uint8_t wscale_peer;
    uint8_t wscale_local;
    uint32_t window_peer;
    uint32_t window_local;
    uint16_t mss_peer;
    uint16_t mss_local;
    uint32_t cwnd;
    uint32_t ssthresh;
    int indent;

    tx_bytes = nla_get_u64(attr[EXASOCK_GENL_A_SKINFOINTC_TX_BYTES]);
    tx_acked_bytes = nla_get_u64(attr[EXASOCK_GENL_A_SKINFOINTC_TX_ACK_BYTES]);
    rx_bytes = nla_get_u64(attr[EXASOCK_GENL_A_SKINFOINTC_RX_BYTES]);
    rx_deliv_bytes = nla_get_u64(attr[EXASOCK_GENL_A_SKINFOINTC_RX_DLVR_BYTES]);
    retr_segs_f = nla_get_u32(attr[EXASOCK_GENL_A_SKINFOINTC_RETRANS_SEGS_FAST]);
    retr_segs_t = nla_get_u32(attr[EXASOCK_GENL_A_SKINFOINTC_RETRANS_SEGS_TO]);
    retr_bytes = nla_get_u32(attr[EXASOCK_GENL_A_SKINFOINTC_RETRANS_BYTES]);
    wscale_peer = nla_get_u8(attr[EXASOCK_GENL_A_SKINFOINTC_PEER_WSCALE]);
    wscale_local = nla_get_u8(attr[EXASOCK_GENL_A_SKINFOINTC_LOCAL_WSCALE]);
    window_peer = nla_get_u32(attr[EXASOCK_GENL_A_SKINFOINTC_PEER_WIN]);
    window_local = nla_get_u32(attr[EXASOCK_GENL_A_SKINFOINTC_LOCAL_WIN]);
    mss_peer = nla_get_u16(attr[EXASOCK_GENL_A_SKINFOINTC_PEER_MSS]);
    mss_local = nla_get_u16(attr[EXASOCK_GENL_A_SKINFOINTC_LOCAL_MSS]);
    cwnd = nla_get_u32(attr[EXASOCK_GENL_A_SKINFOINTC_CWND]);
    ssthresh = nla_get_u32(attr[EXASOCK_GENL_A_SKINFOINTC_SSTHRESH]);

    indent = single ? 4 : 1;
    printf("%*cinternal diagnostics:\n", indent, ' ');
    printf("%*c    Rx Bytes: %llu (Delivered: %llu)\n", indent, ' ',
           (unsigned long long)rx_bytes,
           (unsigned long long)rx_deliv_bytes);
    printf("%*c    Tx Bytes: %llu (Acked: %llu)\n", indent, ' ',
           (unsigned long long)tx_bytes, (unsigned long long)tx_acked_bytes);
    printf("%*c    Retransmitted Segments: %u (Fast Retransmit: %u, Timeouts: %u)\n",
           indent, ' ', (retr_segs_f + retr_segs_t), retr_segs_f, retr_segs_t);
    printf("%*c    Retransmitted Bytes: %u\n", indent, ' ', retr_bytes);
    printf("%*c    Window (peer,local): %u,%u  Scale (peer,local): %u,%u\n",
           indent, ' ', window_peer, window_local, wscale_peer, wscale_local);
    printf("%*c    Congestion Window: %u  Slow Start Threshold: %u  MSS (Tx,Rx): %u,%u\n",
           indent, ' ', cwnd, ssthresh, mss_peer, mss_local);
}

static void print_socket_info_internal_listen(struct nlattr *attr[], bool single)
{
    uint32_t reqs_recv;
    uint32_t reqs_estab;
    int indent;

    reqs_recv = nla_get_u32(attr[EXASOCK_GENL_A_SKINFOINTL_REQS_RCV]);
    reqs_estab = nla_get_u32(attr[EXASOCK_GENL_A_SKINFOINTL_REQS_ESTAB]);

    indent = single ? 4 : 1;
    printf("%*cinternal diagnostics:\n", indent, ' ');
    printf("%*c    Connection Requests: %u (Established: %u)\n", indent, ' ',
           reqs_recv, reqs_estab);
}

static void print_socket_info_extend(struct nlattr *attr[], bool single)
{
    char buf_u[EXASOCK_STAT_BUF_SIZE];
    char buf_p[EXASOCK_STAT_BUF_SIZE];
    uint32_t uid;
    uint32_t pid;
    uint32_t fd;
    char *prog_name;

    uid = nla_get_u32(attr[EXASOCK_GENL_A_SKINFOEXT_UID]);
    prog_name = nla_get_string(attr[EXASOCK_GENL_A_SKINFOEXT_PROG]);

    if (single)
    {
        /* Single socket format */
        printf("    User: %s  Program: %s\n",
               print_username(buf_u, uid), prog_name);
    }
    else
    {
        /* Socket list format */
        pid = nla_get_u32(attr[EXASOCK_GENL_A_SKINFOEXT_PID]);
        fd = nla_get_u32(attr[EXASOCK_GENL_A_SKINFOEXT_FD]);

        printf(" | %-12s | %-10s | %s",
               print_username(buf_u, uid),      /* User */
               print_pid_fd(buf_p, pid, fd),    /* PID:FD */
               prog_name);                      /* Program */
    }
}

static void print_socket_info(struct nlattr *attr[],
                              enum exasock_genl_sock_type sock_type,
                              struct exasock_stat_sock_id *sock_id)
{
    char buf_la[EXASOCK_STAT_BUF_SIZE];
    char buf_pa[EXASOCK_STAT_BUF_SIZE];
    struct in_addr local_ip;
    struct in_addr peer_ip;
    uint16_t local_port;
    uint16_t peer_port;
    uint32_t recv_q;
    uint32_t send_q;
    uint8_t state;

    local_ip.s_addr = nla_get_u32(attr[EXASOCK_GENL_A_SKINFO_LOCAL_ADDR]);
    peer_ip.s_addr = nla_get_u32(attr[EXASOCK_GENL_A_SKINFO_PEER_ADDR]);
    local_port = nla_get_u16(attr[EXASOCK_GENL_A_SKINFO_LOCAL_PORT]);
    peer_port = nla_get_u16(attr[EXASOCK_GENL_A_SKINFO_PEER_PORT]);
    recv_q = nla_get_u32(attr[EXASOCK_GENL_A_SKINFO_RECV_Q]);
    send_q = nla_get_u32(attr[EXASOCK_GENL_A_SKINFO_SEND_Q]);
    state = nla_get_u8(attr[EXASOCK_GENL_A_SKINFO_STATE]);

    if (sock_id)
    {
        /* Single socket format */
        printf("Socket (PID:FD): %i:%i\n", sock_id->pid, sock_id->fd);
        printf("    Proto: %s  State: %s\n",
               print_sock_proto(sock_type), print_sock_state(state));
        printf("    Local Address: %s\n",
               print_sock_addr(buf_la, local_ip, local_port));
        printf("    Foreign Address: %s\n",
               print_sock_addr(buf_pa, peer_ip, peer_port));
        printf("    Recv-Q: %i", recv_q);
        if (sock_type == EXASOCK_GENL_SOCKTYPE_TCP_CONN)
            printf("  Send-Q: %i", send_q);
        printf("\n");
    }
    else
    {
        /* Socket list format */
        printf(" %-5s | %-8i | %-8i | %-24s | %-24s | %-12s",
               print_sock_proto(sock_type),                     /* Proto */
               recv_q,                                          /* Recv-Q */
               send_q,                                          /* Send-Q */
               print_sock_addr(buf_la, local_ip, local_port),   /* Local Address */
               print_sock_addr(buf_pa, peer_ip, peer_port),     /* Foreign Address */
               print_sock_state(state));                        /* State */
    }
}

static int get_single_socket_cb(struct nl_msg *msg, void *arg)
{
    struct exasock_stat_sock_id *sock_id = arg;
    enum exasock_genl_sock_type sock_type;
    struct nlattr *attr[EXASOCK_GENL_A_MAX + 1];
    struct nlattr *attr_sock[EXASOCK_GENL_A_SKINFO_MAX + 1];
    struct nlattr *attr_sockext[EXASOCK_GENL_A_SKINFOEXT_MAX + 1];
    struct nlattr *attr_sockintc[EXASOCK_GENL_A_SKINFOINTC_MAX + 1];
    struct nlattr *attr_sockintl[EXASOCK_GENL_A_SKINFOINTL_MAX + 1];
    int err;

    err = genlmsg_parse(nlmsg_hdr(msg), 0, attr, EXASOCK_GENL_A_MAX, NULL);
    if (err)
    {
        fprintf(stderr, "failed to parse netlink message (%s: err=%i)\n",
                __func__, err);
        return NL_SKIP;
    }

    if (!attr[EXASOCK_GENL_A_SOCK_PID])
    {
        fprintf(stderr, "netlink message error (%s: socket PID not found)\n",
                __func__);
        return NL_SKIP;
    }
    if (!attr[EXASOCK_GENL_A_SOCK_FD])
    {
        fprintf(stderr, "netlink message error (%s: socket FD not found)\n",
                __func__);
        return NL_SKIP;
    }

    if (nla_get_u32(attr[EXASOCK_GENL_A_SOCK_PID]) != sock_id->pid)
    {
        fprintf(stderr, "netlink message error (%s: socket PID mismatch)\n",
                __func__);
        return NL_SKIP;
    }
    if (nla_get_u32(attr[EXASOCK_GENL_A_SOCK_FD]) != sock_id->fd)
    {
        fprintf(stderr, "netlink message error (%s: socket FD mismatch)\n",
                __func__);
        return NL_SKIP;
    }

    if (!attr[EXASOCK_GENL_A_SINGLE_SOCK])
    {
        /* This is not an error but legitimate notification that such a socket
         * has not been found.
         */
        printf("Socket %i:%i not found (not an active accelerated socket)\n\n",
               sock_id->pid, sock_id->fd);
        return NL_SKIP;
    }

    if (!attr[EXASOCK_GENL_A_SOCK_TYPE])
    {
        fprintf(stderr, "netlink message error (%s: socket type not found)\n",
                __func__);
        return NL_SKIP;
    }

    sock_type = nla_get_u8(attr[EXASOCK_GENL_A_SOCK_TYPE]);

    err = nla_parse_nested(attr_sock, EXASOCK_GENL_A_SKINFO_MAX,
                           attr[EXASOCK_GENL_A_SINGLE_SOCK], NULL);
    if (err)
    {
        fprintf(stderr,
                "failed to parse netlink nested attributes (%s: err=%i)\n",
                __func__, err);
        return NL_SKIP;
    }
    print_socket_info(attr_sock, sock_type, sock_id);

    if (attr_sock[EXASOCK_GENL_A_SKINFO_EXTENDED])
    {
        err = nla_parse_nested(attr_sockext, EXASOCK_GENL_A_SKINFOEXT_MAX,
                               attr_sock[EXASOCK_GENL_A_SKINFO_EXTENDED],
                               NULL);
        if (err)
        {
            fprintf(stderr,
                    "failed to parse netlink nested attributes (%s: err=%i)\n",
                    __func__, err);
            return NL_SKIP;
        }
        print_socket_info_extend(attr_sockext, true);
    }

    if (attr_sock[EXASOCK_GENL_A_SKINFO_INTERN_CONN])
    {
        err = nla_parse_nested(attr_sockintc, EXASOCK_GENL_A_SKINFOINTC_MAX,
                               attr_sock[EXASOCK_GENL_A_SKINFO_INTERN_CONN],
                               NULL);
        if (err)
        {
            fprintf(stderr,
                    "failed to parse netlink nested attributes (%s: err=%i)\n",
                    __func__, err);
            return NL_SKIP;
        }
        print_socket_info_internal_conn(attr_sockintc, true);
    }
    else if (attr_sock[EXASOCK_GENL_A_SKINFO_INTERN_LISTEN])
    {
        err = nla_parse_nested(attr_sockintl, EXASOCK_GENL_A_SKINFOINTL_MAX,
                               attr_sock[EXASOCK_GENL_A_SKINFO_INTERN_LISTEN],
                               NULL);
        if (err)
        {
            fprintf(stderr,
                    "failed to parse netlink nested attributes (%s: err=%i)\n",
                    __func__, err);
            return NL_SKIP;
        }
        print_socket_info_internal_listen(attr_sockintl, true);
    }

    printf("\n");

    return NL_SKIP;
}

static int get_single_socket(struct exasock_stat_sock_id sock_id,
                             bool extended, bool internal)
{
    struct nl_msg *msg;
    int ret;

    msg = nlmsg_alloc();
    if (msg == NULL)
    {
        fprintf(stderr, "failed to allocate netlink message (%s)\n", __func__);
        return -ENOMEM;
    }

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
            exasock_genl.family, 0, 0,
            EXASOCK_GENL_C_GET_SOCKET, 0);

    NLA_PUT_U32(msg, EXASOCK_GENL_A_SOCK_PID, sock_id.pid);
    NLA_PUT_U32(msg, EXASOCK_GENL_A_SOCK_FD, sock_id.fd);
    if (extended)
        NLA_PUT_FLAG(msg, EXASOCK_GENL_A_SOCK_EXTENDED);
    if (internal)
        NLA_PUT_FLAG(msg, EXASOCK_GENL_A_SOCK_INTERNAL);

    ret = nl_send_auto(exasock_genl.sock, msg);
    nlmsg_free(msg);
    if (ret < 0)
    {
        fprintf(stderr, "failed to send netlink message (%s): %s\n",
                __func__, nl_geterror(ret));
        return -ECOMM;
    }

    ret = nl_socket_modify_cb(exasock_genl.sock, NL_CB_VALID, NL_CB_CUSTOM,
                              get_single_socket_cb, &sock_id);
    if (ret != 0)
    {
        fprintf(stderr, "failed to set netlink callback (%s): %s\n",
                __func__, nl_geterror(ret));
        return -ECANCELED;
    }

    ret = nl_recvmsgs_default(exasock_genl.sock);
    if (ret != 0)
    {
        fprintf(stderr, "failed to receive netlink reply (%s): %s\n",
                __func__, nl_geterror(ret));
        return -ENODATA;
    }

    return 0;

nla_put_failure:
    fprintf(stderr, "failed to add attribute to netlink message (%s)\n",
            __func__);
    nlmsg_free(msg);
    return -ENOBUFS;
}

static int get_sockets_cb(struct nl_msg *msg, void *arg)
{
    enum exasock_genl_sock_type *sock_type = arg;
    struct nlattr *attr[EXASOCK_GENL_A_MAX + 1];
    struct nlattr *attr_sockelem;
    struct nlattr *attr_sock[EXASOCK_GENL_A_SKINFO_MAX + 1];
    struct nlattr *attr_sockext[EXASOCK_GENL_A_SKINFOEXT_MAX + 1];
    struct nlattr *attr_sockintc[EXASOCK_GENL_A_SKINFOINTC_MAX + 1];
    struct nlattr *attr_sockintl[EXASOCK_GENL_A_SKINFOINTL_MAX + 1];
    int i;
    int err;

    err = genlmsg_parse(nlmsg_hdr(msg), 0, attr, EXASOCK_GENL_A_MAX, NULL);
    if (err)
    {
        fprintf(stderr, "failed to parse netlink message (%s: err=%i)\n",
                __func__, err);
        return NL_SKIP;
    }

    if (!attr[EXASOCK_GENL_A_SOCK_TYPE])
    {
        fprintf(stderr, "netlink message error (%s: socket type not found)\n",
                __func__);
        return NL_SKIP;
    }

    if (nla_get_u8(attr[EXASOCK_GENL_A_SOCK_TYPE]) != *sock_type)
    {
        fprintf(stderr, "netlink message error (%s: socket type mismatch)\n",
                __func__);
        return NL_SKIP;
    }

    if (!attr[EXASOCK_GENL_A_LIST_SOCK])
    {
        fprintf(stderr, "netlink message error (%s: socket list not found)\n",
                __func__);
        return NL_SKIP;
    }

    nla_for_each_nested(attr_sockelem, attr[EXASOCK_GENL_A_LIST_SOCK], i)
    {
        err = nla_parse_nested(attr_sock, EXASOCK_GENL_A_SKINFO_MAX,
                               attr_sockelem, NULL);
        if (err)
        {
            fprintf(stderr,
                    "failed to parse netlink nested attributes (%s: err=%i)\n",
                    __func__, err);
            return NL_SKIP;
        }
        print_socket_info(attr_sock, *sock_type, NULL);

        if (attr_sock[EXASOCK_GENL_A_SKINFO_EXTENDED])
        {
            err = nla_parse_nested(attr_sockext, EXASOCK_GENL_A_SKINFOEXT_MAX,
                                   attr_sock[EXASOCK_GENL_A_SKINFO_EXTENDED],
                                   NULL);
            if (err)
            {
                fprintf(stderr,
                        "failed to parse netlink nested attributes (%s: err=%i)\n",
                        __func__, err);
                return NL_SKIP;
            }
            print_socket_info_extend(attr_sockext, false);
        }

        printf("\n");

        if (attr_sock[EXASOCK_GENL_A_SKINFO_INTERN_CONN])
        {
            err = nla_parse_nested(attr_sockintc, EXASOCK_GENL_A_SKINFOINTC_MAX,
                                   attr_sock[EXASOCK_GENL_A_SKINFO_INTERN_CONN],
                                   NULL);
            if (err)
            {
                fprintf(stderr,
                        "failed to parse netlink nested attributes (%s: err=%i)\n",
                        __func__, err);
                return NL_SKIP;
            }
            print_socket_info_internal_conn(attr_sockintc, false);
            printf("\n");
        }
        else if (attr_sock[EXASOCK_GENL_A_SKINFO_INTERN_LISTEN])
        {
            err = nla_parse_nested(attr_sockintl, EXASOCK_GENL_A_SKINFOINTL_MAX,
                                   attr_sock[EXASOCK_GENL_A_SKINFO_INTERN_LISTEN],
                                   NULL);
            if (err)
            {
                fprintf(stderr,
                        "failed to parse netlink nested attributes (%s: err=%i)\n",
                        __func__, err);
                return NL_SKIP;
            }
            print_socket_info_internal_listen(attr_sockintl, false);
            printf("\n");
        }
    }

    return NL_SKIP;
}

static int get_sockets(enum exasock_genl_sock_type sock_type, bool extended,
                       bool internal)
{
    struct nl_msg *msg;
    int ret;

    msg = nlmsg_alloc();
    if (msg == NULL)
    {
        fprintf(stderr, "failed to allocate netlink message (%s)\n", __func__);
        return -ENOMEM;
    }

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
            exasock_genl.family, 0, 0,
            EXASOCK_GENL_C_GET_SOCKLIST, 0);

    NLA_PUT_U8(msg, EXASOCK_GENL_A_SOCK_TYPE, sock_type);
    if (extended)
        NLA_PUT_FLAG(msg, EXASOCK_GENL_A_SOCK_EXTENDED);
    if (internal)
        NLA_PUT_FLAG(msg, EXASOCK_GENL_A_SOCK_INTERNAL);

    ret = nl_send_auto(exasock_genl.sock, msg);
    nlmsg_free(msg);
    if (ret < 0)
    {
        fprintf(stderr, "failed to send netlink message (%s): %s\n",
                __func__, nl_geterror(ret));
        return -ECOMM;
    }

    ret = nl_socket_modify_cb(exasock_genl.sock, NL_CB_VALID, NL_CB_CUSTOM,
                              get_sockets_cb, &sock_type);
    if (ret != 0)
    {
        fprintf(stderr, "failed to set netlink callback (%s): %s\n",
                __func__, nl_geterror(ret));
        return -ECANCELED;
    }

    ret = nl_recvmsgs_default(exasock_genl.sock);
    if (ret != 0)
    {
        fprintf(stderr, "failed to receive netlink reply (%s): %s\n",
                __func__, nl_geterror(ret));
        return -ENODATA;
    }

    return 0;

nla_put_failure:
    fprintf(stderr, "failed to add attribute to netlink message (%s)\n",
            __func__);
    nlmsg_free(msg);
    return -ENOBUFS;
}

static int init_genl(void)
{
    int err;

    exasock_genl.sock = nl_socket_alloc();
    if (exasock_genl.sock == NULL)
    {
        fprintf(stderr, "failed to allocate netlink socket\n");
        return -ENOMEM;
    }

    err = genl_connect(exasock_genl.sock);
    if (err)
    {
        fprintf(stderr, "failed to connect netlink socket: %s\n",
                nl_geterror(err));
        return -ECONNREFUSED;
    }

    /* As long as we send requests expecting replies, ACK is not needed */
    nl_socket_disable_auto_ack(exasock_genl.sock);

    exasock_genl.family = genl_ctrl_resolve(exasock_genl.sock,
                                            EXASOCK_GENL_NAME);
    if (exasock_genl.family < 0)
    {
        fprintf(stderr, "resolving generic netlink family failed: %s\n",
                nl_geterror(exasock_genl.family));
        return -EADDRNOTAVAIL;
    }

    return 0;
}

static void cleanup_genl(void)
{
    if (exasock_genl.sock)
        nl_socket_free(exasock_genl.sock);
}

static void show_socket(struct exasock_stat_config *cfg)
{
    int err;

    err = get_single_socket(cfg->sock_id, cfg->show_more,
                            cfg->show_tcp_diags);
    if (err)
        fprintf(stderr, "failed to get socket %u:%u from exasock: %s\n",
                cfg->sock_id.pid, cfg->sock_id.fd, strerror(-err));
    return;
}

static void show_tcp(struct exasock_stat_config *cfg)
{
    int err;

    if (cfg->show_listening)
    {
        err = get_sockets(EXASOCK_GENL_SOCKTYPE_TCP_LISTEN,
                          cfg->show_more, cfg->show_tcp_diags);
        if (err)
            goto get_sockets_failure;
    }
    if (cfg->show_connected)
    {
        err = get_sockets(EXASOCK_GENL_SOCKTYPE_TCP_CONN,
                          cfg->show_more, cfg->show_tcp_diags);
        if (err)
            goto get_sockets_failure;
    }
    return;

get_sockets_failure:
    fprintf(stderr, "failed to get a list of TCP sockets from exasock: %s\n",
            strerror(-err));
}

static void show_udp(struct exasock_stat_config *cfg)
{
    int err;

    if (cfg->show_listening)
    {
        err = get_sockets(EXASOCK_GENL_SOCKTYPE_UDP_LISTEN,
                          cfg->show_more, false);
        if (err)
            goto get_sockets_failure;
    }
    if (cfg->show_connected)
    {
        err = get_sockets(EXASOCK_GENL_SOCKTYPE_UDP_CONN,
                          cfg->show_more, false);
        if (err)
            goto get_sockets_failure;
    }
    return;

get_sockets_failure:
    fprintf(stderr, "failed to get a list of UDP sockets from exasock: %s\n",
            strerror(-err));
}

static void show_stats(struct exasock_stat_config *cfg)
{
    printf("\nActive ExaNIC Sockets accelerated connections");
    if (cfg->show_connected && cfg->show_listening)
        printf(" (servers and established):\n");
    else if (cfg->show_connected)
        printf(" (w/o servers):\n");
    else if (cfg->show_listening)
        printf(" (only servers):\n");
    printf(" %-5s | %-8s | %-8s | %-24s | %-24s | %-12s",
           "Proto", "Recv-Q", "Send-Q", "Local Address", "Foreign Address", "State");
    if (cfg->show_more)
        printf(" | %-12s | %-10s | %s",
               "User", "PID:FD", "Program");
    printf("\n");

    if (cfg->show_tcp)
        show_tcp(cfg);
    if (cfg->show_udp)
        show_udp(cfg);
    printf("\n");
}

static int parse_arg_socket(char *arg, struct exasock_stat_config *cfg)
{
    unsigned long int val;
    char *p, *endp;

    p = strtok(arg, ":");
    if (p == NULL)
    {
        fprintf(stderr, "invalid socket identifier\n");
        return -EINVAL;
    }
    val = strtoul(p, &endp, 0);
    if (*p == '\0' || *endp != '\0' || val > UINT32_MAX)
    {
        fprintf(stderr, "invalid PID value in socket identifier\n");
        return -EINVAL;
    }
    cfg->sock_id.pid = (uint32_t)val;

    p = strtok(NULL, "");
    if (p == NULL)
    {
        fprintf(stderr, "invalid socket identifier\n");
        return -EINVAL;
    }
    val = strtoul(p, &endp, 0);
    if (*p == '\0' || *endp != '\0' || val > UINT32_MAX)
    {
        fprintf(stderr, "invalid FD value in socket identifier\n");
        return -EINVAL;
    }
    cfg->sock_id.fd = (uint32_t)val;

    return 0;
}

static void print_usage(char *name)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "   %s [-cltuei]\n", name);
    fprintf(stderr, "   %s -s <socket> [-ei]\n", name);
    fprintf(stderr, "   %s [-h]\n", name);
    fprintf(stderr, "    -c, --connected    display connected sockets (default: all)\n");
    fprintf(stderr, "    -l, --listening    display listening server sockets\n");
    fprintf(stderr, "    -t, --tcp          display TCP sockets (default: all)\n");
    fprintf(stderr, "    -u, --udp          display UDP sockets\n");
    fprintf(stderr, "    -e, --extend       display more information (user, program, fd)\n");
    fprintf(stderr, "    -i, --internal     display internal TCP diagnostics\n");
    fprintf(stderr, "    -s, --socket       specify socket to display information about\n");
    fprintf(stderr, "                       (<socket> defined as PID:FD, where PID is the process ID\n");
    fprintf(stderr, "                       and FD is the file descriptor)\n");
    fprintf(stderr, "    -h, --help         display tool usage info\n\n");
}

static void print_help(char *name)
{
    fprintf(stderr, "\nexasock-stat (ExaSock version @EXANIC_VERSION@)\n");
    fprintf(stderr, "Display ExaNIC Sockets accelerated connections\n\n");
    print_usage(name);
    fprintf(stderr, "Output:\n");
    fprintf(stderr, "   Proto:\n");
    fprintf(stderr, "       The protocol used by the socket (TCP or UDP)\n");
    fprintf(stderr, "   Recv-Q:\n");
    fprintf(stderr, "       Connected: The count of bytes not copied by the user program connected to this socket\n");
    fprintf(stderr, "       Listening: The count of connections waiting to be accepted by the user program\n");
    fprintf(stderr, "   Send-Q:\n");
    fprintf(stderr, "       Connected: The count of bytes not acknowledged by the remote host\n");
    fprintf(stderr, "       Listening: N/A\n");
    fprintf(stderr, "   Local Address:\n");
    fprintf(stderr, "       Address and port number of the local end of the socket\n");
    fprintf(stderr, "   Foreign Address:\n");
    fprintf(stderr, "       Address and port number of the remote end of the socket\n");
    fprintf(stderr, "   State:\n");
    fprintf(stderr, "       The state of the socket\n");
    fprintf(stderr, "Extended Output (-e/--extend enabled):\n");
    fprintf(stderr, "   User:\n");
    fprintf(stderr, "       The username or the user id (UID) of the owner of the socket\n");
    fprintf(stderr, "   PID:FD:\n");
    fprintf(stderr, "       PID of the process that owns the socket and value of the socket's file descriptor\n");
    fprintf(stderr, "   Program:\n");
    fprintf(stderr, "       Process name of the process that owns the socket\n");
    fprintf(stderr, "\n");
}

static struct option longopts[] =
{
    {"connected", 0, 0, 'c'},
    {"listening", 0, 0, 'l'},
    {"tcp",       0, 0, 't'},
    {"udp",       0, 0, 'u'},
    {"extend",    0, 0, 'e'},
    {"internal",  0, 0, 'i'},
    {"socket",    0, 0, 's'},
    {"help",      0, 0, 'h'},
    {0, 0, 0, 0}
};

int main(int argc, char *argv[])
{
    struct exasock_stat_config cfg;
    int opt;
    int err;

    /* initialize config before parsing options */
    cfg.show_connected = false;
    cfg.show_listening = false;
    cfg.show_tcp = false;
    cfg.show_udp = false;
    cfg.show_more = false;
    cfg.show_tcp_diags = false;
    cfg.single_socket = false;
    cfg.sock_id.pid = cfg.sock_id.fd = 0;

    while ((opt = getopt_long(argc, argv, ":cltueis:h", longopts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'c':
            cfg.show_connected = true;
            break;
        case 'l':
            cfg.show_listening = true;
            break;
        case 't':
            cfg.show_tcp = true;
            break;
        case 'u':
            cfg.show_udp = true;
            break;
        case 'e':
            cfg.show_more = true;
            break;
        case 'i':
            cfg.show_tcp_diags = true;
            break;
        case 's':
            err = parse_arg_socket(optarg, &cfg);
            if (err)
                goto usage_error;
            cfg.single_socket = true;
            break;
        case 'h':
            print_help(argv[0]);
            return EXIT_SUCCESS;
        case '?':
        default:
            goto usage_error;
        }
    }

    /* validate options */
    if (cfg.single_socket)
        if (cfg.show_connected || cfg.show_listening ||
            cfg.show_tcp || cfg.show_udp)
            goto usage_error;

    /* set not configured options to defaults */
    if (!cfg.single_socket)
    {
        if (!cfg.show_connected && !cfg.show_listening)
        {
            cfg.show_connected = true;
            cfg.show_listening = true;
        }
        if (!cfg.show_tcp && !cfg.show_udp)
        {
            cfg.show_tcp = true;
            cfg.show_udp = true;
        }
    }

    err = init_genl();
    if (err)
    {
        fprintf(stderr, "netlink initialization failed: %s\n", strerror(-err));
        if (err == -EADDRNOTAVAIL)
            fprintf(stderr,
                    "Please make sure that exasock kernel module (ver. @EXANIC_VERSION@ or newer) is loaded.\n");
        return EXIT_FAILURE;
    }

    if (cfg.single_socket)
        show_socket(&cfg);
    else
        show_stats(&cfg);

    cleanup_genl();

    return EXIT_SUCCESS;

usage_error:
    print_usage(argv[0]);
    return EXIT_FAILURE;
}
