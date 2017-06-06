#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <arpa/inet.h>

#include <exasock/exasock-genl.h>

#define EXASOCK_STAT_VERSION "0.01"

#define EXASOCK_STAT_ADDR_BUF_SIZE 24

struct exasock_stat_config
{
    bool show_connected;
    bool show_listening;
    bool show_tcp;
    bool show_udp;
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
        return "";
    }
}

static inline char * print_sock_addr(char buf[], struct in_addr ip,
                                     uint16_t port)
{
    if (port == 0)
        snprintf(buf, EXASOCK_STAT_ADDR_BUF_SIZE, "%s:*",
                 (ip.s_addr == 0) ? "*" : inet_ntoa(ip));
    else
        snprintf(buf, EXASOCK_STAT_ADDR_BUF_SIZE, "%s:%i",
                 (ip.s_addr == 0) ? "*" : inet_ntoa(ip), ntohs(port));
    return buf;
}

static void print_socket_info(struct nlattr *attr_sock[],
                              enum exasock_genl_sock_type sock_type)
{
    char buf_la[EXASOCK_STAT_ADDR_BUF_SIZE];
    char buf_pa[EXASOCK_STAT_ADDR_BUF_SIZE];
    struct in_addr local_ip;
    struct in_addr peer_ip;
    uint16_t local_port;
    uint16_t peer_port;
    uint32_t recv_q;
    uint32_t send_q;
    uint8_t state;

    local_ip.s_addr = nla_get_u32(attr_sock[EXASOCK_GENL_A_SOCK_LOCAL_ADDR]);
    peer_ip.s_addr = nla_get_u32(attr_sock[EXASOCK_GENL_A_SOCK_PEER_ADDR]);
    local_port = nla_get_u16(attr_sock[EXASOCK_GENL_A_SOCK_LOCAL_PORT]);
    peer_port = nla_get_u16(attr_sock[EXASOCK_GENL_A_SOCK_PEER_PORT]);
    recv_q = nla_get_u32(attr_sock[EXASOCK_GENL_A_SOCK_RECV_Q]);
    send_q = nla_get_u32(attr_sock[EXASOCK_GENL_A_SOCK_SEND_Q]);
    state = nla_get_u8(attr_sock[EXASOCK_GENL_A_SOCK_STATE]);

    printf(" %-8s | %-8i | %-8i | %-24s | %-24s | %-16s\n",
           print_sock_proto(sock_type),                     /* Proto */
           recv_q,                                          /* Recv-Q */
           send_q,                                          /* Send-Q */
           print_sock_addr(buf_la, local_ip, local_port),   /* Local Address */
           print_sock_addr(buf_pa, peer_ip, peer_port),     /* Foreign Address */
           print_sock_state(state));                        /* State */
}

static int get_sockets_cb(struct nl_msg *msg, void *arg)
{
    enum exasock_genl_sock_type *sock_type = arg;
    struct nlattr *attr[EXASOCK_GENL_A_MAX + 1];
    struct nlattr *attr_sockelem;
    struct nlattr *attr_sock[EXASOCK_GENL_A_SOCK_MAX + 1];
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
        err = nla_parse_nested(attr_sock, EXASOCK_GENL_A_SOCK_MAX,
                               attr_sockelem, NULL);
        if (err)
        {
            fprintf(stderr,
                    "failed to parse netlink nested attributes (%s: err=%i)\n",
                    __func__, err);
            return NL_SKIP;
        }
        print_socket_info(attr_sock, *sock_type);
    }

    return NL_SKIP;
}

static int get_sockets(enum exasock_genl_sock_type sock_type)
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

static void show_tcp(struct exasock_stat_config *cfg)
{
    int err;

    if (cfg->show_listening)
    {
        err = get_sockets(EXASOCK_GENL_SOCKTYPE_TCP_LISTEN);
        if (err)
            goto get_sockets_failure;
    }
    if (cfg->show_connected)
    {
        err = get_sockets(EXASOCK_GENL_SOCKTYPE_TCP_CONN);
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
        err = get_sockets(EXASOCK_GENL_SOCKTYPE_UDP_LISTEN);
        if (err)
            goto get_sockets_failure;
    }
    if (cfg->show_connected)
    {
        err = get_sockets(EXASOCK_GENL_SOCKTYPE_UDP_CONN);
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
    printf(" %-8s | %-8s | %-8s | %-24s | %-24s | %-16s\n",
            "Proto", "Recv-Q", "Send-Q", "Local Address", "Foreign Address", "State");

    if (cfg->show_tcp)
        show_tcp(cfg);
    if (cfg->show_udp)
        show_udp(cfg);
    printf("\n");
}

static void print_usage(char *name)
{
    fprintf(stderr, "\nexasock-stat version %s\n", EXASOCK_STAT_VERSION);
    fprintf(stderr, "Display ExaNIC Sockets accelerated connections\n");
    fprintf(stderr, "\nUsage:\n");
    fprintf(stderr, "   %s [-cltu]\n", name);
    fprintf(stderr, "   %s [-h]\n", name);
    fprintf(stderr, "    -c, --connected    display connected sockets (default: all)\n");
    fprintf(stderr, "    -l, --listening    display listening server sockets\n");
    fprintf(stderr, "    -t, --tcp          display TCP sockets (default: all)\n");
    fprintf(stderr, "    -u, --udp          display UDP sockets\n");
    fprintf(stderr, "    -h, --help         display this usage info\n");
    fprintf(stderr, "\nOutput:\n");
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
    fprintf(stderr, "\n");
}

static struct option longopts[] =
{
    {"connected", 0, 0, 'c'},
    {"listening", 0, 0, 'l'},
    {"tcp",       0, 0, 't'},
    {"udp",       0, 0, 'u'},
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

    while ((opt = getopt_long(argc, argv, ":cltuh", longopts, NULL)) != -1)
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
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        case '?':
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    /* set not configured options to defaults */
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

    err = init_genl();
    if (err)
    {
        fprintf(stderr, "netlink initialization failed: %s\n", strerror(-err));
        return EXIT_FAILURE;
    }

    show_stats(&cfg);

    cleanup_genl();

    return EXIT_SUCCESS;
}
