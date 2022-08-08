#ifndef EXASOCK_KERNEL_API_H
#define EXASOCK_KERNEL_API_H

#define EXASOCK_DEVICE "/dev/exasock"
#define EXASOCK_API_VERSION 21

#define EXASOCK_IOCTL_TYPE          'x'
#define EXASOCK_IOCTL_SOCKET        _IOW(EXASOCK_IOCTL_TYPE, 0x50, int)
#define EXASOCK_IOCTL_SETSOCKOPT    _IOW(EXASOCK_IOCTL_TYPE, 0x51, \
                                         struct exasock_opt_request)
#define EXASOCK_IOCTL_GETSOCKOPT    _IOWR(EXASOCK_IOCTL_TYPE, 0x52, \
                                          struct exasock_opt_request)
#define EXASOCK_IOCTL_BIND          _IOWR(EXASOCK_IOCTL_TYPE, 0x54, \
                                          struct exasock_endpoint)
#define EXASOCK_IOCTL_CONNECT       _IOWR(EXASOCK_IOCTL_TYPE, 0x55, \
                                          struct exasock_endpoint)
#define EXASOCK_IOCTL_ATE_ENABLE    _IOW(EXASOCK_IOCTL_TYPE, 0x58, int)
#define EXASOCK_IOCTL_ATE_INIT      _IO(EXASOCK_IOCTL_TYPE, 0x59)
#define EXASOCK_IOCTL_DST_QUEUE     _IOWR(EXASOCK_IOCTL_TYPE, 0x5c, \
                                          struct exasock_dst_request)
#define EXASOCK_IOCTL_UPDATE        _IOW(EXASOCK_IOCTL_TYPE, 0x5d, \
                                         struct exasock_endpoint)
#define EXASOCK_IOCTL_EPOLL_CREATE  _IO(EXASOCK_IOCTL_TYPE, 0x5e)
#define EXASOCK_IOCTL_EPOLL_CTL     _IOW(EXASOCK_IOCTL_TYPE, 0x5f, \
                                         struct exasock_epoll_ctl_request)
#define EXASOCK_IOCTL_ISN_ALLOC     _IOR(EXASOCK_IOCTL_TYPE, 0x60, uint32_t)

#ifdef TCP_LISTEN_SOCKET_PROFILING
#define EXASOCK_IOCTL_LISTEN_SOCKET_PROFILE  _IOW(EXASOCK_IOCTL_TYPE, 0x61, \
                                                  struct exasock_listen_endpoint)

#endif /* TCP_LISTEN_SOCKET_PROFILING */

/* Arguments for EXASOCK_IOCTL_BIND, EXASOCK_IOCTL_CONNECT
 * and EXASOCK_IOCTL_UPDATE
 */
struct exasock_endpoint
{
    uint32_t local_addr;
    uint32_t peer_addr;
    uint16_t local_port;
    uint16_t peer_port;
};

/* Argument for EXASOCK_IOCTL_DST_QUEUE */
struct exasock_dst_request
{
    uint32_t dst_addr;
    uint32_t src_addr;
    void *ip_packet;
    size_t ip_packet_len;
};

/* Argument for EXASOCK_IOCTL_SETSOCKOPT and EXASOCK_IOCTL_GETSOCKOPT */
struct exasock_opt_request
{
    int level;
    int optname;
    char *optval;
    unsigned int optlen;
};

enum exasock_epoll_ctl_op
{
    EXASOCK_EPOLL_CTL_ADD,
    EXASOCK_EPOLL_CTL_DEL
};

/* Argument for EXASOCK_IOCTL_EPOLL_CTL */
struct exasock_epoll_ctl_request
{
    enum exasock_epoll_ctl_op op;
    int fd;
};

struct exasock_kernel_info
{
    uint32_t api_version;
    uint32_t dst_table_size;
};


#ifdef TCP_LISTEN_SOCKET_PROFILING

/* both local_addr and local_port are in network byte order */
struct exasock_listen_endpoint
{
    uint32_t local_addr;
    uint16_t local_port;
};
#endif /* TCP_LISTEN_SOCKET_PROFILING */

#define EXASOCK_OFFSET_KERNEL_INFO      0x0000000
#define EXASOCK_OFFSET_SOCKET_STATE     0x0010000
#define EXASOCK_OFFSET_DST_TABLE        0x1000000
#define EXASOCK_OFFSET_DST_USED_FLAGS   0x1800000
#define EXASOCK_OFFSET_RX_BUFFER        0x2000000
#define EXASOCK_OFFSET_TX_BUFFER        0x3000000
#define EXASOCK_OFFSET_EPOLL_STATE      0x4000000
#define EXASOCK_OFFSET_LISTEN_SOCK_PROFILE_INFO  0x5000000

#define EXASOCK_KERNEL_INFO_SIZE        0x1000
#define EXASOCK_SOCKET_STATE_SIZE       0x1000
#define EXASOCK_EPOLL_STATE_SIZE        0x1000

#endif /* EXASOCK_KERNEL_API_H */
