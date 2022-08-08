#include "../common.h"

#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <sched.h>
#include <poll.h>
#include <time.h>

#if HAVE_NET_TSTAMP_H
#include <linux/net_tstamp.h>
#else
#include "../net_tstamp_compat.h"
#endif

#include "../kernel/consts.h"
#include "../kernel/structs.h"
#include "../lock.h"
#include "../rwlock.h"
#include "../warn.h"
#include "../structs.h"
#include "../checksum.h"
#include "../ip.h"
#include "../exanic.h"
#include "../udp_queue.h"
#include "../tcp_buffer.h"
#include "../notify.h"
#include "override.h"
#include "trace.h"
#include "common.h"
#include "../latency.h"

void __chk_fail(void);

static inline void
print_warning(struct exa_socket * restrict sock, int fd)
{
    if (sock->warn.mcast_bound)
    {
        WARNING_MCAST(fd);
        sock->warn.mcast_bound = false;
    }
}

/* Skip skip_len bytes in the iovec before copying data
 * Returns number of bytes copied */
static inline size_t
copy_to_iovec(const struct iovec * restrict iov, size_t iovcnt,
              size_t skip_len, char *buf, size_t buf_len)
{
    size_t total_len = skip_len + buf_len;
    size_t offs, i;
    char *p;

    offs = 0;
    p = buf;
    for (i = 0; i < iovcnt && offs < total_len; i++)
    {
        size_t len = iov[i].iov_len < total_len - offs
                   ? iov[i].iov_len : total_len - offs;
        size_t skip = offs < skip_len ? skip_len - offs : 0;
        if (skip < len)
        {
            memcpy(iov[i].iov_base + skip, p, len - skip);
            p += len - skip;
        }
        offs += len;
    }

    return offs - skip_len;
}

static inline bool
__recv_block_udp_ready(struct exa_socket * restrict sock, int *ret,
                       struct exa_endpoint *ep, char **pkt, size_t *pkt_len,
                       struct exa_timestamp ts[2])
{
    assert(exa_read_locked(&sock->lock));
    if (sock->state == NULL)
    {
        /* Socket no longer exists, how can this happen? */
        errno = EBADF;
        *ret = -1;
        return true;
    }
    exa_lock(&sock->state->rx_lock);
    if (exa_udp_queue_read_begin(sock, ep, pkt, pkt_len, ts) == 0)
    {
        *ret = 0;
        return true;
    }
    else if (sock->state->rx_shutdown)
    {
        *pkt = NULL;
        *pkt_len = 0;
        *ret = 0;
        return true;
    }
    exa_unlock(&sock->state->rx_lock);
    return false;
}

/* Block until data is available in the UDP receive buffer
 * On entry, socket lock is held
 * On success, returns 0 with socket rx_lock and socket lock held
 * Otherwise returns -1 with only socket lock held */
static int
recv_block_udp(struct exa_socket * restrict sock, int fd, int flags,
               struct exa_endpoint *ep, char **pkt, size_t *pkt_len,
               struct exa_timestamp ts[2])
{
    bool nonblock = (flags & MSG_DONTWAIT) || (sock->flags & O_NONBLOCK);
    int ret;

    assert(sock->bound);
    assert(exa_read_locked(&sock->lock));

    do_socket_wait(sock, fd, nonblock, sock->so_rcvtimeo,
                   __recv_block_udp_ready, ret, ep, pkt, pkt_len, ts);

    return ret;
}

static inline bool
__recv_block_tcp_ready(struct exa_socket * restrict sock, int *ret,
                       char ** restrict buf1, size_t * restrict len1,
                       char ** restrict buf2, size_t * restrict len2)
{
    assert(exa_read_locked(&sock->lock));
    if (sock->state == NULL)
    {
        /* Socket no longer exists, how can this happen? */
        errno = EBADF;
        *ret = -1;
        return true;
    }
    exa_lock(&sock->state->rx_lock);
    if (exa_tcp_rx_buffer_read_begin(sock, buf1, len1, buf2, len2) == -1)
    {
        exa_unlock(&sock->state->rx_lock);
        errno = EIO;
        *ret = -1;
        return true;
    }
    else if (*len1 > 0 || *len2 > 0 || sock->state->rx_shutdown)
    {
        *ret = 0;
        return true;
    }
    else if (exa_tcp_rx_buffer_eof(sock))
    {
        if (sock->state->error == ETIMEDOUT &&
            sock->state->p.tcp.state == EXA_TCP_CLOSED)
        {
            errno = sock->state->error;
            *ret = -1;
            return true;
        }
        else
        {
            *ret = 0;
            return true;
        }
    }
    exa_unlock(&sock->state->rx_lock);
    return false;
}

/* Block until data is available in the TCP receive buffer
 * On entry, socket lock is held
 * On success, returns 0 with socket rx_lock and socket lock held
 * Otherwise returns -1 with only socket lock held */
static int
recv_block_tcp(struct exa_socket * restrict sock, int flags,
               char ** restrict buf1, size_t * restrict len1,
               char ** restrict buf2, size_t * restrict len2)
{
    bool nonblock = (flags & MSG_DONTWAIT) || (sock->flags & O_NONBLOCK);
    int ret;

    assert(sock->bound);
    assert(exa_read_locked(&sock->lock));

    do_socket_wait_tcp(sock, nonblock, sock->so_rcvtimeo,
                       __recv_block_tcp_ready, ret, buf1, len1, buf2, len2);

    return ret;
}

static ssize_t
recvfrom_udp(struct exa_socket * restrict sock, int sockfd,
             void *buf, size_t len, int flags,
             struct sockaddr *src_addr, socklen_t *addrlen)
{
    struct exa_endpoint ep;
    char *pkt;
    size_t pkt_len, data_len;

    assert(exa_read_locked(&sock->lock));

    if (!sock->bound)
    {
        errno = EINVAL;
        return -1;
    }

    /* Block until packet is available, or error
     * Returns with rx_lock held */
    if (recv_block_udp(sock, sockfd, flags, &ep, &pkt, &pkt_len, NULL) == -1)
        return -1;

    data_len = pkt_len < len ? pkt_len : len;

    /* Copy data */
    memcpy(buf, pkt, data_len);

    /* Copy address */
    if (src_addr != NULL)
    {
        struct sockaddr_in addr;

        addr.sin_family = AF_INET;
        addr.sin_port = ep.port.peer;
        addr.sin_addr.s_addr = ep.addr.peer;

        memcpy(src_addr, &addr,
               *addrlen < sizeof(addr) ? *addrlen : sizeof(addr));
        *addrlen = sizeof(addr);
    }

    /* Finished reading packet */
    if (flags & MSG_PEEK)
        exa_udp_queue_read_abort(sock);
    else
    {
        exa_udp_queue_read_end(sock);
        exa_notify_udp_read_update(sock);
    }

    exa_unlock(&sock->state->rx_lock);

    return (flags & MSG_TRUNC) ? pkt_len : data_len;
}

static ssize_t
recvfrom_tcp(struct exa_socket * restrict sock,
             void *buf, size_t len, int flags,
             struct sockaddr *src_addr, socklen_t *addrlen)
{
    char *rx_buf1, *rx_buf2;
    size_t rx_len1, rx_len2, recv_len;

    assert(exa_read_locked(&sock->lock));

    if (!sock->connected)
    {
        errno = EINVAL;
        return -1;
    }

    /* Block until packet is available, or error */
    if (recv_block_tcp(sock, flags, &rx_buf1, &rx_len1, &rx_buf2,
                       &rx_len2) == -1)
        return -1;

    if (rx_len2 == 0 || len <= rx_len1)
    {
        /* Read does not cross receive buffer wrap */
        recv_len = rx_len1 < len ? rx_len1 : len;
        memcpy(buf, rx_buf1, recv_len);
    }
    else
    {
        /* Read crosses receive buffer wrap */
        recv_len = (rx_len1 + rx_len2) < len ? (rx_len1 + rx_len2) : len;
        memcpy(buf, rx_buf1, rx_len1);
        memcpy(buf + rx_len1, rx_buf2, recv_len - rx_len1);
    }
    exa_tcp_rx_buffer_read_end(sock, (flags & MSG_PEEK) ? 0 : recv_len);
    exa_notify_tcp_read_update(sock);
    exa_unlock(&sock->state->rx_lock);

    /* Copy address */
    if (src_addr != NULL)
    {
        struct sockaddr_in addr;

        addr.sin_family = AF_INET;
        addr.sin_port = sock->bind.ip.port.peer;
        addr.sin_addr.s_addr = sock->bind.ip.addr.peer;

        memcpy(src_addr, &addr,
               *addrlen < sizeof(addr) ? *addrlen : sizeof(addr));
        *addrlen = sizeof(addr);
    }

    return recv_len;
}

static ssize_t
recvfrom_bypass(struct exa_socket * restrict sock, int sockfd,
                void *buf, size_t len, int flags,
                struct sockaddr *src_addr, socklen_t *addrlen)
{
    assert(exa_read_locked(&sock->lock));

    if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
        return recvfrom_udp(sock, sockfd, buf, len, flags, src_addr, addrlen);
    else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
        return recvfrom_tcp(sock, buf, len, flags, src_addr, addrlen);
    else
    {
        errno = EINVAL;
        return -1;
    }
}

__attribute__((visibility("default")))
ssize_t
recv(int sockfd, void *buf, size_t len, int flags)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    ssize_t ret;

    TRACE_CALL("recv");
    TRACE_ARG(INT, sockfd);
    TRACE_FLUSH();

    LATENCY_START_POINT(6);
    if (sock == NULL)
        ret = LIBC(recv, sockfd, buf, len, flags);
    else
    {
        exa_read_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            print_warning(sock, sockfd);
            exa_read_unlock(&sock->lock);
            ret = LIBC(recv, sockfd, buf, len, flags);
        }
        else
        {
            ret = recvfrom_bypass(sock, sockfd, buf, len, flags, NULL, NULL);
            exa_read_unlock(&sock->lock);
        }
    }
    LATENCY_END_POINT(6);

    TRACE_ARG(BUF, buf, ret);
    TRACE_ARG(LONG, len);
    TRACE_LAST_ARG(BITS, flags, msg_flags);
    TRACE_RETURN(LONG, ret);

    return ret;
}

__attribute__((visibility("default")))
ssize_t
__recv_chk(int sockfd, void *buf, size_t len, size_t buflen, int flags)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    ssize_t ret;

    TRACE_CALL("__recv_chk");
    TRACE_ARG(INT, sockfd);
    TRACE_FLUSH();

    if (buflen < len)
        __chk_fail();

    if (sock == NULL)
        ret = LIBC(recv, sockfd, buf, len, flags);
    else
    {
        exa_read_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            print_warning(sock, sockfd);
            exa_read_unlock(&sock->lock);
            ret = LIBC(recv, sockfd, buf, len, flags);
        }
        else
        {
            ret = recvfrom_bypass(sock, sockfd, buf, len, flags, NULL, NULL);
            exa_read_unlock(&sock->lock);
        }
    }

    TRACE_ARG(BUF, buf, ret);
    TRACE_ARG(LONG, len);
    TRACE_ARG(LONG, buflen);
    TRACE_LAST_ARG(BITS, flags, msg_flags);
    TRACE_RETURN(LONG, ret);

    return ret;
}

__attribute__((visibility("default")))
ssize_t
recvfrom(int sockfd, void *buf, size_t len, int flags,
         struct sockaddr *src_addr, socklen_t *addrlen)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    ssize_t ret;

    TRACE_CALL("recvfrom");
    TRACE_ARG(INT, sockfd);
    TRACE_FLUSH();

    if (sock == NULL)
        ret = LIBC(recvfrom, sockfd, buf, len, flags, src_addr, addrlen);
    else
    {
        exa_read_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            print_warning(sock, sockfd);
            exa_read_unlock(&sock->lock);
            ret = LIBC(recvfrom, sockfd, buf, len, flags, src_addr, addrlen);
        }
        else
        {
            ret = recvfrom_bypass(sock, sockfd, buf, len, flags, src_addr,
                                  addrlen);
            exa_read_unlock(&sock->lock);
        }
    }

    TRACE_ARG(BUF, buf, ret);
    TRACE_ARG(LONG, len);
    TRACE_ARG(BITS, flags, msg_flags);
    TRACE_ARG(SOCKADDR_PTR, src_addr);
    TRACE_LAST_ARG(INT_PTR, addrlen);
    TRACE_RETURN(LONG, ret);

    return ret;
}

__attribute__((visibility("default")))
ssize_t
__recvfrom_chk(int sockfd, void *buf, size_t len, size_t buflen,
               int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    ssize_t ret;

    TRACE_CALL("__recvfrom_chk");
    TRACE_ARG(INT, sockfd);
    TRACE_FLUSH();

    if (buflen < len)
        __chk_fail();

    if (sock == NULL)
        ret = LIBC(recvfrom, sockfd, buf, len, flags, src_addr, addrlen);
    else
    {
        exa_read_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            print_warning(sock, sockfd);
            exa_read_unlock(&sock->lock);
            ret = LIBC(recvfrom, sockfd, buf, len, flags, src_addr, addrlen);
        }
        else
        {
            ret = recvfrom_bypass(sock, sockfd, buf, len, flags, src_addr,
                                  addrlen);
            exa_read_unlock(&sock->lock);
        }
    }

    TRACE_ARG(BUF, buf, ret);
    TRACE_ARG(LONG, len);
    TRACE_ARG(LONG, buflen);
    TRACE_ARG(BITS, flags, msg_flags);
    TRACE_ARG(SOCKADDR_PTR, src_addr);
    TRACE_LAST_ARG(INT_PTR, addrlen);
    TRACE_RETURN(LONG, ret);

    return ret;
}

static ssize_t
recvmsg_udp(struct exa_socket * restrict sock, int sockfd,
            struct msghdr *msg, int flags)
{
    struct exa_endpoint ep;
    struct exa_timestamp ts[2];
    char *pkt;
    size_t pkt_len, recv_len;
    int msg_flags = 0;

    assert(exa_read_locked(&sock->lock));

    /* Block until packet is available, or error */
    if (recv_block_udp(sock, sockfd, flags, &ep, &pkt, &pkt_len,
                       sock->report_timestamp ? ts : NULL) == -1)
        return -1;

    /* Copy data */
    recv_len = copy_to_iovec(msg->msg_iov, msg->msg_iovlen, 0, pkt, pkt_len);

    if (recv_len < pkt_len)
        msg_flags |= MSG_TRUNC;

    /* Copy address */
    if (msg->msg_name != NULL)
    {
        struct sockaddr_in addr;

        addr.sin_family = AF_INET;
        addr.sin_port = ep.port.peer;
        addr.sin_addr.s_addr = ep.addr.peer;

        memcpy(msg->msg_name, &addr, msg->msg_namelen < sizeof(addr)
               ? msg->msg_namelen : sizeof(addr));
    }

    /* Populate ancillary data */
    if (msg->msg_control != NULL)
    {
        size_t offs = 0;

        if (sock->so_timestamp)
        {
            /* SO_TIMESTAMP control message */
            if (offs + CMSG_LEN(sizeof(struct timeval)) <= msg->msg_controllen)
            {
                struct cmsghdr *cmsg = (struct cmsghdr *)
                    (msg->msg_control + offs);
                struct timeval *tv = (struct timeval *)
                    (msg->msg_control + offs + sizeof(struct cmsghdr));

                cmsg->cmsg_len = CMSG_LEN(sizeof(struct timeval));
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SO_TIMESTAMP;

                tv->tv_sec = ts[0].sec;
                tv->tv_usec = ts[0].nsec / 1000;

                offs += CMSG_LEN(sizeof(struct timeval));
            }
            else
                msg_flags |= MSG_CTRUNC;
        }

        if (sock->so_timestampns)
        {
            /* SO_TIMESTAMPNS control message */
            if (offs + CMSG_LEN(sizeof(struct timespec)) <= msg->msg_controllen)
            {
                struct cmsghdr *cmsg = (struct cmsghdr *)
                    (msg->msg_control + offs);
                struct timespec *tv = (struct timespec *)
                    (msg->msg_control + offs + sizeof(struct cmsghdr));

                cmsg->cmsg_len = CMSG_LEN(sizeof(struct timespec));
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SO_TIMESTAMPNS;

                tv->tv_sec = ts[0].sec;
                tv->tv_nsec = ts[0].nsec;

                offs += CMSG_LEN(sizeof(struct timespec));
            }
            else
                msg_flags |= MSG_CTRUNC;
        }

        if (((SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE) &
                    sock->so_timestamping) != 0)
        {
            if (offs + CMSG_LEN(sizeof(struct timespec) * 3) <=
                    msg->msg_controllen)
            {
                struct cmsghdr *cmsg = (struct cmsghdr *)
                    (msg->msg_control + offs);
                struct timespec *tv = (struct timespec *)
                    (msg->msg_control + offs + sizeof(struct cmsghdr));

                cmsg->cmsg_len = CMSG_LEN(sizeof(struct timespec) * 3);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_TIMESTAMPING;

                memset(tv, 0, sizeof(struct timespec) * 3);

                if ((SOF_TIMESTAMPING_SOFTWARE & sock->so_timestamping) != 0)
                {
                    tv[0].tv_sec = ts[0].sec;
                    tv[0].tv_nsec = ts[0].nsec;
                }

                if ((SOF_TIMESTAMPING_RAW_HARDWARE &
                            sock->so_timestamping) != 0)
                {
                    tv[2].tv_sec = ts[1].sec;
                    tv[2].tv_nsec = ts[1].nsec;
                }

                offs += CMSG_LEN(sizeof(struct timespec) * 3);
            }
            else
                msg_flags |= MSG_CTRUNC;
        }

        msg->msg_controllen = offs;
    }

    msg->msg_flags = msg_flags;

    /* Finished reading packet */
    if (flags & MSG_PEEK)
        exa_udp_queue_read_abort(sock);
    else
    {
        exa_udp_queue_read_end(sock);
        exa_notify_udp_read_update(sock);
    }

    exa_unlock(&sock->state->rx_lock);

    return (flags & MSG_TRUNC) ? pkt_len : recv_len;
}

static ssize_t
recvmsg_tcp(struct exa_socket * restrict sock, struct msghdr *msg, int flags)
{
    char *rx_buf1, *rx_buf2;
    size_t rx_len1, rx_len2, recv_len;

    assert(exa_read_locked(&sock->lock));

    if (!sock->connected)
    {
        errno = EINVAL;
        return -1;
    }

    /* Block until packet is available, or error */
    if (recv_block_tcp(sock, flags, &rx_buf1, &rx_len1, &rx_buf2,
                       &rx_len2) == -1)
        return -1;

    /* Copy data */
    recv_len = copy_to_iovec(msg->msg_iov, msg->msg_iovlen, 0, rx_buf1,
                             rx_len1);
    if (rx_len2 != 0 && recv_len == rx_len1)
        recv_len += copy_to_iovec(msg->msg_iov, msg->msg_iovlen, rx_len1,
                                rx_buf2, rx_len2);

    /* Copy address */
    if (msg->msg_name != NULL)
    {
        struct sockaddr_in addr;

        addr.sin_family = AF_INET;
        addr.sin_port = sock->bind.ip.port.peer;
        addr.sin_addr.s_addr = sock->bind.ip.addr.peer;

        memcpy(msg->msg_name, &addr, msg->msg_namelen < sizeof(addr)
               ? msg->msg_namelen : sizeof(addr));
    }

    /* TODO: Populate ancillary data */
    if (msg->msg_control != NULL)
        msg->msg_controllen = 0;

    /* Populate flags */
    msg->msg_flags = 0;

    exa_tcp_rx_buffer_read_end(sock, (flags & MSG_PEEK) ? 0 : recv_len);
    exa_notify_tcp_read_update(sock);
    exa_unlock(&sock->state->rx_lock);

    return recv_len;
}

static ssize_t
recvmsg_bypass(struct exa_socket * restrict sock, int sockfd,
               struct msghdr *msg, int flags)
{
    assert(exa_read_locked(&sock->lock));

    if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
        return recvmsg_udp(sock, sockfd, msg, flags);
    else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
        return recvmsg_tcp(sock, msg, flags);
    else
    {
        errno = EINVAL;
        return -1;
    }
}

__attribute__((visibility("default")))
ssize_t
recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    ssize_t ret;

    TRACE_CALL("recvmsg");
    TRACE_ARG(INT, sockfd);
    TRACE_FLUSH();

    if (sock == NULL)
        ret = LIBC(recvmsg, sockfd, msg, flags);
    else
    {
        exa_read_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            print_warning(sock, sockfd);
            exa_read_unlock(&sock->lock);
            ret = LIBC(recvmsg, sockfd, msg, flags);
        }
        else
        {
            ret = recvmsg_bypass(sock, sockfd, msg, flags);
            exa_read_unlock(&sock->lock);
        }
    }

    TRACE_ARG(MSG_PTR, msg, ret);
    TRACE_LAST_ARG(BITS, flags, msg_flags);
    TRACE_RETURN(LONG, ret);

    return ret;
}

static ssize_t
read_udp(struct exa_socket * restrict sock, int fd, void *buf, size_t count)
{
    char *pkt;
    size_t pkt_len, data_len;

    assert(exa_read_locked(&sock->lock));

    /* Block until packet is available, or error */
    if (recv_block_udp(sock, fd, 0, NULL, &pkt, &pkt_len, NULL) == -1)
        return -1;

    data_len = pkt_len < count ? pkt_len : count;

    /* Copy data */
    memcpy(buf, pkt, data_len);

    /* Remainder of packet is discarded */
    exa_udp_queue_read_end(sock);
    exa_notify_udp_read_update(sock);
    exa_unlock(&sock->state->rx_lock);

    return data_len;
}

static ssize_t
read_tcp(struct exa_socket * restrict sock, void *buf, size_t count)
{
    char *rx_buf1, *rx_buf2;
    size_t rx_len1, rx_len2, data_len;

    assert(exa_read_locked(&sock->lock));

    if (!sock->connected)
    {
        errno = ENOTCONN;
        return -1;
    }

    if (count == 0)
        return 0;

    /* Block until data is available, or error */
    if (recv_block_tcp(sock, 0, &rx_buf1, &rx_len1, &rx_buf2,
                       &rx_len2) == -1)
        return -1;

    if (rx_len2 == 0 || count <= rx_len1)
    {
        /* Read does not cross receive buffer wrap */
        data_len = rx_len1 < count ? rx_len1 : count;
        memcpy(buf, rx_buf1, data_len);
    }
    else
    {
        /* Read crosses receive buffer wrap */
        data_len = (rx_len1 + rx_len2) < count ? (rx_len1 + rx_len2) : count;
        memcpy(buf, rx_buf1, rx_len1);
        memcpy(buf + rx_len1, rx_buf2, data_len - rx_len1);
    }
    exa_tcp_rx_buffer_read_end(sock, data_len);
    exa_notify_tcp_read_update(sock);
    exa_unlock(&sock->state->rx_lock);

    return data_len;
}

static ssize_t
read_bypass(struct exa_socket * restrict sock, int fd, void *buf, size_t count)
{
    assert(exa_read_locked(&sock->lock));

    if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
        return read_udp(sock, fd, buf, count);
    else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
        return read_tcp(sock, buf, count);
    else
    {
        errno = EINVAL;
        return -1;
    }
}

__attribute__((visibility("default")))
ssize_t
read(int fd, void *buf, size_t count)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);
    ssize_t ret;

    TRACE_CALL("read");
    TRACE_ARG(INT, fd);
    TRACE_FLUSH();

    if (sock == NULL)
        ret = LIBC(read, fd, buf, count);
    else
    {
        exa_read_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            print_warning(sock, fd);
            exa_read_unlock(&sock->lock);
            ret = LIBC(read, fd, buf, count);
        }
        else
        {
            ret = read_bypass(sock, fd, buf, count);
            exa_read_unlock(&sock->lock);
        }
    }

    TRACE_ARG(BUF, buf, ret);
    TRACE_LAST_ARG(LONG, count);
    TRACE_RETURN(LONG, ret);

    return ret;
}

__attribute__((visibility("default")))
ssize_t
__read_chk(int fd, void *buf, size_t nbytes, size_t buflen)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);
    ssize_t ret;

    TRACE_CALL("__read_chk");
    TRACE_ARG(INT, fd);
    TRACE_FLUSH();

    if (buflen < nbytes)
        __chk_fail();

    if (sock == NULL)
        ret = LIBC(read, fd, buf, nbytes);
    else
    {
        exa_read_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            print_warning(sock, fd);
            exa_read_unlock(&sock->lock);
            ret = LIBC(read, fd, buf, nbytes);
        }
        else
        {
            ret = read_bypass(sock, fd, buf, nbytes);
            exa_read_unlock(&sock->lock);
        }
    }

    TRACE_ARG(BUF, buf, ret);
    TRACE_ARG(LONG, nbytes);
    TRACE_LAST_ARG(LONG, buflen);
    TRACE_RETURN(LONG, ret);

    return ret;
}

static ssize_t
readv_udp(struct exa_socket * restrict sock, int fd, const struct iovec *iov,
          size_t iovcnt)
{
    char *pkt;
    size_t pkt_len, data_len;

    assert(exa_read_locked(&sock->lock));

    /* Block until packet is available, or error */
    if (recv_block_udp(sock, fd, 0, NULL, &pkt, &pkt_len, NULL) == -1)
        return -1;

    /* Copy data */
    data_len = copy_to_iovec(iov, iovcnt, 0, pkt, pkt_len);

    /* Remainder of packet is discarded */
    exa_udp_queue_read_end(sock);
    exa_notify_udp_read_update(sock);
    exa_unlock(&sock->state->rx_lock);

    return data_len;
}

static ssize_t
readv_tcp(struct exa_socket * restrict sock, const struct iovec *iov,
          size_t iovcnt)
{
    char *rx_buf1, *rx_buf2;
    size_t rx_len1, rx_len2, data_len;

    assert(exa_read_locked(&sock->lock));

    if (!sock->connected)
    {
        errno = ENOTCONN;
        return -1;
    }

    /* Block until data is available, or error */
    if (recv_block_tcp(sock, 0, &rx_buf1, &rx_len1, &rx_buf2,
                       &rx_len2) == -1)
        return -1;

    /* Copy data */
    data_len = copy_to_iovec(iov, iovcnt, 0, rx_buf1, rx_len1);
    if (rx_len2 != 0 && data_len == rx_len1)
        data_len += copy_to_iovec(iov, iovcnt, rx_len1, rx_buf2, rx_len2);

    exa_tcp_rx_buffer_read_end(sock, data_len);
    exa_notify_tcp_read_update(sock);
    exa_unlock(&sock->state->rx_lock);

    return data_len;
}

static ssize_t
readv_bypass(struct exa_socket * restrict sock, int fd, const struct iovec *iov,
             size_t iovcnt)
{
    assert(exa_read_locked(&sock->lock));

    if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
        return readv_udp(sock, fd, iov, iovcnt);
    else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
        return readv_tcp(sock, iov, iovcnt);
    else
    {
        errno = EINVAL;
        return -1;
    }
}

__attribute__((visibility("default")))
ssize_t
readv(int fd, const struct iovec *iov, int iovcnt)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);
    ssize_t ret;

    TRACE_CALL("readv");
    TRACE_ARG(INT, fd);
    TRACE_FLUSH();

    if (sock == NULL)
        ret = LIBC(readv, fd, iov, iovcnt);
    else
    {
        exa_read_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            print_warning(sock, fd);
            exa_read_unlock(&sock->lock);
            ret = LIBC(readv, fd, iov, iovcnt);
        }
        else
        {
            ret = readv_bypass(sock, fd, iov, iovcnt);
            exa_read_unlock(&sock->lock);
        }
    }

    TRACE_ARG(IOVEC_ARRAY, iov, iovcnt, ret);
    TRACE_LAST_ARG(INT, iovcnt);
    TRACE_RETURN(LONG, ret);

    return ret;
}

#ifdef HAVE_RECVMMSG
__attribute__((visibility("default")))
int
recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
         int flags,
#if RECVMMSG_HAS_CONST_TIMESPEC
         const
#endif
         struct timespec *timeout)
{
    struct exa_socket *restrict sock = exa_socket_get(sockfd);
    struct timespec t_max, t_now;
    int ret = 0;
    unsigned int i = 0;

    TRACE_CALL("recvmmsg");
    TRACE_ARG(INT, sockfd);
    TRACE_FLUSH();

    if (sock == NULL)
    {
        ret = LIBC(recvmmsg, sockfd, msgvec, vlen, flags, timeout);
        goto out;
    }

    if (timeout != NULL)
    {
        if (!ts_vld(timeout))
        {
            errno = EINVAL;
            ret = -1;
            goto out;
        }

        /* configure timeout */
        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t_max) == -1)
        {
            errno = EAGAIN;
            ret = -1;
            goto out;
        }
        ts_add(&t_max, timeout);
    }

    if (sock->bypass_state != EXA_BYPASS_ACTIVE)
    {
        print_warning(sock, sockfd);
        ret = LIBC(recvmmsg, sockfd, msgvec, vlen, flags, timeout);
        goto out;
    }

    exa_read_lock(&sock->lock);
    for (i = 0; i < vlen; i++)
    {
        ret = recvmsg_bypass(sock, sockfd, &msgvec[i].msg_hdr,
                             flags & ~MSG_WAITFORONE);
        if (ret == -1)
        {
            /*
             * Per Linux behaviour, if at least one message has been received when
             * an error occurs, return it.  If some permanent error has occurred
             * such as the socket no longer being valid, this error will be returned
             * on the next call to recvmmsg.
             */
            if (i > 0)
                ret = i;
            goto out_unlock;
        }

        msgvec[i].msg_len = ret;
        ret = i + 1;

        /* check timeout */
        if (timeout != NULL)
        {
            if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t_now) == -1)
            {
                errno = EAGAIN;
                ret = -1;
                goto out_unlock;
            }

            /*
             * Stripping the const-ness of this timespec is a little nasty, but
             * Linux does not define it as const (see net/socket.c), and changes the
             * pointee (by setting it to how far away you were from the timeout).
             *
             * This is fine so far, but glibc versions before 2.24 define the
             * timespec as const - so, to maintain compatibility, we declare it as
             * const and cast it away here.
             */
            ts_sub(&t_max, &t_now, (struct timespec*)timeout);

            if (ts_after_eq(&t_now, &t_max))
                goto out_unlock;
        }

        if (flags & MSG_WAITFORONE)
            flags |= MSG_DONTWAIT;
    }

 out_unlock:
    exa_read_unlock(&sock->lock);

 out:
    TRACE_ARG(MMSG_PTR, msgvec, ret);
    TRACE_ARG(UNSIGNED, vlen);
    TRACE_ARG(BITS, flags, msg_flags);
    TRACE_LAST_ARG(TIMESPEC_PTR, timeout);
    TRACE_RETURN(INT, ret);

    return ret;
}
#endif
