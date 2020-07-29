#include "../common.h"

#include <netinet/ether.h>
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
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <poll.h>
#include <time.h>

#include <exasock/socket.h>

#include "../kernel/api.h"
#include "../kernel/structs.h"
#include "../lock.h"
#include "../rwlock.h"
#include "../warn.h"
#include "../structs.h"
#include "../sockets.h"
#include "../exanic.h"
#include "../sys.h"
#include "../dst.h"
#include "../udp_queue.h"
#include "../tcp_buffer.h"
#include "../notify.h"
#include "override.h"
#include "trace.h"
#include "common.h"

/* Calculate total length of iovec */
static inline size_t
__iovec_total_len(const struct iovec *iov, size_t iovcnt)
{
    size_t len = 0, i;
    for (i = 0; i < iovcnt; i++)
        len += iov[i].iov_len;
    return len;
}

static ssize_t
sendto_bypass_udp(struct exa_socket * restrict sock, int sockfd,
                  const void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen)
{
    bool warm = !!(flags & MSG_EXA_WARM);
    ssize_t ret;

    assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
    assert(sock->domain == AF_INET);
    assert(sock->type == SOCK_DGRAM);
    assert(exa_read_locked(&sock->lock));

    if (sock->connected && dest_addr != NULL)
    {
        errno = EISCONN;
        return -1;
    }

    exa_lock(&sock->state->tx_lock);

    if (dest_addr != NULL)
    {
        struct sockaddr_in *in_addr = (struct sockaddr_in *)dest_addr;

        if (addrlen < sizeof(struct sockaddr_in))
        {
            errno = EINVAL;
            exa_unlock(&sock->state->tx_lock);
            return -1;
        }

        if (exa_socket_udp_target(sock, in_addr->sin_addr.s_addr,
                                  in_addr->sin_port) == -1)
        {
            exa_unlock(&sock->state->tx_lock);
            return -1;
        }
    }

    ret = exanic_udp_send(sock, buf, len, warm);
    exa_unlock(&sock->state->tx_lock);
    return ret;
}

static inline bool
__sendto_bypass_tcp_ready(struct exa_socket * restrict sock, ssize_t *ret,
                          int dummy)
{
    return exanic_tcp_writeable(sock);
}

static ssize_t
sendto_bypass_tcp(struct exa_socket * restrict sock, int sockfd,
                  const void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen)
{
    bool nonblock = (flags & MSG_DONTWAIT) || (sock->flags & O_NONBLOCK);
    bool warm = !!(flags & MSG_EXA_WARM);
    ssize_t nwritten, ret;

    assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
    assert(sock->domain == AF_INET);
    assert(sock->type == SOCK_STREAM);
    assert(exa_read_locked(&sock->lock));

    if (!sock->connected)
    {
        errno = ENOTCONN;
        return -1;
    }

    /* Provided address in dest_addr is ignored */

    nwritten = 0;
    while (true)
    {
        /* Send as much data as we can */
        exa_lock(&sock->state->tx_lock);
        while (nwritten < len)
        {
            ret = exanic_tcp_send(sock, buf + nwritten, len - nwritten, warm);
            if (ret <= 0)
                break;
            nwritten += ret;
        }
        exa_unlock(&sock->state->tx_lock);

        /* Exit loop if we have sent everything */
        if (nwritten >= len)
            break;

        if (ret == -1)
        {
            /* FIXME: Emit signal */
            if (sock->state->error == ETIMEDOUT)
                errno = sock->state->error;
            else
                errno = EPIPE;
            break;
        }

        exa_notify_tcp_write_fake_unready(sock);

        /* Wait until socket is ready for writing */
        do_socket_wait_tcp(sock, nonblock, sock->so_sndtimeo,
                           __sendto_bypass_tcp_ready, ret, 0);

        /* NOTE: Socket may have disappeared while waiting! */
        if (ret == -1)
            break;
    }

    return (nwritten > 0 || len == 0) ? nwritten : -1;
}

static ssize_t
sendto_bypass(struct exa_socket * restrict sock, int sockfd,
              const void *buf, size_t len, int flags,
              const struct sockaddr *dest_addr, socklen_t addrlen)
{
    assert(exa_read_locked(&sock->lock));
    assert(sock->bypass_state == EXA_BYPASS_ACTIVE);

    if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
        return sendto_bypass_udp(sock, sockfd, buf, len, flags,
                                 dest_addr, addrlen);
    else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
        return sendto_bypass_tcp(sock, sockfd, buf, len, flags,
                                 dest_addr, addrlen);
    else
    {
        errno = EINVAL;
        return -1;
    }
}

__attribute__((visibility("default")))
ssize_t
send(int sockfd, const void *buf, size_t len, int flags)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    ssize_t ret;

    TRACE_CALL("send");
    TRACE_ARG(INT, sockfd);
    TRACE_ARG(BUF, buf, len);
    TRACE_ARG(LONG, len);
    TRACE_LAST_ARG(BITS, flags, msg_flags);
    TRACE_FLUSH();

    if (sock == NULL)
    {
        if (flags & MSG_EXA_WARM)
        {
            WARNING_MSGWARM(sockfd);
            ret = len;
        }
        else
        {
            ret = LIBC(send, sockfd, buf, len, flags);
        }
    }
    else
    {
        exa_read_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            exa_read_unlock(&sock->lock);
            if (flags & MSG_EXA_WARM)
            {
                WARNING_MSGWARM(sockfd);
                ret = len;
            }
            else
            {
                ret = LIBC(send, sockfd, buf, len, flags);
            }
        }
        else if (sock->connected)
        {
            ret = sendto_bypass(sock, sockfd, buf, len, flags, NULL, 0);
            exa_read_unlock(&sock->lock);
        }
        else
        {
            exa_read_unlock(&sock->lock);
            errno = ENOTCONN;
            ret = -1;
        }
    }

    TRACE_RETURN(LONG, ret);
    return ret;
}

static int
auto_bind(struct exa_socket * restrict sock, int sockfd,
          const struct sockaddr *addr, socklen_t addrlen)
{
    struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
    int ret;

    assert(exa_write_locked(&sock->lock));

    if (sock->bypass_state == EXA_BYPASS_ACTIVE)
    {
        /* Someone beat us to it - this is possible because we test
         * sock->bypass before acquiring the lock */
        return 0;
    }

    if (override_unsafe)
    {
        /* Inside a libc function that is known to be incompatible with
         * bypass sockets */
        return 0;
    }

    if (sock->bypass_state <= EXA_BYPASS_INACTIVE)
    {
        /* Bypass is either disabled by default or permanently disabled
         * for this socket */
        return 0;
    }

    if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
    {
        /* Auto-bind if sending to multicast address and IP_MULTICAST_IF
         * is set to an ExaNIC interface, or if route output is via an
         * ExaNIC interface */
        if ((IN_MULTICAST(ntohl(in_addr->sin_addr.s_addr)) &&
                sock->ip_multicast_if != htonl(INADDR_ANY) &&
                exanic_ip_find(sock->ip_multicast_if)) ||
            exa_dst_via_exanic(in_addr->sin_addr.s_addr,
                               sock->bind.ip.addr.local))
        {
            /* Put socket into bypass mode.
             * On successful return we hold rx_lock and tx_lock */
            ret = exa_socket_enable_bypass(sock);
            if (ret == -1)
                return -1;

            exa_unlock(&sock->state->rx_lock);
            exa_unlock(&sock->state->tx_lock);

            /* Bind the socket to an auto assigned port */
            ret = exa_socket_udp_bind(sock, 0, 0);
            return ret;
        }
    }

    /* Falls through to native */
    return 0;
}

__attribute__((visibility("default")))
ssize_t
sendto(int sockfd, const void *buf, size_t len, int flags,
       const struct sockaddr *dest_addr, socklen_t addrlen)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    ssize_t ret;

    TRACE_CALL("sendto");
    TRACE_ARG(INT, sockfd);
    TRACE_ARG(BUF, buf, len);
    TRACE_ARG(LONG, len);
    TRACE_ARG(BITS, flags, msg_flags);
    TRACE_ARG(SOCKADDR_PTR, dest_addr);
    TRACE_LAST_ARG(INT, addrlen);
    TRACE_FLUSH();

    if (sock == NULL)
    {
        if (flags & MSG_EXA_WARM)
        {
            WARNING_MSGWARM(sockfd);
            ret = len;
        }
        else
        {
            ret = LIBC(sendto, sockfd, buf, len, flags, dest_addr, addrlen);
        }
    }
    else
    {
        if (sock->bypass_state != EXA_BYPASS_ACTIVE && dest_addr != NULL)
        {
            exa_write_lock(&sock->lock);

            /* Auto-bind and enable bypass based on route */
            /* TODO: Only try this once for native sockets */
            if (auto_bind(sock, sockfd, dest_addr, addrlen) != 0)
            {
                exa_write_unlock(&sock->lock);
                TRACE_RETURN(INT, -1);
                return -1;
            }

            /* Convert write lock to read lock */
            exa_rwlock_downgrade(&sock->lock);
        }
        else
            exa_read_lock(&sock->lock);

        assert(exa_read_locked(&sock->lock));

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            exa_read_unlock(&sock->lock);

            if (flags & MSG_EXA_WARM)
            {
                WARNING_MSGWARM(sockfd);
                ret = len;
            }
            else
            {
                ret = LIBC(sendto, sockfd, buf, len, flags, dest_addr, addrlen);
            }
        }
        else
        {
            ret = sendto_bypass(sock, sockfd, buf, len, flags,
                                dest_addr, addrlen);
            exa_read_unlock(&sock->lock);
        }
    }

    TRACE_RETURN(LONG, ret);
    return ret;
}

static ssize_t
sendmsg_bypass_udp(struct exa_socket * restrict sock, int sockfd,
                   const struct msghdr *msg, int flags)
{
    bool warm = !!(flags & MSG_EXA_WARM);
    ssize_t ret;

    assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
    assert(sock->domain == AF_INET);
    assert(sock->type == SOCK_DGRAM);

    exa_lock(&sock->state->tx_lock);

    if (sock->connected && msg->msg_name != NULL)
    {
        /* Address was provided, but socket is already connected */
        errno = EISCONN;
        exa_unlock(&sock->state->tx_lock);
        return -1;
    }
    else if (!sock->connected)
    {
        if (msg->msg_name == NULL)
        {
            /* Socket is not connected and no address is supplied */
            errno = ENOTCONN;
            exa_unlock(&sock->state->tx_lock);
            return -1;
        }

        /* Use provided address */
        if (msg->msg_namelen >= sizeof(struct sockaddr_in))
        {
            struct sockaddr_in *in_addr = (struct sockaddr_in *)msg->msg_name;
            if (exa_socket_udp_target(sock, in_addr->sin_addr.s_addr,
                                      in_addr->sin_port) == -1)
            {
                exa_unlock(&sock->state->tx_lock);
                return -1;
            }
        }
        else
        {
            /* Cannot set address */
            errno = EINVAL;
            exa_unlock(&sock->state->tx_lock);
            return -1;
        }
    }

    ret = exanic_udp_send_iov(sock, msg->msg_iov, msg->msg_iovlen, warm);

    exa_unlock(&sock->state->tx_lock);
    return ret;
}

static inline bool
__sendmsg_bypass_tcp_ready(struct exa_socket * restrict sock, ssize_t *ret,
                           int dummy)
{
    return exanic_tcp_writeable(sock);
}

static ssize_t
sendmsg_bypass_tcp(struct exa_socket * restrict sock, int sockfd,
                   const struct msghdr *msg, int flags)
{
    bool nonblock = (flags & MSG_DONTWAIT) || (sock->flags & O_NONBLOCK);
    bool warm = !!(flags & MSG_EXA_WARM);
    ssize_t nwritten, ret;
    size_t count;

    assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
    assert(sock->domain == AF_INET);
    assert(sock->type == SOCK_STREAM);
    assert(exa_read_locked(&sock->lock));

    if (!sock->connected)
    {
        errno = ENOTCONN;
        return -1;
    }

    /* Calculate total length of iovec */
    count = __iovec_total_len(msg->msg_iov, msg->msg_iovlen);

    /* Provided address in msg_name is ignored */

    nwritten = 0;
    while (true)
    {
        /* Send as much data as we can */
        exa_lock(&sock->state->tx_lock);
        while (nwritten < count)
        {
            ret = exanic_tcp_send_iov(sock, msg->msg_iov, msg->msg_iovlen,
                                      nwritten, count - nwritten, warm);
            if (ret <= 0)
                break;
            nwritten += ret;
        }
        exa_unlock(&sock->state->tx_lock);

        /* Exit loop if we have sent everything */
        if (nwritten >= count)
            break;

        if (ret == -1)
        {
            /* FIXME: Emit signal */
            if (sock->state->error == ETIMEDOUT)
                errno = sock->state->error;
            else
                errno = EPIPE;
            break;
        }

        exa_notify_tcp_write_fake_unready(sock);

        /* Wait until socket is ready for writing */
        do_socket_wait_tcp(sock, nonblock, sock->so_sndtimeo,
                           __sendmsg_bypass_tcp_ready, ret, 0);

        /* NOTE: Socket may have disappeared while waiting! */
        if (ret == -1)
            break;
    }

    return (nwritten > 0 || count == 0) ? nwritten : -1;
}

static ssize_t
sendmsg_bypass(struct exa_socket * restrict sock, int sockfd,
               const struct msghdr *msg, int flags)
{
    assert(exa_read_locked(&sock->lock));
    assert(sock->bypass_state == EXA_BYPASS_ACTIVE);

    if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
        return sendmsg_bypass_udp(sock, sockfd, msg, flags);
    else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
        return sendmsg_bypass_tcp(sock, sockfd, msg, flags);
    else
    {
        errno = EINVAL;
        return -1;
    }
}

/* If you modify the logic in this function, be sure to make
 * accompanying modifictions to `sendmmsg()` as well
 */
__attribute__((visibility("default")))
ssize_t
sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    ssize_t ret;

    TRACE_CALL("sendmsg");
    TRACE_ARG(INT, sockfd);
    TRACE_ARG(MSG_PTR, msg, SSIZE_MAX);
    TRACE_LAST_ARG(BITS, flags, msg_flags);
    TRACE_FLUSH();

    if (sock == NULL)
    {
        if (flags & MSG_EXA_WARM)
        {
            WARNING_MSGWARM(sockfd);
            ret = __iovec_total_len(msg->msg_iov, msg->msg_iovlen);
        }
        else
        {
            ret = LIBC(sendmsg, sockfd, msg, flags);
        }
    }
    else
    {
        if (sock->bypass_state != EXA_BYPASS_ACTIVE && msg->msg_name != NULL)
        {
            exa_write_lock(&sock->lock);

            /* Auto-bind and enable bypass based on route */
            /* TODO: Only try this once for native sockets */
            if (auto_bind(sock, sockfd, msg->msg_name, msg->msg_namelen) != 0)
            {
                exa_write_unlock(&sock->lock);
                TRACE_RETURN(INT, -1);
                return -1;
            }

            exa_rwlock_downgrade(&sock->lock);
        }
        else
            exa_read_lock(&sock->lock);

        assert(exa_read_locked(&sock->lock));

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            exa_read_unlock(&sock->lock);
            if (flags & MSG_EXA_WARM)
            {
                WARNING_MSGWARM(sockfd);
                ret = __iovec_total_len(msg->msg_iov, msg->msg_iovlen);
            }
            else
            {
                ret = LIBC(sendmsg, sockfd, msg, flags);
            }
        }
        else
        {
            ret = sendmsg_bypass(sock, sockfd, msg, flags);
            exa_read_unlock(&sock->lock);
        }
    }

    TRACE_RETURN(LONG, ret);
    return ret;
}

/* If you modify the logic in this function, be sure to make
 * accompanying modifictions to `sendmsg()` as well
 */
__attribute__((visibility("default")))
int
sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
	 int flags)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    int ret = 0;
    int i;

    TRACE_CALL("sendmmsg");
    TRACE_ARG(INT, sockfd);
    TRACE_ARG(MMSG_PTR, msgvec, SSIZE_MAX);
    TRACE_ARG(INT, vlen);
    TRACE_LAST_ARG(BITS, flags, msg_flags);
    TRACE_FLUSH();

    if (sock == NULL)
    {
        if (flags & MSG_EXA_WARM)
        {
            WARNING_MSGWARM(sockfd);
            for (i = 0; i < vlen; i++)
            {
                ret += __iovec_total_len(msgvec[i].msg_hdr.msg_iov,
                                         msgvec[i].msg_hdr.msg_iovlen);
            }
        }
        else
            ret = LIBC(sendmmsg, sockfd, msgvec, vlen, flags);

        TRACE_RETURN(INT, ret);
        return ret;
    }

    /* We need to process each destination address one by one. */
    for (i = 0; i < vlen; i++)
    {
        struct msghdr *currmsg = &msgvec[i].msg_hdr;
        int tmpret;

        if (sock->bypass_state != EXA_BYPASS_ACTIVE && currmsg->msg_name != NULL)
        {
            exa_write_lock(&sock->lock);

            if (auto_bind(sock, sockfd,
                          currmsg->msg_name, currmsg->msg_namelen) != 0)
            {
                exa_write_unlock(&sock->lock);

                /* If no messages were successfully sent at all, return -1 */
                if (ret == 0)
                    ret = -1;

                /* ENETUNREACH not a standard return value for sendmmsg, but it
                 * best reflects this situation.
                 */
                errno = ENETUNREACH;
                TRACE_RETURN(INT, ret);
                return ret;
            }

            exa_rwlock_downgrade(&sock->lock);
        }
        else
            exa_read_lock(&sock->lock);

        assert(exa_read_locked(&sock->lock));

        tmpret = 0;
        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            exa_read_unlock(&sock->lock);
            if (flags & MSG_EXA_WARM)
            {
                WARNING_MSGWARM(sockfd);
                tmpret = __iovec_total_len(currmsg->msg_iov, currmsg->msg_iovlen);
            }
            else
                tmpret = LIBC(sendmsg, sockfd, currmsg, flags);
        }
        else
        {
            tmpret = sendmsg_bypass(sock, sockfd, currmsg, flags);
            exa_read_unlock(&sock->lock);
        }

        if (tmpret < 0)
        {
            /* Exit early on the first failure, returning the number
             * of successfully sent msgs.
             */
            if (ret == 0)
                ret = tmpret;

            TRACE_RETURN(INT, ret);
            return ret;
        }
        else
            ret += (tmpret > 0) ? 1 : 0;
    }

    TRACE_RETURN(INT, ret);
    return ret;
}

static ssize_t
write_bypass_udp(struct exa_socket * restrict sock, int fd, const void *buf,
                 size_t count)
{
    ssize_t ret;

    assert(exa_read_locked(&sock->lock));
    assert(sock->connected);

    exa_lock(&sock->state->tx_lock);
    ret = exanic_udp_send(sock, buf, count, false);
    exa_unlock(&sock->state->tx_lock);

    return ret;
}

static inline bool
__write_bypass_tcp_ready(struct exa_socket * restrict sock, ssize_t *ret,
                         int dummy)
{
    return exanic_tcp_writeable(sock);
}

static ssize_t
write_bypass_tcp(struct exa_socket * restrict sock, int fd, const void *buf,
                 size_t count)
{
    bool nonblock = (sock->flags & O_NONBLOCK);
    ssize_t nwritten, ret;

    assert(exa_read_locked(&sock->lock));
    assert(sock->connected);

    nwritten = 0;
    while (true)
    {
        /* Send as much data as we can */
        exa_lock(&sock->state->tx_lock);
        while (nwritten < count)
        {
            ret = exanic_tcp_send(sock, buf + nwritten, count - nwritten,
                                  false);
            if (ret <= 0)
                break;
            nwritten += ret;
        }
        exa_unlock(&sock->state->tx_lock);

        /* Exit loop if we have sent everything */
        if (nwritten >= count)
            break;

        if (ret == -1)
        {
            /* FIXME: Emit signal */
            if (sock->state->error == ETIMEDOUT)
                errno = sock->state->error;
            else
                errno = EPIPE;
            break;
        }

        exa_notify_tcp_write_fake_unready(sock);

        /* Wait until socket is ready for writing */
        do_socket_wait_tcp(sock, nonblock, sock->so_sndtimeo,
                           __write_bypass_tcp_ready, ret, 0);

        /* NOTE: Socket may have disappeared while waiting! */
        if (ret == -1)
            break;
    }

    return (nwritten > 0 || count == 0) ? nwritten : -1;
}

static ssize_t
write_bypass(struct exa_socket * restrict sock, int fd, const void *buf,
             size_t count)
{
    if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
        return write_bypass_udp(sock, fd, buf, count);
    else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
        return write_bypass_tcp(sock, fd, buf, count);
    else
    {
        errno = EINVAL;
        return -1;
    }
}

__attribute__((visibility("default")))
ssize_t
write(int fd, const void *buf, size_t count)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);
    ssize_t ret;

    TRACE_CALL("write");
    TRACE_ARG(INT, fd);
    TRACE_ARG(BUF, buf, count);
    TRACE_LAST_ARG(LONG, count);
    TRACE_FLUSH();

    if (sock == NULL)
        ret = LIBC(write, fd, buf, count);
    else
    {
        exa_read_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            exa_read_unlock(&sock->lock);
            ret = LIBC(write, fd, buf, count);
        }
        else if (sock->connected)
        {
            ret = write_bypass(sock, fd, buf, count);
            exa_read_unlock(&sock->lock);
        }
        else
        {
            exa_read_unlock(&sock->lock);
            errno = ENOTCONN;
            ret = -1;
        }
    }

    TRACE_RETURN(LONG, ret);
    return ret;
}

static ssize_t
writev_bypass_udp(struct exa_socket * restrict sock, int fd,
                  const struct iovec *iov, size_t iovcnt)
{
    ssize_t ret;

    assert(exa_read_locked(&sock->lock));
    assert(sock->connected);

    exa_lock(&sock->state->tx_lock);
    ret = exanic_udp_send_iov(sock, iov, iovcnt, false);
    exa_unlock(&sock->state->tx_lock);

    return ret;
}

static inline bool
__writev_bypass_tcp_ready(struct exa_socket * restrict sock, ssize_t *ret,
                          int dummy)
{
    return exanic_tcp_writeable(sock);
}

static ssize_t
writev_bypass_tcp(struct exa_socket * restrict sock, int fd,
                  const struct iovec *iov, size_t iovcnt)
{
    bool nonblock = (sock->flags & O_NONBLOCK);
    ssize_t nwritten, ret;
    size_t count;

    assert(exa_read_locked(&sock->lock));
    assert(sock->connected);

    /* Calculate total length of iovec */
    count = __iovec_total_len(iov, iovcnt);

    nwritten = 0;
    while (true)
    {
        /* Send as much data as we can */
        exa_lock(&sock->state->tx_lock);
        while (nwritten < count)
        {
            ret = exanic_tcp_send_iov(sock, iov, iovcnt, nwritten,
                                      count - nwritten, false);
            if (ret <= 0)
                break;
            nwritten += ret;
        }
        exa_unlock(&sock->state->tx_lock);

        /* Exit loop if we have sent everything */
        if (nwritten >= count)
            break;

        if (ret == -1)
        {
            /* FIXME: Emit signal */
            if (sock->state->error == ETIMEDOUT)
                errno = sock->state->error;
            else
                errno = EPIPE;
            break;
        }

        exa_notify_tcp_write_fake_unready(sock);

        /* Wait until socket is ready for writing */
        do_socket_wait_tcp(sock, nonblock, sock->so_sndtimeo,
                           __writev_bypass_tcp_ready, ret, 0);

        /* NOTE: Socket may have disappeared while waiting! */
        if (ret == -1)
            break;
    }

    return (nwritten > 0 || count == 0) ? nwritten : -1;
}

static ssize_t
writev_bypass(struct exa_socket * restrict sock, int fd,
              const struct iovec *iov, size_t iovcnt)
{
    if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
        return writev_bypass_udp(sock, fd, iov, iovcnt);
    else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
        return writev_bypass_tcp(sock, fd, iov, iovcnt);
    else
    {
        errno = EINVAL;
        return -1;
    }
}

__attribute__((visibility("default")))
ssize_t
writev(int fd, const struct iovec *iov, int iovcnt)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);
    ssize_t ret;

    TRACE_CALL("writev");
    TRACE_ARG(INT, fd);
    TRACE_ARG(IOVEC_ARRAY, iov, iovcnt, LONG_MAX);
    TRACE_LAST_ARG(INT, iovcnt);
    TRACE_FLUSH();

    if (sock == NULL)
        ret = LIBC(writev, fd, iov, iovcnt);
    else
    {
        exa_read_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            exa_read_unlock(&sock->lock);
            ret = LIBC(writev, fd, iov, iovcnt);
        }
        else if (sock->connected)
        {
            ret = writev_bypass(sock, fd, iov, iovcnt);
            exa_read_unlock(&sock->lock);
        }
        else
        {
            exa_read_unlock(&sock->lock);
            errno = ENOTCONN;
            ret = -1;
        }
    }

    TRACE_RETURN(LONG, ret);
    return ret;
}
