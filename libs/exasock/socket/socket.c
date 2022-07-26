#include "../common.h"

#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <sched.h>
#include <errno.h>
#include <poll.h>
#include <time.h>

#include <linux/sockios.h>

#include <exasock/socket.h>

#include "../kernel/api.h"
#include "../kernel/consts.h"
#include "../kernel/structs.h"
#include "../lock.h"
#include "../rwlock.h"
#include "../warn.h"
#include "../structs.h"
#include "../sockets.h"
#include "../checksum.h"
#include "../ip.h"
#include "../udp.h"
#include "../exanic.h"
#include "../sys.h"
#include "../dst.h"
#include "../udp_queue.h"
#include "../tcp_buffer.h"
#include "../tcp.h"
#include "../notify.h"
#include "override.h"
#include "common.h"
#include "trace.h"

__attribute__((visibility("default")))
int
socket(int domain, int type, int protocol)
{
    int ret;
    int fd;
    struct exa_socket * restrict sock;

    if (override_disabled)
        return LIBC(socket, domain, type, protocol);

    TRACE_CALL("socket");
    TRACE_ARG(ENUM, domain, family);
    TRACE_ARG(ENUM, type, socktype);
    TRACE_LAST_ARG(INT, protocol);
    TRACE_FLUSH();

    fd = LIBC(socket, domain, type, protocol);
    sock = exa_socket_get(fd);

    if (sock != NULL)
    {
        exa_write_lock(&sock->lock);

        exa_socket_zero(sock);
        exa_socket_init(sock, domain, type & 0xF, protocol);
        sock->valid = true;

        ret = LIBC(fcntl, fd, F_GETFL);
        if (ret != -1)
            sock->flags = ret;

        exa_write_unlock(&sock->lock);
    }

    TRACE_RETURN(INT, fd);
    return fd;
}

static inline bool
__linger_tcp_ready(struct exa_socket * restrict sock, int *ret, int dummy)
{
    if (exa_tcp_tx_buffer_empty(sock))
    {
        *ret = 0;
        return true;
    }
    return false;
}

static int
linger_tcp(struct exa_socket * restrict sock)
{
    struct exa_timeo timeout;
    bool nonblock;
    int ret;

    /* Block until socket transmit buffer is empty or timeout occurs */
    timeout.enabled = !!sock->so_linger.l_linger;
    timeout.val.tv_sec = sock->so_linger.l_linger;
    timeout.val.tv_usec = 0;
    nonblock = (!timeout.enabled) || (sock->flags & O_NONBLOCK);
    do_socket_wait_tcp(sock, nonblock, timeout, __linger_tcp_ready, ret, 0);
    if (errno == EAGAIN)
        errno = EWOULDBLOCK;
    return ret;
}

__attribute__((visibility("default")))
int
close(int fd)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);
    int linger_ret = 0, linger_errno = 0;
    int ret;
    int gen_id;

    if (override_disabled)
        return LIBC(close, fd);

    TRACE_CALL("close");
    TRACE_LAST_ARG(INT, fd);
    TRACE_FLUSH();

    if (sock == NULL)
        goto native_close;

    /* clean up exasock userspace metadata */
    exa_read_lock(&sock->lock);
    gen_id = sock->gen_id;

    if (sock->bypass_state == EXA_BYPASS_ACTIVE &&
        sock->domain == AF_INET && sock->type == SOCK_STREAM &&
        sock->so_linger.l_onoff)
    {
        /* SO_LINGER is set */
        linger_ret = linger_tcp(sock);
        linger_errno = errno;
        if ((linger_ret == -1) && (errno != EWOULDBLOCK))
        {
            exa_read_unlock(&sock->lock);
            TRACE_RETURN(INT, -1);
            return -1;
        }

        /* Reset the connection if it's not already closed */
        if (linger_errno == EWOULDBLOCK)
        {
            exa_lock(&sock->state->tx_lock);
            exanic_tcp_reset(sock);
            exa_unlock(&sock->state->tx_lock);
        }
    }

    if (sock->bypass_state == EXA_BYPASS_ACTIVE)
    {
        /* remove the UDP and TCP structures from the hashtables
         * and block until the current exanic_poll call has finished
         * then the socket's resources will be safe to reclaim */
        if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
            exa_socket_udp_remove(sock);
        else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
            exa_socket_tcp_remove(sock);
    }

    /* Upgrade to write lock - need to check that socket
     * is still valid afterwards */
    exa_read_unlock(&sock->lock);
    exa_write_lock(&sock->lock);
    if (gen_id != sock->gen_id)
    {
        exa_write_unlock(&sock->lock);
        errno = EBADF;
        TRACE_RETURN(INT, -1);
        return -1;
    }

    /* Remove any exa_notify memberships
     * This must be done before the bypass flag is cleared */
    exa_notify_remove_sock_all(sock);

    if (sock->bypass_state == EXA_BYPASS_ACTIVE)
    {
        if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
            exa_socket_udp_free(sock);
        else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
            exa_socket_tcp_free(sock);
    }

    /* Free exa_notify struct for epoll sockets */
    if (sock->notify)
    {
        exa_notify_free(sock->notify);
        sock->notify = NULL;
    }

    /* Clear the struct and then release the lock */
    exa_socket_zero(sock);
    exa_write_unlock(&sock->lock);

native_close:
    ret = LIBC(close, fd);

    /* If we had a linger timeout on the way, make sure we inform about it */
    if (ret == 0)
        ret = linger_ret;

    TRACE_RETURN(INT, ret);
    return ret;
}

__attribute__((visibility("default")))
int
bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    int ret;

    TRACE_CALL("bind");
    TRACE_ARG(INT, sockfd);
    TRACE_ARG(SOCKADDR_PTR, addr);
    TRACE_LAST_ARG(INT, addrlen);
    TRACE_FLUSH();

    if (sock == NULL || override_unsafe)
    {
        ret = LIBC(bind, sockfd, addr, addrlen);
        TRACE_RETURN(INT, ret);
        return ret;
    }

    exa_write_lock(&sock->lock);

    if (sock->bypass_state == EXA_BYPASS_AVAIL)
    {
        /* Put into bypass mode if address is an ExaNIC interface or INADDR_ANY */
        if (sock->domain == AF_INET && in_addr->sin_family == AF_INET)
        {
            if (in_addr->sin_addr.s_addr == htonl(INADDR_ANY) ||
                exanic_ip_find(in_addr->sin_addr.s_addr))
            {
                /* On successful return we hold rx_lock and tx_lock */
                ret = exa_socket_enable_bypass(sock);
                if (ret == -1)
                {
                    exa_write_unlock(&sock->lock);
                    TRACE_RETURN(INT, ret);
                    return ret;
                }

                exa_unlock(&sock->state->rx_lock);
                exa_unlock(&sock->state->tx_lock);

                assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
            }
            else if (IN_MULTICAST(ntohl(in_addr->sin_addr.s_addr)))
            {
                sock->warn.mcast_bound = true;
            }
        }
    }

    if (sock->bypass_state == EXA_BYPASS_ACTIVE)
    {
        /* Bind to ExaNIC interface */
        if (sock->domain == AF_INET && in_addr->sin_family == AF_INET)
        {
            if (sock->type == SOCK_DGRAM)
                ret = exa_socket_udp_bind(sock, in_addr->sin_addr.s_addr,
                                          in_addr->sin_port);
            else if (sock->type == SOCK_STREAM)
                ret = exa_socket_tcp_bind(sock, in_addr->sin_addr.s_addr,
                                          in_addr->sin_port);
            else
            {
                errno = EINVAL;
                ret = -1;
            }
        }
        else
        {
            errno = EINVAL;
            ret = -1;
        }
    }
    else
        ret = LIBC(bind, sockfd, addr, addrlen);

    exa_write_unlock(&sock->lock);
    TRACE_RETURN(INT, ret);
    return ret;
}

static int
bind_to_device(struct exa_socket * restrict sock, const char *ifnamein,
               socklen_t ifnamelen)
{
    char ifname[IFNAMSIZ];
    in_addr_t address;
    int ret;

    /* Input string may not be null terminated */
    if (ifnamelen > IFNAMSIZ-1)
        ifnamelen = IFNAMSIZ-1;
    memcpy(ifname, ifnamein, ifnamelen);
    ifname[ifnamelen] = 0;

    if (exanic_ip_find_by_interface(ifname, &address) && sock->bypass_state >= EXA_BYPASS_AVAIL)
    {
        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            /* This is an ExaNIC interface, enable bypass */
            /* On successful return we hold rx_lock and tx_lock */
            ret = exa_socket_enable_bypass(sock);
            if (ret == -1)
            {
                exa_write_unlock(&sock->lock);
                return ret;
            }

            exa_unlock(&sock->state->rx_lock);
            exa_unlock(&sock->state->tx_lock);

            assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
        }

        sock->bound_to_device = false;
        exa_socket_update_interfaces(sock, address);
        sock->bound_to_device = true;
    }
    else
    {
        sock->bypass_state = EXA_BYPASS_DISABLED;
        /* note: if socket is already in bypass mode, there is
         * currently no way to undo that */
    }

    return 0;
}

__attribute__((visibility("default")))
int
listen(int sockfd, int backlog)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    int ret;

    TRACE_CALL("listen");
    TRACE_ARG(INT, sockfd);
    TRACE_LAST_ARG(INT, backlog);
    TRACE_FLUSH();

    if (sock == NULL || sock->bypass_state != EXA_BYPASS_ACTIVE)
    {
        ret = LIBC(listen, sockfd, backlog);
        TRACE_RETURN(INT, ret);
        return ret;
    }
    else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
    {
        exa_write_lock(&sock->lock);

        if (!sock->bound || sock->connected)
        {
            exa_write_unlock(&sock->lock);
            errno = EINVAL;
            TRACE_RETURN(INT, -1);
            return -1;
        }

        if (EXA_USE_ATE(sock))
        {
            /* No support for ATE on listening sockets */
            exa_write_unlock(&sock->lock);
            errno = EOPNOTSUPP;
            TRACE_RETURN(INT, -1);
            return -1;
        }

        if (exanic_tcp_listening(sock))
        {
            /* If socket is already listening, return success */
            exa_write_unlock(&sock->lock);
            TRACE_RETURN(INT, 0);
            return 0;
        }

        ret = exa_socket_tcp_listen(sock, backlog);

        exa_lock(&sock->state->rx_lock);
        exa_notify_tcp_update(sock);
        exa_unlock(&sock->state->rx_lock);

        exa_write_unlock(&sock->lock);
        TRACE_RETURN(INT, ret);
        return ret;
    }
    else
    {
        errno = EINVAL;
        TRACE_RETURN(INT, -1);
        return -1;
    }
}

static inline int
__accept_tcp_block_ready(struct exa_socket * restrict sock, int *ret,
                         struct exa_endpoint * restrict ep,
                         struct exa_tcp_init_state * restrict tcp_state)
{
    exa_lock(&sock->state->rx_lock);
    if (exa_tcp_rx_buffer_read_conn(sock, ep, tcp_state) == 0)
    {
        exa_notify_tcp_read_update(sock);
        *ret = 0;
        return true;
    }
    exa_unlock(&sock->state->rx_lock);
    return false;
}

/* Block until a new connection is in the queue
 * On success, returns 0 with socket rx_lock held
 * Otherwise returns -1 with no locks held */
static int
accept_tcp_block(struct exa_socket * restrict sock,
                 struct exa_endpoint * restrict ep,
                 struct exa_tcp_init_state * restrict tcp_state)
{
    bool nonblock = (sock->flags & O_NONBLOCK);
    int ret;

    assert(exa_read_locked(&sock->lock));

    do_socket_poll(sock, nonblock, sock->so_rcvtimeo, __accept_tcp_block_ready,
                   ret, ep, tcp_state);
    return ret;
}

static int
accept4_tcp(struct exa_socket * restrict sock, struct sockaddr *addr,
            socklen_t *addrlen, int flags)
{
    struct exa_endpoint ep;
    struct exa_tcp_init_state tcp_state;
    int fd;

    assert(exa_read_locked(&sock->lock));

    if (!exanic_tcp_listening(sock))
    {
        /* Socket is not listening for connections */
        errno = EINVAL;
        return -1;
    }

    if (accept_tcp_block(sock, &ep, &tcp_state) == -1)
        return -1;

    exa_unlock(&sock->state->rx_lock);

    /* Got a connection */
    if (addr != NULL)
    {
        struct sockaddr_in peer;

        /* Return peer address and port to caller */
        peer.sin_family = AF_INET;
        peer.sin_port = ep.port.peer;
        peer.sin_addr.s_addr = ep.addr.peer;

        memcpy(addr, &peer, *addrlen < sizeof(peer) ? *addrlen : sizeof(peer));
        *addrlen = sizeof(peer);
    }

    /* Create the new socket */
    fd = exa_socket_tcp_accept(&ep, &tcp_state);

    if (fd != -1)
    {
        struct exa_socket * restrict new_sock = exa_socket_get(fd);

        exa_write_lock(&new_sock->lock);

        new_sock->flags = flags;
        LIBC(fcntl, fd, F_SETFL, flags);

        /* Inherit required socket options from the listening socket */
        new_sock->so_keepalive = sock->so_keepalive;
        new_sock->tcp_keepcnt = sock->tcp_keepcnt;
        new_sock->tcp_keepidle = sock->tcp_keepidle;
        new_sock->tcp_keepintvl = sock->tcp_keepintvl;
        exa_socket_tcp_update_keepalive(new_sock);

        exa_write_unlock(&new_sock->lock);
    }

    return fd;
}

static void
accept_native_init(int fd, struct exa_socket * restrict ls_sock, int flags)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);

    if (sock != NULL)
    {
        exa_write_lock(&sock->lock);

        exa_socket_zero(sock);
        sock->valid = true;

        if (ls_sock != NULL)
        {
            exa_socket_init(sock, ls_sock->domain, ls_sock->type & 0xF,
                            ls_sock->protocol);
            sock->bypass_state = ls_sock->bypass_state;
        }

        sock->flags = flags;

        exa_write_unlock(&sock->lock);
    }
}

__attribute__((visibility("default")))
int
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    bool native = false;
    int fd;

    TRACE_CALL("accept");
    TRACE_ARG(INT, sockfd);
    TRACE_FLUSH();

    if (sock != NULL && !override_unsafe)
    {
        exa_read_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            exa_read_unlock(&sock->lock);
            native = true;
            fd = LIBC(accept, sockfd, addr, addrlen);
        }
        else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
        {
            fd = accept4_tcp(sock, addr, addrlen, 0);
            exa_read_unlock(&sock->lock);
        }
        else
        {
            exa_read_unlock(&sock->lock);
            errno = EOPNOTSUPP;
            fd = -1;
        }
    }
    else
    {
        native = true;
        fd = LIBC(accept, sockfd, addr, addrlen);
    }

    if (native && fd != -1)
        accept_native_init(fd, sock, 0);

    TRACE_ARG(SOCKADDR_PTR, addr);
    TRACE_LAST_ARG(INT_PTR, addrlen);
    TRACE_RETURN(INT, fd);

    return fd;
}

__attribute__((visibility("default")))
int
accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    bool native = false;
    int fd;

    TRACE_CALL("accept4");
    TRACE_ARG(INT, sockfd);
    TRACE_FLUSH();

    if (sock != NULL && !override_unsafe)
    {
        exa_read_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            exa_read_unlock(&sock->lock);
            native = true;
            fd = LIBC(accept4, sockfd, addr, addrlen, flags);
        }
        else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
        {
            fd = accept4_tcp(sock, addr, addrlen, flags);
            exa_read_unlock(&sock->lock);
        }
        else
        {
            exa_read_unlock(&sock->lock);
            errno = EOPNOTSUPP;
            fd = -1;
        }
    }
    else
    {
        native = true;
        fd = LIBC(accept4, sockfd, addr, addrlen, flags);
    }

    if (native && fd != -1)
        accept_native_init(fd, sock, flags);

    TRACE_ARG(SOCKADDR_PTR, addr);
    TRACE_ARG(INT_PTR, addrlen);
    TRACE_LAST_ARG(BITS, flags, sock_flags);
    TRACE_RETURN(INT, fd);

    return fd;
}

/* This function will release rx_lock, tx_lock and socket lock */
static int
connect_udp(struct exa_socket * restrict sock, int sockfd, in_addr_t addr,
            in_port_t port)
{
    int ret;

    assert(exa_write_locked(&sock->lock));
    assert(sock->state->rx_lock);
    assert(sock->state->tx_lock);
    assert(sock->bound);
    assert(!sock->connected);

    if (sock->listen.all_if &&
        !exa_dst_via_exanic(addr, sock->bind.ip.addr.local))
    {
        /* Destination not reachable on ExaNIC interface */
        errno = EINVAL;
        ret = -1;
    }
    else
        ret = exa_socket_udp_connect(sock, addr, port);

    exa_write_unlock(&sock->lock);
    exa_unlock(&sock->state->rx_lock);
    exa_unlock(&sock->state->tx_lock);
    return ret;
}

static inline bool
__connect_tcp_ready(struct exa_socket * restrict sock, int *ret, int dummy)
{
    if (exa_tcp_rx_buffer_eof(sock))
    {
        errno = sock->state->error;
        *ret = -1;
        return true;
    }
    else if (!exanic_tcp_connecting(sock))
    {
        *ret = 0;
        return true;
    }
    return false;
}

/* This function will release rx_lock, tx_lock and socket lock */
static int
connect_tcp(struct exa_socket * restrict sock, int sockfd, in_addr_t addr,
            in_port_t port)
{
    bool nonblock = (sock->flags & O_NONBLOCK);
    int ret = 0;

    assert(exa_write_locked(&sock->lock));
    assert(sock->state->rx_lock);
    assert(sock->state->tx_lock);

    if (sock->connected)
    {
        /* Connection is in progress, or is already connected */
        if (exanic_tcp_connecting(sock))
            errno = EALREADY;
        else
            errno = EISCONN;
        exa_unlock(&sock->state->rx_lock);
        exa_unlock(&sock->state->tx_lock);
        exa_write_unlock(&sock->lock);
        return -1;
    }

    if (!sock->bound)
    {
        in_addr_t src_addr = htonl(INADDR_ANY);

        /* Bind socket to get the kernel to assign us a port */
        ret = exa_dst_lookup_src(addr, &src_addr);
        if (ret == 0)
            ret = exa_socket_tcp_bind(sock, src_addr, 0);
    }

    if (ret == 0)
        ret = exa_socket_tcp_connect(sock, addr, port);

    /* Release locks before blocking */
    exa_unlock(&sock->state->rx_lock);
    exa_unlock(&sock->state->tx_lock);

    if (ret == -1)
    {
        exa_write_unlock(&sock->lock);
        return ret;
    }

    if (nonblock)
    {
        /* Don't wait for connection to be established */
        exa_write_unlock(&sock->lock);
        errno = EINPROGRESS;
        return -1;
    }

    /* Convert write lock to read lock */
    exa_rwlock_downgrade(&sock->lock);

    /* Block until socket is connected */
    do_socket_wait(sock, sockfd, nonblock, sock->so_sndtimeo,
                   __connect_tcp_ready, ret, 0);

    exa_read_unlock(&sock->lock);

    /* connect does not return EAGAIN but EINPROGRESS */
    if (errno == EAGAIN)
        errno = EINPROGRESS;

    return ret;
}

__attribute__((visibility("default")))
int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    int ret;

    TRACE_CALL("connect");
    TRACE_ARG(INT, sockfd);
    TRACE_ARG(SOCKADDR_PTR, addr);
    TRACE_LAST_ARG(INT, addrlen);
    TRACE_FLUSH();

    if (sock == NULL || override_unsafe)
    {
        ret = LIBC(connect, sockfd, addr, addrlen);
        TRACE_RETURN(INT, ret);
        return ret;
    }

    if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
    {
        if (in_addr->sin_family != AF_INET)
        {
            errno = EINVAL;
            TRACE_RETURN(INT, -1);
            return -1;
        }

        exa_write_lock(&sock->lock);

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            struct sockaddr_in sa;
            socklen_t sl;

            /* Use native connect(), then put socket into bypass mode if
             * source address is on an ExaNIC interface */
            ret = LIBC(connect, sockfd, addr, addrlen);
            if (ret == -1)
            {
                exa_write_unlock(&sock->lock);
                TRACE_RETURN(INT, ret);
                return ret;
            }

            sl = sizeof(sa);
            if (sock->bypass_state >= EXA_BYPASS_AVAIL &&
                LIBC(getsockname, sockfd, (struct sockaddr *)&sa, &sl) == 0 &&
                sa.sin_family == AF_INET &&
                exanic_ip_find(sa.sin_addr.s_addr))
            {
                /* Put socket into bypass mode */
                ret = exa_socket_enable_bypass(sock);
                if (ret == 0)
                {
                    /* On successful return we hold rx_lock and tx_lock */
                    exa_write_unlock(&sock->lock);
                    exa_unlock(&sock->state->rx_lock);
                    exa_unlock(&sock->state->tx_lock);
                    TRACE_RETURN(INT, ret);
                    return ret;
                }
                else
                {
                    exa_write_unlock(&sock->lock);
                    TRACE_RETURN(INT, ret);
                    return ret;
                }
            }
            else
            {
                /* Leave socket in native mode */
                exa_write_unlock(&sock->lock);
                TRACE_RETURN(INT, ret);
                return ret;
            }
        }
        else
        {
            exa_lock(&sock->state->rx_lock);
            exa_lock(&sock->state->tx_lock);

            /* This will release rx_lock, tx_lock and socket lock */
            ret = connect_udp(sock, sockfd, in_addr->sin_addr.s_addr,
                              in_addr->sin_port);
            TRACE_RETURN(INT, ret);
            return ret;
        }
    }
    else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
    {
        if (in_addr->sin_family != AF_INET)
        {
            errno = EINVAL;
            TRACE_RETURN(INT, -1);
            return -1;
        }

        exa_write_lock(&sock->lock);

        if (sock->bypass_state == EXA_BYPASS_ACTIVE)
        {
            exa_lock(&sock->state->rx_lock);
            exa_lock(&sock->state->tx_lock);
        }
        else if (sock->bypass_state >= EXA_BYPASS_AVAIL)
        {
            /* If the route is via an ExaNIC interface, put the socket into
             * bypass mode */
            if (exa_dst_via_exanic(in_addr->sin_addr.s_addr,
                                   sock->bind.ip.addr.local))
            {
                /* On successful return we hold rx_lock and tx_lock */
                ret = exa_socket_enable_bypass(sock);
                if (ret == -1)
                {
                    exa_write_unlock(&sock->lock);
                    TRACE_RETURN(INT, ret);
                    return ret;
                }

                assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
                assert(sock->state->rx_lock);
                assert(sock->state->tx_lock);
            }
        }

        if (sock->bypass_state == EXA_BYPASS_ACTIVE)
        {
            /* This will release rx_lock, tx_lock and socket lock */
            ret = connect_tcp(sock, sockfd, in_addr->sin_addr.s_addr,
                              in_addr->sin_port);
            TRACE_RETURN(INT, ret);
            return ret;
        }
        else if (EXA_USE_ATE(sock))
        {
            /* Unable to use ATE requested on this socket */
            exa_write_unlock(&sock->lock);
            errno = EOPNOTSUPP;
            TRACE_RETURN(INT, -1);
            return -1;
        }
        else
        {
            exa_write_unlock(&sock->lock);
            ret = LIBC(connect, sockfd, addr, addrlen);
            TRACE_RETURN(INT, ret);
            return ret;
        }
    }
    else
    {
        ret = LIBC(connect, sockfd, addr, addrlen);
        TRACE_RETURN(INT, ret);
        return ret;
    }
}

__attribute__((visibility("default")))
int
shutdown(int sockfd, int how)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    int ret;

    TRACE_CALL("shutdown");
    TRACE_ARG(INT, sockfd);
    TRACE_LAST_ARG(INT, how);
    TRACE_FLUSH();

    if (sock == NULL)
    {
        ret = LIBC(shutdown, sockfd, how);
        TRACE_RETURN(INT, ret);
        return ret;
    }

    exa_write_lock(&sock->lock);

    if (sock->bypass_state == EXA_BYPASS_ACTIVE)
    {
        if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
        {
            if (!sock->connected)
            {
                exa_write_unlock(&sock->lock);
                errno = ENOTCONN;
                TRACE_RETURN(INT, -1);
                return -1;
            }

            /* TCP connection half close */
            if (how == SHUT_WR || how == SHUT_RDWR)
            {
                exa_lock(&sock->state->tx_lock);
                exanic_tcp_shutdown_write(sock);
                exa_unlock(&sock->state->tx_lock);
                exa_notify_tcp_hangup_update(sock);
            }
        }

        if (how == SHUT_RD || how == SHUT_RDWR)
            sock->state->rx_shutdown = true;
        if (how == SHUT_WR || how == SHUT_RDWR)
            sock->state->tx_shutdown = true;

        exa_write_unlock(&sock->lock);

        TRACE_RETURN(INT, 0);
        return 0;
    }
    else
    {
        exa_write_unlock(&sock->lock);
        ret = LIBC(shutdown, sockfd, how);
        TRACE_RETURN(INT, ret);
        return ret;
    }
}

__attribute__((visibility("default")))
int
fcntl(int fd, int cmd, ... /* arg */ )
{
    int ret;
    va_list ap;

    if (override_disabled)
    {
        va_start(ap, cmd);
        switch (cmd)
        {
        case F_GETFD:
        case F_GETFL:
        case F_GETOWN:
        case F_GETSIG:
        case F_GETLEASE:
            /* arg is void */
            ret = LIBC(fcntl, fd, cmd);
            break;
        case F_SETLK:
        case F_SETLKW:
        case F_GETLK:
            /* arg is pointer */
            ret = LIBC(fcntl, fd, cmd, va_arg(ap, void *));
            break;
        default:
            /* arg is long */
            ret = LIBC(fcntl, fd, cmd, va_arg(ap, long));
            break;
        }
        va_end(ap);
        return ret;
    }

    TRACE_CALL("fcntl");
    TRACE_ARG(INT, fd);
    TRACE_FLUSH();

    va_start(ap, cmd);

    switch (cmd)
    {
    case F_SETFL:
        {
            /* Record flags in socket struct, and pass through to kernel */
            struct exa_socket * restrict sock = exa_socket_get(fd);
            long flags = va_arg(ap, long);
            TRACE_ARG(ENUM, cmd, fcntl);
            TRACE_LAST_ARG(BITS, flags, file_flags);
            if (sock != NULL)
            {
                exa_write_lock(&sock->lock);
                sock->flags = flags;
                exa_write_unlock(&sock->lock);
            }
            ret = LIBC(fcntl, fd, cmd, flags);
            break;
        }

    case F_GETFD:
    case F_GETFL:
    case F_GETOWN:
    case F_GETSIG:
    case F_GETLEASE:
        /* arg is void */
        {
            TRACE_LAST_ARG(ENUM, cmd, fcntl);
            ret = LIBC(fcntl, fd, cmd);
            break;
        }

    case F_SETLK:
    case F_SETLKW:
    case F_GETLK:
        /* arg is pointer */
        {
            void *p = va_arg(ap, void *);
            TRACE_ARG(ENUM, cmd, fcntl);
            TRACE_LAST_ARG(PTR, p);
            ret = LIBC(fcntl, fd, cmd, p);
            break;
        }

    default:
        /* arg is long */
        {
            long l = va_arg(ap, long);
            TRACE_ARG(ENUM, cmd, fcntl);
            TRACE_LAST_ARG(LONG, l);
            ret = LIBC(fcntl, fd, cmd, l);
            break;
        }
    }

    va_end(ap);

    TRACE_RETURN(INT, ret);

    return ret;
}

__attribute__((visibility("default")))
int
ioctl(int fd, unsigned long int request, ...)
{
    struct exa_socket * restrict sock;
    int ret;
    va_list ap;

    if (override_disabled)
    {
        va_start(ap, request);
        ret = LIBC(ioctl, fd, request, va_arg(ap, void *));
        va_end(ap);
        return ret;
    }

    TRACE_CALL("ioctl");
    TRACE_ARG(INT, fd);
    TRACE_ARG(ENUM, request, ioctl);
    va_start(ap, request);
    TRACE_LAST_ARG(PTR, va_arg(ap, void *));
    va_end(ap);
    TRACE_FLUSH();

    sock = exa_socket_get(fd);
    if (sock != NULL && sock->bypass_state == EXA_BYPASS_ACTIVE)
    {
        int tempsock = LIBC(socket, sock->domain, sock->type, sock->protocol);
        va_start(ap, request);
        ret = LIBC(ioctl, tempsock, request, va_arg(ap, void *));
        va_end(ap);
        LIBC(close, tempsock);
    }
    else
    {
        va_start(ap, request);
        ret = LIBC(ioctl, fd, request, va_arg(ap, void *));
        va_end(ap);
    }

    va_start(ap, request);
    switch (request)
    {
    case FIONBIO:
        {
            if (sock != NULL)
            {
                if (*va_arg(ap, int *) == 0)
                    sock->flags &= ~O_NONBLOCK;
                else
                    sock->flags |= O_NONBLOCK;
            }
            break;
        }

    case SIOCSHWTSTAMP:
        {
            struct ifreq *ifr = va_arg(ap, struct ifreq *);
            exanic_ip_update_timestamping(ifr->ifr_name);
        }
        break;

    default:
        break;
    }
    va_end(ap);

    TRACE_RETURN(INT, ret);

    return ret;
}

__attribute__((visibility("default")))
int
getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    int ret;

    TRACE_CALL("getsockname");
    TRACE_ARG(INT, sockfd);
    TRACE_FLUSH();

    if (sock != NULL && sock->bypass_state == EXA_BYPASS_ACTIVE)
    {
        exa_read_lock(&sock->lock);

        if (sock->domain == AF_INET)
        {
            struct sockaddr_in sa;

            sa.sin_family = AF_INET;
            sa.sin_port = sock->bind.ip.port.local;
            sa.sin_addr.s_addr = sock->bind.ip.addr.local;

            memcpy(addr, &sa, *addrlen < sizeof(sa) ? *addrlen : sizeof(sa));
            *addrlen = sizeof(sa);
            ret = 0;
        }
        else
        {
            errno = EINVAL;
            ret = -1;
        }

        exa_read_unlock(&sock->lock);
    }
    else
        ret = LIBC(getsockname, sockfd, addr, addrlen);

    TRACE_ARG(SOCKADDR_PTR, addr);
    TRACE_LAST_ARG(INT_PTR, addrlen);
    TRACE_RETURN(INT, ret);

    return ret;
}

__attribute__((visibility("default")))
int
getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    int ret;

    TRACE_CALL("getpeername");
    TRACE_ARG(INT, sockfd);
    TRACE_FLUSH();

    if (sock != NULL && sock->bypass_state == EXA_BYPASS_ACTIVE)
    {
        exa_read_lock(&sock->lock);
        if (sock->type == SOCK_DGRAM && !sock->connected)
        {
            errno = ENOTCONN;
            ret = -1;
        }
        /* if socket is tcp then check tcp socket state directly, 
           do not rely on connected flag. It is set as soon as connection
           is in progress and not when it is actually connected */
        else if (sock->type == SOCK_STREAM &&
                (exanic_tcp_connecting(sock) || exanic_tcp_write_closed(sock)))
        {
            errno = ENOTCONN;
            ret = -1;
        }
        else if (sock->domain == AF_INET)
        {
            struct sockaddr_in sa;

            sa.sin_family = AF_INET;
            sa.sin_port = sock->bind.ip.port.peer;
            sa.sin_addr.s_addr = sock->bind.ip.addr.peer;

            memcpy(addr, &sa, *addrlen < sizeof(sa) ? *addrlen : sizeof(sa));
            *addrlen = sizeof(sa);
            ret = 0;
        }
        else
        {
            errno = EINVAL;
            ret = -1;
        }

        exa_read_unlock(&sock->lock);
    }
    else
        ret = LIBC(getpeername, sockfd, addr, addrlen);

    TRACE_ARG(SOCKADDR_PTR, addr);
    TRACE_LAST_ARG(INT_PTR, addrlen);
    TRACE_RETURN(INT, ret);

    return ret;
}

static int
getsockopt_ip(struct exa_socket * restrict sock, int sockfd, int optname,
              void *optval, socklen_t *optlen)
{
    int val;
    int ret;
    bool out_int = false;

    exa_read_lock(&sock->lock);

    if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        ret = LIBC(getsockopt, sockfd, IPPROTO_IP, optname, optval, optlen);
    else
    {
        ret = exa_sys_getsockopt(sockfd, IPPROTO_IP, optname, optval, optlen);

        /* Adjust the output if necessary */
        switch (optname)
        {
        case IP_MULTICAST_LOOP:
            /* Loopback is unsupported, always return 0 */
            val = 0;
            out_int = true;
            break;
        }
    }

    exa_read_unlock(&sock->lock);

    if (out_int)
    {
        if (*optlen >= sizeof(int))
        {
            *(int *)optval = val;
            *optlen = sizeof(int);
        }
        else if (*optlen >= sizeof(unsigned char))
        {
            *(unsigned char *)optval = val;
            *optlen = sizeof(unsigned char);
        }
    }

    return ret;
}

static int
getsockopt_tcp(struct exa_socket * restrict sock, int sockfd, int optname,
              void *optval, socklen_t *optlen)
{
    int val;
    int ret;
    bool out_int = false;

    exa_read_lock(&sock->lock);

    if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        ret = LIBC(getsockopt,sockfd, IPPROTO_TCP, optname, optval, optlen);
    else
    {
        ret = exa_sys_getsockopt(sockfd, IPPROTO_TCP, optname, optval, optlen);

        /* Adjust the output if necessary */
        switch (optname)
        {
        case TCP_NODELAY:
            /* TODO: We do not currently implement Nagle, so act as if
               TCP_NODELAY is always set */
            val = 1;
            out_int = true;
            break;
        case TCP_KEEPCNT:
            val = exa_socket_get_tcp_keepcnt(sock);
            out_int = true;
            break;
        case TCP_KEEPIDLE:
            val = exa_socket_get_tcp_keepidle(sock);
            out_int = true;
            break;
        case TCP_KEEPINTVL:
            val = exa_socket_get_tcp_keepintvl(sock);
            out_int = true;
            break;

#ifdef TCP_USER_TIMEOUT
        case TCP_USER_TIMEOUT:
            val = sock->state->p.tcp.user_timeout_ms;
            out_int = true;
            break;
#endif

        }
    }

    exa_read_unlock(&sock->lock);

    if (out_int)
    {
        if (*optlen >= sizeof(int))
        {
            *(int *)optval = val;
            *optlen = sizeof(int);
        }
        else if (*optlen >= sizeof(unsigned char))
        {
            *(unsigned char *)optval = val;
            *optlen = sizeof(unsigned char);
        }
    }

    return ret;
}

static int
getsockopt_sock(struct exa_socket * restrict sock, int sockfd, int optname,
                void *optval, socklen_t *optlen)
{
    int val;
    int ret;
    bool out_int = false;

    exa_read_lock(&sock->lock);

    if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        ret = LIBC(getsockopt, sockfd, SOL_SOCKET, optname, optval, optlen);
    else
    {
        ret = exa_sys_getsockopt(sockfd, SOL_SOCKET, optname, optval, optlen);

        /* Adjust the output if necessary */
        switch (optname)
        {
        case SO_ERROR:
            /* Return our error code if we have one */
            if (sock->state->error != 0 || ret == -1)
            {
                val = sock->state->error;
                out_int = true;
                ret = 0;
            }
            break;
        case SO_KEEPALIVE:
            val = sock->so_keepalive ? 1 : 0;
            out_int = true;
            ret = 0;
            break;
        case SO_SNDBUF:
            /* sock->state->tx_buffer_size is 0 for UDP exasock sockets */
            val = (sock->type == SOCK_STREAM) ? sock->state->tx_buffer_size : 1472;
            out_int = true;
            ret = 0;
            break;
        case SO_RCVBUF:
            val = sock->state->rx_buffer_size;
            out_int = true;
            ret = 0;
            break;
        case SO_LINGER:
            if (*optlen > sizeof(struct linger))
                *optlen = sizeof(struct linger);
            memcpy(optval, &sock->so_linger, *optlen);
            ret = 0;
            break;
        case SO_TIMESTAMP:
            val = sock->so_timestamp ? 1 : 0;
            out_int = true;
            ret = 0;
            break;
        case SO_TIMESTAMPNS:
            val = sock->so_timestampns ? 1 : 0;
            out_int = true;
            ret = 0;
            break;
        case SO_TIMESTAMPING:
            val = sock->so_timestamping;
            out_int = true;
            ret = 0;
            break;
        case SO_SNDTIMEO:
            if (*optlen > sizeof(struct timeval))
                *optlen = sizeof(struct timeval);
            memcpy(optval, &sock->so_sndtimeo.val, sizeof(struct timeval));
            ret = 0;
            break;
        case SO_RCVTIMEO:
            if (*optlen > sizeof(struct timeval))
                *optlen = sizeof(struct timeval);
            memcpy(optval, &sock->so_rcvtimeo.val, sizeof(struct timeval));
            ret = 0;
            break;
        }
    }

    exa_read_unlock(&sock->lock);

    if (out_int)
    {
        if (*optlen >= sizeof(int))
        {
            *(int *)optval = val;
            *optlen = sizeof(int);
        }
        else if (*optlen >= sizeof(unsigned char))
        {
            *(unsigned char *)optval = val;
            *optlen = sizeof(unsigned char);
        }
    }

    return ret;
}

static int
getsockopt_exasock(struct exa_socket * restrict sock, int sockfd, int optname,
                   void *optval, socklen_t *optlen)
{
    int val;
    int ret;
    bool out_int = false;

    if (sock == NULL)
    {
        /* Unfortunatelly Exasock has no control over this file descriptor,
         * so there is no way to obtain state of its options at this level */
        errno = EBADFD;
        return -1;
    }
    if (!sock->valid)
    {
        /* Not a valid socket */
        errno = ENOTSOCK;
        return -1;
    }

    exa_read_lock(&sock->lock);

    switch (optname)
    {
    case SO_EXA_NO_ACCEL:
        val = sock->bypass_state <= EXA_BYPASS_INACTIVE;
        out_int = true;
        ret = 0;
        break;
    case SO_EXA_ATE:
        val = sock->ate_id;
        out_int = true;
        ret = 0;
        break;
    default:
        errno = ENOPROTOOPT;
        ret = -1;
    }

    exa_read_unlock(&sock->lock);

    if (out_int)
    {
        if (*optlen >= sizeof(int))
        {
            *(int *)optval = val;
            *optlen = sizeof(int);
        }
        else if (*optlen >= sizeof(unsigned char))
        {
            *(unsigned char *)optval = val;
            *optlen = sizeof(unsigned char);
        }
    }

    return ret;
}

__attribute__((visibility("default")))
int
getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    int ret;

    TRACE_CALL("getsockopt");
    TRACE_ARG(INT, sockfd);
    TRACE_ARG(ENUM, level, sockopt_proto);
    TRACE_ARG(ENUM, optname, sockopt);
    TRACE_FLUSH();

    if (level == SOL_EXASOCK)
        ret = getsockopt_exasock(sock, sockfd, optname, optval, optlen);
    else if ((sock != NULL) && (level == SOL_SOCKET))
        ret = getsockopt_sock(sock, sockfd, optname, optval, optlen);
    else if ((sock != NULL) && (level == IPPROTO_IP))
        ret = getsockopt_ip(sock, sockfd, optname, optval, optlen);
    else if ((sock != NULL) && (level == IPPROTO_TCP))
        ret = getsockopt_tcp(sock, sockfd, optname, optval, optlen);
    else
        ret = LIBC(getsockopt, sockfd, level, optname, optval, optlen);

    TRACE_ARG(SOCKOPT_PTR, optval, *optlen);
    TRACE_LAST_ARG(INT_PTR, optlen);
    TRACE_RETURN(INT, ret);

    return ret;
}

static int
parse_mreq(const void *optval, socklen_t optlen,
           struct exa_mcast_endpoint *mcast_ep, bool *is_exanic)
{
    if (optlen >= sizeof(struct ip_mreqn))
    {
        struct ip_mreqn *mreqn = (struct ip_mreqn *)optval;
        char devname[IF_NAMESIZE];

        if (mreqn->imr_ifindex)
        {
            mcast_ep->interface = htonl(INADDR_ANY);
            *is_exanic = exanic_ip_find_by_interface(
                                   if_indextoname(mreqn->imr_ifindex, devname),
                                   &mcast_ep->interface);
            if (mcast_ep->interface == htonl(INADDR_ANY))
            {
                /* No interface found */
                errno = EINVAL;
                return -1;
            }
        }
        else
        {
            mcast_ep->interface = mreqn->imr_address.s_addr;
            *is_exanic = exanic_ip_find(mcast_ep->interface);
        }
        mcast_ep->multiaddr = mreqn->imr_multiaddr.s_addr;
    }
    else if (optlen >= sizeof(struct ip_mreq))
    {
        struct ip_mreq *mreq = (struct ip_mreq *)optval;

        mcast_ep->interface = mreq->imr_interface.s_addr;
        *is_exanic = exanic_ip_find(mcast_ep->interface);
        mcast_ep->multiaddr = mreq->imr_multiaddr.s_addr;
    }
    else
    {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

static int
setsockopt_ip(struct exa_socket * restrict sock, int sockfd, int optname,
              const void *optval, socklen_t optlen)
{
    int val = 0;
    int ret;
    struct exa_mcast_endpoint mcast_ep;
    bool is_exanic = false;

    if (optname == IP_MULTICAST_TTL || optname == IP_MULTICAST_LOOP)
    {
        if (optlen >= sizeof(int))
            val = *(int *)optval;
        else if (optlen >= sizeof(unsigned char))
            val = *(unsigned char *)optval;
        else
        {
            errno = EINVAL;
            return -1;
        }
    }

    exa_write_lock(&sock->lock);

    /* Validate options */
    switch (optname)
    {
    case IP_MULTICAST_LOOP:
        /* Loopback is unsupported, return error if user tries to enable it */
        if (sock->bypass_state == EXA_BYPASS_ACTIVE && val)
        {
            errno = EINVAL;
            goto err_exit;
        }
        break;

    case IP_ADD_MEMBERSHIP:
        if (sock->type == SOCK_DGRAM)
        {
            ret = parse_mreq(optval, optlen, &mcast_ep, &is_exanic);
            if (ret == -1)
                goto err_exit;

            if (!is_exanic && (mcast_ep.interface != htonl(INADDR_ANY)) &&
                sock->bypass_state == EXA_BYPASS_ACTIVE)
            {
                /* Unable to join multicast on an accelerated socket with
                 * non-exanic interface
                 */
                errno = EOPNOTSUPP;
                goto err_exit;
            }

            if (is_exanic && sock->bypass_state >= EXA_BYPASS_AVAIL)
            {
                struct exa_mcast_membership *tmp_memb;

                /* Joining multicast groups with mixed (exanic and
                 * non-exanic) interfaces on the same socket is not
                 * supported. An attempt to enable bypass on such a socket
                 * would cause no ability to receive multicast packets from
                 * groups joined with non-exanic interfaces.
                 */
                if (sock->mcast_num_not_bypassed > 0)
                {
                    errno = EOPNOTSUPP;
                    goto err_exit;
                }

                /* Don't allow duplicate membership additions.*/
                tmp_memb = exa_socket_ip_memberships_find(sock,
                                                          mcast_ep.multiaddr,
                                                          mcast_ep.interface,
                                                          NULL);
                if (tmp_memb != NULL)
                {
                    errno = EINVAL;
                    goto err_exit;
                }
            }
        }
        break;

    case IP_DROP_MEMBERSHIP:
        if (sock->type == SOCK_DGRAM)
        {
            ret = parse_mreq(optval, optlen, &mcast_ep, &is_exanic);
            if (ret == -1)
                goto err_exit;

            if (is_exanic && sock->bypass_state >= EXA_BYPASS_AVAIL)
            {
                struct exa_mcast_membership *tmp_memb;

                if (sock->bypass_state != EXA_BYPASS_ACTIVE)
                {
                    errno = EINVAL;
                    goto err_exit;
                }

                tmp_memb = exa_socket_ip_memberships_find(sock,
                                                          mcast_ep.multiaddr,
                                                          mcast_ep.interface,
                                                          NULL);
                if (tmp_memb == NULL)
                {
                    errno = EADDRNOTAVAIL;
                    goto err_exit;
                }
            }
            else
            {
                if (sock->mcast_num_not_bypassed == 0)
                {
                    errno = EINVAL;
                    goto err_exit;
                }
            }
        }
        break;
    }

    if (sock->bypass_state == EXA_BYPASS_ACTIVE)
        ret = exa_sys_setsockopt(sockfd, IPPROTO_IP, optname, optval, optlen);
    else
        ret = LIBC(setsockopt, sockfd, IPPROTO_IP, optname, optval, optlen);

    if (ret == -1)
        goto err_exit;

    /* Process some socket options on exasock level or keep track of those
     * we will need to know if this socket is put into bypass mode
     */
    switch (optname)
    {
    case IP_ADD_MEMBERSHIP:
        if (is_exanic && sock->bypass_state >= EXA_BYPASS_AVAIL)
        {
            if (sock->bypass_state != EXA_BYPASS_ACTIVE)
            {
                /* Put socket into bypass mode.
                 * On successful return we hold rx_lock and tx_lock.
                 */
                ret = exa_socket_enable_bypass(sock);
                if (ret == -1)
                {
                    LIBC(setsockopt, sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, optval,
                                    optlen);
                    goto err_exit;
                }
                exa_unlock(&sock->state->rx_lock);
                exa_unlock(&sock->state->tx_lock);
                assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
            }

            if (exa_socket_ip_memberships_add(sock, &mcast_ep) != 0)
            {
                errno = EINVAL;
                goto err_exit;
            }

            if (sock->bound)
            {
                ret = exa_socket_add_mcast(sock, &mcast_ep);
                if (ret == -1)
                {
                    exa_socket_ip_memberships_remove_and_free(sock, &mcast_ep);
                    goto err_exit;
                }
            }
        }
        else
        {
            sock->mcast_num_not_bypassed++;
        }
        break;

    case IP_DROP_MEMBERSHIP:
        if (is_exanic && sock->bypass_state >= EXA_BYPASS_AVAIL)
        {
            if (sock->bound)
            {
                /* First remove hashtable entry and then remove membership
                 * from the linked list of memberships and free its memory
                 */
                ret = exa_socket_del_mcast(sock, &mcast_ep);
                if (ret == -1)
                {
                    exa_socket_ip_memberships_remove_and_free(sock, &mcast_ep);
                    goto err_exit;
                }
            }
            exa_socket_ip_memberships_remove_and_free(sock, &mcast_ep);
        }
        else
        {
            sock->mcast_num_not_bypassed--;
        }
        break;

    case IP_MULTICAST_IF:
        if (optlen >= sizeof(struct ip_mreqn))
        {
            const struct ip_mreqn *mreqn = optval;
            sock->ip_multicast_if = mreqn->imr_address.s_addr;
        }
        else if (optlen >= sizeof(struct ip_mreq))
            sock->ip_multicast_if =
                ((const struct ip_mreq *)optval)->imr_interface.s_addr;
        else if (optlen >= sizeof(struct in_addr))
            sock->ip_multicast_if = ((const struct in_addr *)optval)->s_addr;
        break;

    case IP_MULTICAST_TTL:
        sock->ip_multicast_ttl = val;
        break;
    }

    exa_write_unlock(&sock->lock);
    return 0;

err_exit:
    exa_write_unlock(&sock->lock);
    return -1;
}

static int
setsockopt_tcp(struct exa_socket * restrict sock, int sockfd, int optname,
              const void *optval, socklen_t optlen)
{
    int val = 0;
    int ret;

    if (optname == TCP_NODELAY ||
        optname == TCP_KEEPCNT ||
        optname == TCP_KEEPIDLE ||
#ifdef TCP_USER_TIMEOUT
        optname == TCP_USER_TIMEOUT ||
#endif
        optname == TCP_KEEPINTVL)
    {
        if (optlen >= sizeof(int))
            val = *(int *)optval;
        else if (optlen >= sizeof(unsigned char))
            val = *(unsigned char *)optval;
        else
        {
            errno = EINVAL;
            return -1;
        }
    }

    exa_write_lock(&sock->lock);

    /* Validate options */
    switch (optname)
    {
    case TCP_NODELAY:
        /* TODO: We do not currently implement Nagle, so prevent
           any attempt to disable it */
        if (sock->bypass_state == EXA_BYPASS_ACTIVE && !val)
        {
            errno = EINVAL;
            goto err_exit;
        }
    }

    if (sock->bypass_state == EXA_BYPASS_ACTIVE)
        ret = exa_sys_setsockopt(sockfd, IPPROTO_TCP, optname, optval, optlen);
    else
        ret = LIBC(setsockopt, sockfd, IPPROTO_TCP, optname, optval, optlen);

    if (ret == -1)
        goto err_exit;

    if (ret == 0)
    {
        /* Keep track of some socket options which we will need to know
         * if this socket is put into bypass mode */
        switch (optname)
        {
        case TCP_KEEPCNT:
            sock->tcp_keepcnt = val;
            if (sock->bypass_state == EXA_BYPASS_ACTIVE
                && sock->domain == AF_INET
                && sock->type == SOCK_STREAM)
            {
                exa_socket_tcp_update_keepalive(sock);
            }
            break;
        case TCP_KEEPIDLE:
            sock->tcp_keepidle = val;
            if (sock->bypass_state == EXA_BYPASS_ACTIVE
                && sock->domain == AF_INET
                && sock->type == SOCK_STREAM)
            {
                exa_socket_tcp_update_keepalive(sock);
            }
            break;
        case TCP_KEEPINTVL:
            sock->tcp_keepintvl = val;
            if (sock->bypass_state == EXA_BYPASS_ACTIVE
                && sock->domain == AF_INET
                && sock->type == SOCK_STREAM)
            {
                exa_socket_tcp_update_keepalive(sock);
            }
            break;

#ifdef TCP_USER_TIMEOUT
        case TCP_USER_TIMEOUT:
            sock->tcp_user_timeout = (unsigned)val;
            if (sock->bypass_state == EXA_BYPASS_ACTIVE
                && sock->domain == AF_INET
                && sock->type == SOCK_STREAM)
            {
                exa_socket_tcp_update_user_timeout(sock);
            }
            break;
#endif

        }
    }

    exa_write_unlock(&sock->lock);
    return 0;

err_exit:
    exa_write_unlock(&sock->lock);
    return -1;
}

static int
setsockopt_sock(struct exa_socket * restrict sock, int sockfd, int optname,
                const void *optval, socklen_t optlen)
{
    int val = 0;
    int ret;

    if (optname == SO_TIMESTAMP ||
        optname == SO_TIMESTAMPNS ||
        optname == SO_TIMESTAMPING ||
        optname == SO_KEEPALIVE)
    {
        if (optlen >= sizeof(int))
            val = *(int *)optval;
        else if (optlen >= sizeof(unsigned char))
            val = *(unsigned char *)optval;
        else
        {
            errno = EINVAL;
            return -1;
        }
    }

    exa_write_lock(&sock->lock);

    if (sock->bypass_state == EXA_BYPASS_ACTIVE)
    {
        /* Some options don't work on the dummy socket.
         * Don't call exa_sys_setsockopt() for those options */
        if (optname == SO_LINGER ||
            optname == SO_SNDBUF ||
            optname == SO_RCVBUF ||
            optname == SO_KEEPALIVE ||
            optname == SO_BINDTODEVICE ||
            optname == SO_TIMESTAMP ||
            optname == SO_TIMESTAMPNS ||
            optname == SO_TIMESTAMPING ||
            optname == SO_SNDTIMEO ||
            optname == SO_RCVTIMEO)
            ret = 0;
        else
            ret = exa_sys_setsockopt(sockfd, SOL_SOCKET, optname, optval, optlen);
    }
    else
        ret = LIBC(setsockopt, sockfd, SOL_SOCKET, optname, optval, optlen);

    if (ret == 0)
    {
        /* Keep track of some socket options which we will need to know
         * if this socket is put into bypass mode */
        switch (optname)
        {
        case SO_BINDTODEVICE:
            ret = bind_to_device(sock, optval, optlen);
            break;
        case SO_LINGER:
            if (optlen >= sizeof(struct linger))
                memcpy(&sock->so_linger, optval, sizeof(struct linger));
            else
            {
                errno = EINVAL;
                ret = -1;
            }
            break;
        case SO_TIMESTAMP:
            sock->so_timestamp = (val != 0);
            sock->so_timestampns = false;
            if (sock->bypass_state == EXA_BYPASS_ACTIVE)
                exa_socket_update_timestamping(sock);
            break;
        case SO_TIMESTAMPNS:
            sock->so_timestamp = false;
            sock->so_timestampns = (val != 0);
            if (sock->bypass_state == EXA_BYPASS_ACTIVE)
                exa_socket_update_timestamping(sock);
            break;
        case SO_TIMESTAMPING:
            sock->so_timestamping = val;
            if (sock->bypass_state == EXA_BYPASS_ACTIVE)
                exa_socket_update_timestamping(sock);
            break;
        case SO_SNDTIMEO:
            if (optlen >= sizeof(struct timeval))
                memcpy(&sock->so_sndtimeo.val, optval, sizeof(struct timeval));
            else
            {
                errno = EINVAL;
                ret = -1;
            }
            sock->so_sndtimeo.enabled =
                sock->so_sndtimeo.val.tv_sec || sock->so_sndtimeo.val.tv_usec;
            break;
        case SO_RCVTIMEO:
            if (optlen >= sizeof(struct timeval))
                memcpy(&sock->so_rcvtimeo.val, optval, sizeof(struct timeval));
            else
            {
                errno = EINVAL;
                ret = -1;
            }
            sock->so_rcvtimeo.enabled =
                sock->so_rcvtimeo.val.tv_sec || sock->so_rcvtimeo.val.tv_usec;
            break;
        case SO_SNDBUF:
            /* Not supported with bypass enabled */
            if (sock->bypass_state == EXA_BYPASS_ACTIVE)
                WARNING_SOCKOPT("SO_SNDBUF");
            else
                sock->warn.so_sndbuf = true;
            break;
        case SO_RCVBUF:
            /* Not supported with bypass enabled */
            if (sock->bypass_state == EXA_BYPASS_ACTIVE)
                WARNING_SOCKOPT("SO_RCVBUF");
            else
                sock->warn.so_rcvbuf = true;
            break;
        case SO_KEEPALIVE:
            sock->so_keepalive = (val != 0);
            if (sock->bypass_state == EXA_BYPASS_ACTIVE
                && sock->domain == AF_INET
                && sock->type == SOCK_STREAM)
            {
                exa_socket_tcp_update_keepalive(sock);
            }
            break;
        }
    }

    exa_write_unlock(&sock->lock);
    return ret;
}

static int
setsockopt_exasock(struct exa_socket * restrict sock, int sockfd, int optname,
                   const void *optval, socklen_t optlen)
{
    int val = 0;
    int ret;
    struct exa_mcast_endpoint mcast_ep;
    bool is_exanic = false;

    if (sock == NULL)
    {
        /* Unfortunatelly Exasock has no control over this file descriptor,
         * so there is no way to manipulate its options at this level */
        errno = EBADFD;
        return -1;
    }
    if (!sock->valid)
    {
        /* Not a valid socket */
        errno = ENOTSOCK;
        return -1;
    }

    if (optname == SO_EXA_NO_ACCEL || optname == SO_EXA_ATE)
    {
        if (optlen >= sizeof(int))
            val = *(int *)optval;
        else if (optlen >= sizeof(unsigned char))
            val = *(unsigned char *)optval;
        else
        {
            errno = EINVAL;
            return -1;
        }
    }

    exa_write_lock(&sock->lock);

    switch (optname)
    {
    case SO_EXA_NO_ACCEL:
        if ((val && sock->bypass_state == EXA_BYPASS_ACTIVE)
            || (val == 0 && sock->bypass_state == EXA_BYPASS_DISABLED))
        {
            errno = EPERM;
            goto err_exit;
        }
        else
        {
            sock->bypass_state = (val != 0) ? EXA_BYPASS_DISABLED : EXA_BYPASS_AVAIL;
        }
        break;

    case SO_EXA_MCAST_LISTEN:
        if ((sock->type != SOCK_DGRAM) || (sock->bypass_state <= EXA_BYPASS_INACTIVE))
        {
            errno = EPERM;
            goto err_exit;
        }
        if (sock->mcast_num_not_bypassed > 0)
        {
            /* Enabling bypass on a socket which already has joined a multicast
             * group with a non-exanic interface is not supported. It would
             * cause lack of ability to receive multicast packets from this
             * group.
             */
            errno = EOPNOTSUPP;
            goto err_exit;
        }

        ret = parse_mreq(optval, optlen, &mcast_ep, &is_exanic);
        if (ret == -1)
            goto err_exit;

        /* Don't allow duplicate membership additions.*/
        if (exa_socket_ip_memberships_find(sock,
                                           mcast_ep.multiaddr,
                                           mcast_ep.interface,
                                           NULL) != NULL)
        {
            errno = EINVAL;
            goto err_exit;
        }

        if (mcast_ep.interface == htonl(INADDR_ANY))
        {
            /* This socket will be receiving packets of the multicast group
             * arriving through any ExaNIC interface
             */
            is_exanic = true;
        }
        if (!IN_MULTICAST(ntohl(mcast_ep.multiaddr)) || !is_exanic)
        {
            errno = EINVAL;
            goto err_exit;
        }

        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            /* Put socket into bypass mode.
             * On successful return we hold rx_lock and tx_lock.
             */
            ret = exa_socket_enable_bypass(sock);
            if (ret == -1)
                goto err_exit;
            exa_unlock(&sock->state->rx_lock);
            exa_unlock(&sock->state->tx_lock);
            assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
        }

        if (exa_socket_ip_memberships_add(sock, &mcast_ep) != 0)
        {
            errno = EINVAL;
            goto err_exit;
        }

        if (sock->bound)
        {
            ret = exa_socket_add_mcast(sock, &mcast_ep);
            if (ret == -1)
            {
                exa_socket_ip_memberships_remove_and_free(sock, &mcast_ep);
                goto err_exit;
            }
        }

        break;

    case SO_EXA_ATE:
        if ((sock->domain != AF_INET)
            || (sock->type != SOCK_STREAM)
            || sock->bypass_state == EXA_BYPASS_DISABLED
            || sock->connected)
        {
            errno = EPERM;
            goto err_exit;
        }
        if (sock->bypass_state == EXA_BYPASS_ACTIVE
            && exanic_tcp_listening(sock))
        {
            errno = EOPNOTSUPP;
            goto err_exit;
        }
        if (val < -1)
        {
            errno = EINVAL;
            goto err_exit;
        }
        sock->ate_id = val;
        break;

    default:
        errno = ENOPROTOOPT;
        goto err_exit;
    }

    exa_write_unlock(&sock->lock);
    return 0;

err_exit:
    exa_write_unlock(&sock->lock);
    return -1;
}

__attribute__((visibility("default")))
int
setsockopt(int sockfd, int level, int optname, const void *optval,
           socklen_t optlen)
{
    struct exa_socket * restrict sock = exa_socket_get(sockfd);
    int ret;

    TRACE_CALL("setsockopt");
    TRACE_ARG(INT, sockfd);
    TRACE_ARG(ENUM, level, sockopt_proto);
    TRACE_ARG(ENUM, optname, sockopt);
    TRACE_ARG(SOCKOPT_PTR, optval, optlen);
    TRACE_LAST_ARG(INT, optlen);
    TRACE_FLUSH();

    if (override_unsafe)
        ret = LIBC(setsockopt, sockfd, level, optname, optval, optlen);
    else if (level == SOL_EXASOCK)
        ret = setsockopt_exasock(sock, sockfd, optname, optval, optlen);
    else if ((sock != NULL) && (level == SOL_SOCKET))
        ret = setsockopt_sock(sock, sockfd, optname, optval, optlen);
    else if ((sock != NULL) && (level == IPPROTO_IP))
        ret = setsockopt_ip(sock, sockfd, optname, optval, optlen);
    else if ((sock != NULL) && (level == IPPROTO_TCP))
        ret = setsockopt_tcp(sock, sockfd, optname, optval, optlen);
    else
        ret = LIBC(setsockopt, sockfd, level, optname, optval, optlen);

    TRACE_RETURN(INT, ret);
    return ret;
}
