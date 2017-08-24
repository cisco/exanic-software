#include "common.h"

#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/epoll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sched.h>
#include <time.h>

#if HAVE_NET_TSTAMP_H
#include <linux/net_tstamp.h>
#else
#include "net_tstamp_compat.h"
#endif

#include "kernel/api.h"
#include "kernel/consts.h"
#include "kernel/structs.h"
#include "override.h"
#include "lock.h"
#include "rwlock.h"
#include "structs.h"
#include "checksum.h"
#include "ip.h"
#include "udp.h"
#include "udp_queue.h"
#include "tcp_buffer.h"
#include "tcp.h"
#include "exanic.h"
#include "sys.h"
#include "dst.h"
#include "notify.h"

void
exa_socket_zero(struct exa_socket * restrict sock)
{
    assert(exa_write_locked(&sock->lock));

    /* Zero the exa-socket struct except for the lock and gen_id */
    memset((char *)sock + offsetof(struct exa_socket, domain), 0,
           sizeof(struct exa_socket) - offsetof(struct exa_socket, domain));

    /* Increment gen_id to inform users that the socket is gone */
    sock->gen_id++;
}

void
exa_socket_init(struct exa_socket * restrict sock, int domain, int type,
                int protocol)
{
    assert(exa_write_locked(&sock->lock));

    sock->domain = domain;
    sock->type = type;
    sock->protocol = protocol;

    /* Default socket options */
    sock->ip_multicast_if = htonl(INADDR_ANY);
    sock->ip_multicast_ttl = 1;
    sock->ip_membership.mcast_ep_valid = false;
    sock->ip_membership.mcast_ep.interface = htonl(INADDR_ANY);
    sock->ip_membership.mcast_ep.multiaddr = htonl(INADDR_ANY);
}

static void
exa_socket_release_interfaces(struct exa_socket * restrict sock)
{
    assert(exa_write_locked(&sock->lock));

    if (sock->listen.all_if)
        exanic_ip_release_all();
    else if (sock->listen.interface)
        exanic_ip_release(sock->listen.interface);

    sock->listen.all_if = false;
    sock->listen.interface = NULL;
}

/* Update interfaces according to address */
int
exa_socket_update_interfaces(struct exa_socket * restrict sock, in_addr_t addr)
{
    struct exanic_ip *ctx;

    assert(exa_write_locked(&sock->lock));

    if (sock->bound_to_device)
    {
        /* already bound to a specific device with SO_BINDTODEVICE */
        return 0;
    }

    if (IN_MULTICAST(ntohl(addr)))
    {
        /* In case of sockets bound to a multicast address acquiring
         * of interfaces is performed as a part of IP_ADD_MEMBERSHIP socket
         * option handling with an address of an interface with which
         * the group is being joined. Now just release held interfaces, if any.
         */
        exa_socket_release_interfaces(sock);
        return 0;
    }

    if (addr == htonl(INADDR_ANY))
    {
        if (!sock->listen.all_if)
            exanic_ip_acquire_all();
        if (sock->listen.interface)
            exanic_ip_release(sock->listen.interface);

        sock->listen.all_if = true;
        sock->listen.interface = NULL;
        return 0;
    }
    else
    {
        ctx = exanic_ip_acquire(addr);
        if (ctx == NULL)
        {
            /* ExaNIC interface not found */
            errno = EADDRNOTAVAIL;
            return -1;
        }
        if (sock->listen.all_if)
            exanic_ip_release_all();
        if (sock->listen.interface)
            exanic_ip_release(sock->listen.interface);

        sock->listen.all_if = false;
        sock->listen.interface = ctx;
        return 0;
    }
}

#define exa_socket_holds_interfaces(sk)  \
                        ((sk)->listen.all_if || (sk)->listen.interface != NULL)

/* Update timestamping flags according to socket options */
void
exa_socket_update_timestamping(struct exa_socket * restrict sock)
{
    assert(exa_write_locked(&sock->lock));
    assert(sock->bypass);

    sock->rx_sw_timestamp = (sock->so_timestamp || sock->so_timestampns ||
            (sock->so_timestamping & SOF_TIMESTAMPING_RX_SOFTWARE) != 0);

    sock->report_timestamp = sock->so_timestamp || sock->so_timestampns ||
        (sock->so_timestamping &
            (SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE)) != 0;
}

/* Update UDP TX contexts, including cached headers */
static int
exa_socket_udp_update_tx(struct exa_socket * restrict sock,
                         in_addr_t dst_addr, in_port_t dst_port)
{
    struct exanic_ip *ctx;
    in_addr_t addr, src_addr;
    in_port_t port;
    uint8_t ttl, old_ttl;

    assert(sock->state->tx_lock);
    assert(sock->bound);

    if (IN_MULTICAST(ntohl(dst_addr)))
        ttl = sock->ip_multicast_ttl;
    else
        ttl = IPDEFTTL;

    exanic_udp_get_dest(sock, &addr, &port, &old_ttl);
    if (addr == dst_addr)
    {
        /* Address not changed */
        if (port != dst_port || old_ttl != ttl)
            exanic_udp_set_dest(sock, dst_addr, dst_port, ttl);
        return 0;
    }

    /* Get new source address */
    if (sock->bind.ip.addr.local != ntohl(INADDR_ANY) &&
            !IN_MULTICAST(ntohl(sock->bind.ip.addr.local)))
        src_addr = sock->bind.ip.addr.local;
    else if (IN_MULTICAST(ntohl(dst_addr)))
        src_addr = sock->ip_multicast_if;
    else if (exa_dst_lookup_src(dst_addr, &src_addr) == -1)
        return -1;

    exanic_udp_get_src(sock, &addr, &port);
    if (addr == src_addr && port == sock->bind.ip.port.local)
    {
        /* No need to change source */
        exanic_udp_set_dest(sock, dst_addr, dst_port, ttl);
        return 0;
    }

    /* Source changed, look up new ExaNIC interface context */
    if (src_addr == sock->bind.ip.addr.local && sock->listen.interface != NULL)
    {
        ctx = sock->listen.interface;
        exanic_ip_acquire_ref(ctx);
    }
    else
    {
        ctx = exanic_ip_acquire(src_addr);
        if (ctx == NULL)
        {
            errno = EINVAL;
            return -1;
        }
    }

    exanic_udp_set_src(sock, ctx, sock->bind.ip.port.local);
    exanic_udp_set_dest(sock, dst_addr, dst_port, ttl);

    exanic_ip_release(ctx);

    return 0;
}

static int
exa_socket_udp_enable_bypass(struct exa_socket * restrict sock)
{
    int fd = exa_socket_fd(sock);

    assert(exa_write_locked(&sock->lock));
    assert(sock->state->rx_lock);
    assert(sock->state->tx_lock);
    assert(sock->domain == AF_INET);
    assert(sock->type == SOCK_DGRAM);

    if (exanic_udp_alloc(sock) == -1)
    {
        errno = ENOMEM;
        goto err_udp_alloc;
    }

    sock->bind.ip.addr.local = sock->state->e.ip.local_addr;
    sock->bind.ip.addr.peer = sock->state->e.ip.peer_addr;
    sock->bind.ip.port.local = sock->state->e.ip.local_port;
    sock->bind.ip.port.peer = sock->state->e.ip.peer_port;

    if (sock->bind.ip.addr.local != htonl(INADDR_ANY) ||
        sock->bind.ip.port.local != 0)
    {
        /* Socket is bound */
        if (exa_socket_update_interfaces(sock, sock->bind.ip.addr.local) == -1)
            goto err_update_interfaces;

        sock->bound = true;
    }

    if (sock->bound && (sock->bind.ip.addr.peer != htonl(INADDR_ANY) ||
                        sock->bind.ip.port.peer != 0))
    {
        /* Socket is connected */
        if (exa_socket_udp_update_tx(sock, sock->bind.ip.addr.peer,
                                     sock->bind.ip.port.peer) == -1)
            goto err_udp_update_tx;

        sock->connected = true;
    }

    if (exa_socket_holds_interfaces(sock))
        exa_udp_insert(fd);

    exa_notify_udp_init(sock);

    return 0;

err_udp_update_tx:
    exa_socket_release_interfaces(sock);
    sock->bound = false;
err_update_interfaces:
    exanic_udp_free(sock);
err_udp_alloc:
    return -1;
}

static int
exa_socket_tcp_enable_bypass(struct exa_socket * restrict sock)
{
    assert(exa_write_locked(&sock->lock));
    assert(sock->state->rx_lock);
    assert(sock->state->tx_lock);
    assert(sock->domain == AF_INET);
    assert(sock->type == SOCK_STREAM);

    if (exanic_tcp_alloc(sock) == -1)
    {
        errno = ENOMEM;
        goto err_tcp_alloc;
    }

    exa_notify_tcp_init(sock);

    return 0;

err_tcp_alloc:
    return -1;
}

/* Replace a socket file descriptor with an exasock file descriptor.
 * Socket rx_lock and tx_lock are held when this function returns */
int
exa_socket_enable_bypass(struct exa_socket * restrict sock)
{
    int fd = exa_socket_fd(sock);
    int tmpfd;
    unsigned i;

    /* Socket is not in bypass mode */
    assert(exa_write_locked(&sock->lock));
    assert(!sock->bypass);

    tmpfd = exa_sys_exasock_open(fd);
    if (tmpfd == -1)
        goto err_sys_exasock_open;

    /* Map in buffers */
    if (exa_sys_buffer_mmap(tmpfd, &sock->state, &sock->rx_buffer,
                            &sock->tx_buffer) == -1)
        goto err_sys_buffer_mmap;

    /* Remove native epoll memberships */
    exasock_override_off();
    for (i = 0; i < sock->num_epoll_fd; i++)
        epoll_ctl(sock->epoll_fd[i], EPOLL_CTL_DEL, fd, NULL);
    exasock_override_on();
    sock->num_epoll_fd = 0;

    /* Take both rx_lock and tx_lock - the buffers are in an invalid state
     * while the socket is still being initialised */
    exa_lock(&sock->state->rx_lock);
    exa_lock(&sock->state->tx_lock);

    /* The bypass flag needs to be set before switching to native fd.
     * The reason is to allow socket calls to check the flag without taking
     * the socket lock (if bypass found set, then exasock blocks on the lock
     * so that processing continues no sooner than fd switching is completed).
     */
    sock->bypass = true;

    if (exa_sys_replace_fd(fd, tmpfd) == -1)
        goto err_sys_replace_fd;

    /* Protocol specific setup */
    if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
    {
        if (exa_socket_udp_enable_bypass(sock) == -1)
            goto err_proto_enable_bypass;
    }
    else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
    {
        if (exa_socket_tcp_enable_bypass(sock) == -1)
            goto err_proto_enable_bypass;
    }
    else
    {
        errno = EINVAL;
        goto err_proto_enable_bypass;
    }

    exa_socket_update_timestamping(sock);

    exa_notify_enable_sock_bypass(sock);

    if (getenv("EXASOCK_DEBUG"))
        fprintf(stderr, "exasock: enabled bypass on fd %u\n", fd);

    return 0;

err_proto_enable_bypass:
    /* Can't revert to previous state, so just close the fd */
    tmpfd = fd;
err_sys_replace_fd:
    sock->bypass = false;
    exa_unlock(&sock->state->rx_lock);
    exa_unlock(&sock->state->tx_lock);
    /* FIXME: The original epoll memberships are lost */
    exa_sys_buffer_munmap(tmpfd, &sock->state, &sock->rx_buffer,
                          &sock->tx_buffer);
err_sys_buffer_mmap:
    exasock_override_off();
    close(tmpfd);
    exasock_override_on();
err_sys_exasock_open:
    return -1;
}

static int
exa_socket_add_mcast_interface(struct exa_socket * restrict sock,
                               struct exa_mcast_endpoint * restrict mc_ep,
                               in_addr_t addr_local)
{
    if (addr_local == htonl(INADDR_ANY) || addr_local == mc_ep->multiaddr)
    {
        if (exa_socket_update_interfaces(sock, mc_ep->interface) == -1)
            return -1;
        sock->listen.mcast = true;
    }
    return 0;
}

int
exa_socket_add_mcast(struct exa_socket * restrict sock,
                     struct exa_mcast_endpoint * restrict mc_ep)
{
    int fd = exa_socket_fd(sock);

    assert(exa_write_locked(&sock->lock));
    assert(sock->bound);

    if (sock->bind.ip.addr.local == htonl(INADDR_ANY) ||
        sock->bind.ip.addr.local == mc_ep->multiaddr)
    {
        if (exa_socket_holds_interfaces(sock))
            exa_udp_remove(fd);
        if (exa_socket_update_interfaces(sock, mc_ep->interface) == -1)
        {
            if (exa_socket_holds_interfaces(sock))
                exa_udp_insert(fd);
            return -1;
        }
        sock->listen.mcast = true;
        exa_udp_mcast_insert(fd, mc_ep);
    }
    return 0;
}

int
exa_socket_del_mcast(struct exa_socket * restrict sock,
                     struct exa_mcast_endpoint * restrict mc_ep)
{
    int fd = exa_socket_fd(sock);

    assert(exa_write_locked(&sock->lock));
    assert(sock->bound);

    if (sock->listen.mcast)
    {
        if (exa_socket_update_interfaces(sock, sock->bind.ip.addr.local) == -1)
            return -1;
        sock->listen.mcast = false;
        exa_udp_mcast_remove(fd, mc_ep);
        if (exa_socket_holds_interfaces(sock))
            exa_udp_insert(fd);
    }
    return 0;
}

int
exa_socket_udp_bind(struct exa_socket * restrict sock, in_addr_t addr,
                    in_port_t port)
{
    int fd = exa_socket_fd(sock);
    struct exa_endpoint endpoint;
    struct exa_mcast_endpoint *mc_ep = &sock->ip_membership.mcast_ep;

    /* Socket lock is held, socket is not bound */
    assert(exa_write_locked(&sock->lock));
    assert(!sock->bound);

    /* Acquire interfaces for bind address */
    if (exa_socket_update_interfaces(sock, addr) == -1)
        goto err_update_interfaces;

    if (sock->ip_membership.mcast_ep_valid)
        if (exa_socket_add_mcast_interface(sock, mc_ep, addr) == -1)
            goto err_add_mcast_interface;

    sock->bound = true;

    endpoint = sock->bind.ip;
    endpoint.addr.local = addr;
    endpoint.port.local = port;

    /* Bind to ExaNIC interface */
    if (exa_sys_bind(fd, &endpoint) == -1)
        goto err_sys_bind;

    sock->bind.ip = endpoint;

    if (sock->listen.mcast)
        exa_udp_mcast_insert(fd, mc_ep);
    else if (exa_socket_holds_interfaces(sock))
        exa_udp_insert(fd);

    return 0;

err_sys_bind:
    sock->bound = false;
err_add_mcast_interface:
    exa_socket_release_interfaces(sock);
err_update_interfaces:
    return -1;
}

int
exa_socket_udp_connect(struct exa_socket * restrict sock, in_addr_t addr,
                       in_port_t port)
{
    int fd = exa_socket_fd(sock);
    struct exa_endpoint endpoint;

    /* Socket is bound but not connected.
     * rx_lock, tx_lock, socket lock are held */
    assert(exa_write_locked(&sock->lock));
    assert(sock->state->rx_lock);
    assert(sock->state->tx_lock);
    assert(sock->bound);
    assert(!sock->connected);

    endpoint = sock->bind.ip;
    endpoint.addr.peer = addr;
    endpoint.port.peer = port;

    if (exa_sys_connect(fd, &endpoint) == -1)
        goto err_sys_connect;

    if (exa_socket_holds_interfaces(sock))
        exa_udp_remove(fd);

    /* If socket was bound to INADDR_ANY, connect() would have changed it */
    if (exa_socket_update_interfaces(sock, endpoint.addr.local) == -1)
        goto err_update_interfaces;

    /* Update UDP TX contexts, this should never fail */
    if (exa_socket_udp_update_tx(sock, addr, port) == -1)
        assert(0);

    sock->bind.ip = endpoint;
    if (exa_socket_holds_interfaces(sock))
        exa_udp_insert(fd);

    sock->connected = true;

    return 0;

err_update_interfaces:
    if (exa_socket_holds_interfaces(sock))
        exa_udp_insert(fd);
    /* Can't revert to previous state, so just close the fd */
    exasock_override_off();
    close(fd);
    exasock_override_on();
err_sys_connect:
    return -1;
}

/* This function only changes the udp tx context */
int
exa_socket_udp_target(struct exa_socket * restrict sock, in_addr_t dst_addr,
                      in_port_t dst_port)
{
    assert(sock->state->tx_lock);
    assert(sock->bound);
    assert(!sock->connected);

    return exa_socket_udp_update_tx(sock, dst_addr, dst_port);
}

void
exa_socket_udp_close(struct exa_socket * restrict sock)
{
    int fd = exa_socket_fd(sock);

    assert(exa_write_locked(&sock->lock));

    if (sock->listen.mcast)
        exa_udp_mcast_remove(fd, &sock->ip_membership.mcast_ep);
    else if (exa_socket_holds_interfaces(sock))
        exa_udp_remove(fd);

    exa_socket_release_interfaces(sock);
    exanic_udp_free(sock);

    sock->bound = false;
    sock->bypass = false;

    exa_sys_buffer_munmap(fd, &sock->state, &sock->rx_buffer, &sock->tx_buffer);
}

int
exa_socket_tcp_bind(struct exa_socket * restrict sock, in_addr_t addr,
                    in_port_t port)
{
    int fd = exa_socket_fd(sock);
    struct exa_endpoint endpoint;

    /* Socket lock is held, socket is not bound */
    assert(exa_write_locked(&sock->lock));
    assert(!sock->bound);

    /* Acquire interfaces for bind address */
    if (exa_socket_update_interfaces(sock, addr) == -1)
        goto err_update_interfaces;

    sock->bound = true;

    endpoint = sock->bind.ip;
    endpoint.addr.local = addr;
    endpoint.port.local = port;

    /* Bind to ExaNIC interface */
    if (exa_sys_bind(fd, &endpoint) == -1)
        goto err_sys_bind;

    sock->bind.ip = endpoint;
    if (exa_socket_holds_interfaces(sock))
        exa_tcp_insert(fd);

    return 0;

err_sys_bind:
    exa_socket_release_interfaces(sock);
    sock->bound = false;
err_update_interfaces:
    return -1;
}

int
exa_socket_tcp_connect(struct exa_socket * restrict sock, in_addr_t addr,
                       in_port_t port)
{
    int fd = exa_socket_fd(sock);
    struct exa_endpoint endpoint;

    /* rx_lock, tx_lock, socket lock are held */
    assert(exa_write_locked(&sock->lock));
    assert(sock->state->rx_lock);
    assert(sock->state->tx_lock);
    assert(sock->bound);
    assert(!sock->connected);

    endpoint = sock->bind.ip;
    endpoint.addr.peer = addr;
    endpoint.port.peer = port;

    if (exa_socket_holds_interfaces(sock))
        exa_tcp_remove(fd);

    if (endpoint.addr.local == htonl(INADDR_ANY))
    {
        in_addr_t src_addr;

        /* Find a suitable local address for the socket and bind to it */
        if (exa_dst_lookup_src(addr, &src_addr) == -1)
            goto err_dst_lookup;

        if (exa_socket_update_interfaces(sock, src_addr) == -1)
            goto err_update_interfaces;

        endpoint.addr.local = src_addr;
    }

    /* Update kernel about the connection endpoint */
    if (exa_sys_update(fd, &endpoint) == -1)
        goto err_sys_update;

    exanic_tcp_connect(sock, &endpoint);

    sock->bind.ip = endpoint;
    if (exa_socket_holds_interfaces(sock))
        exa_tcp_insert(fd);

    sock->connected = true;

    return 0;

err_sys_update:
    /* Revert to previously bound interface */
    exa_socket_update_interfaces(sock, sock->bind.ip.addr.local);
err_update_interfaces:
err_dst_lookup:
    if (exa_socket_holds_interfaces(sock))
        exa_tcp_insert(fd);
    return -1;
}

int
exa_socket_tcp_listen(struct exa_socket * restrict sock, int backlog)
{
    /* Socket is bound and not connected */
    assert(exa_write_locked(&sock->lock));
    assert(sock->bound);
    assert(!sock->connected);

    exanic_tcp_listen(sock, backlog);

    /* The kernel writes to the rx buffer, so we need to poll for updates */
    sock->need_ready_poll = true;

    /* If member of exa_notify, a listening socket needs to be also added
     * to exasock kernel epoll instance
     */
    if (sock->notify_parent)
        return exa_notify_kern_epoll_add(sock->notify_parent, sock);

    return 0;
}

int
exa_socket_tcp_accept(struct exa_endpoint * restrict endpoint,
                      struct exa_tcp_init_state * restrict tcp_state)
{
    int fd;
    struct exa_socket * restrict sock;

    /* Create new bypass socket */
    exasock_override_off();
    fd = socket(AF_INET, SOCK_STREAM, 0);
    exasock_override_on();
    if (fd == -1)
        goto err_socket;

    sock = exa_socket_get(fd);
    if (sock == NULL)
    {
        errno = ENOMEM;
        goto err_socket_get;
    }

    exa_write_lock(&sock->lock);

    exa_socket_zero(sock);
    exa_socket_init(sock, AF_INET, SOCK_STREAM, 0);
    sock->valid = true;

    if (exa_socket_enable_bypass(sock) == -1)
        goto err_socket_enable_bypass;

    /* Locks are held when returning from exa_socket_enable_bypass() */
    assert(sock->state->rx_lock);
    assert(sock->state->tx_lock);

    /* Acquire interfaces for local address */
    if (exa_socket_update_interfaces(sock, endpoint->addr.local) == -1)
        goto err_update_interfaces;

    sock->bound = true;

    /* Update kernel about the connection endpoint */
    if (exa_sys_update(fd, endpoint) == -1)
        goto err_sys_update;

    exanic_tcp_accept(sock, endpoint, tcp_state);

    sock->bind.ip = *endpoint;
    if (exa_socket_holds_interfaces(sock))
        exa_tcp_insert(fd);

    sock->connected = true;

    exa_unlock(&sock->state->rx_lock);
    exa_unlock(&sock->state->tx_lock);
    exa_write_unlock(&sock->lock);

    return fd;

err_sys_update:
err_update_interfaces:
    exa_unlock(&sock->state->rx_lock);
    exa_unlock(&sock->state->tx_lock);
err_socket_enable_bypass:
err_socket_get:
    exasock_override_off();
    close(fd);
    exasock_override_on();
err_socket:
    return -1;
}

void
exa_socket_tcp_close(struct exa_socket * restrict sock)
{
    int fd = exa_socket_fd(sock);

    assert(exa_write_locked(&sock->lock));

    if (exa_socket_holds_interfaces(sock))
    {
        exa_tcp_remove(fd);
        exa_socket_release_interfaces(sock);
    }
    exanic_tcp_free(sock);

    sock->bound = false;
    sock->bypass = false;

    exa_sys_buffer_munmap(fd, &sock->state, &sock->rx_buffer, &sock->tx_buffer);
}
