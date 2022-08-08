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
#include <ctype.h>
#include <fcntl.h>
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
#include "warn.h"
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
#include "socket/common.h"

void
exa_socket_zero(struct exa_socket * restrict sock)
{
    assert(exa_write_locked(&sock->lock));

    exa_socket_ip_memberships_remove_and_free_all(sock);
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
    sock->ip_memberships = NULL;
    sock->mcast_listening_denominator_iface = htonl(INADDR_NONE);

    /* ATE disabled */
    sock->ate_id = -1;
    sock->ate_init_pending = false;

    sock->bypass_state =
        (getenv("EXASOCK_DEFAULT_DISABLE") != NULL) ? EXA_BYPASS_INACTIVE : EXA_BYPASS_AVAIL;
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

/* The aim here is to determine whether the socket should
 * be listening on one interface or on INADDR_ANY (all_if).
 *
 * The reason is because exasock doesn't support listening
 * to a specified subset of interfaces (see exa_socket_update_interfaces())
 * so we must choose one or the other.
 *
 * We also need to ensure that we can receive unicast udp segs while
 * listening in multicast mode. So if the socket has been bound to a
 * unicast address, and that unicast address differs from the
 * denominator address for all the multicast listens, then we
 * have to listen on INADDR_ANY in that case as well.
 */
static in_addr_t
exa_socket_ip_memberships_get_denominator_iface(struct exa_socket *esk)
{
    struct exa_mcast_membership *cur;
    in_addr_t denom;

    if (esk->ip_memberships == NULL)
        return ~htonl(INADDR_ANY);

    /* Set it to the first one by default */
    denom = esk->ip_memberships->mcast_ep.interface;

    for (cur = esk->ip_memberships; cur != NULL; cur = cur->next)
    {
        /* If even one of the multicast memberships requires listening
         * on all interfaces, then the common denominator to listen on
         * has to be INADDR_ANY.
         */
        if (cur->mcast_ep.interface == htonl(INADDR_ANY))
            return htonl(INADDR_ANY);

        /* If the memberships require that we listen to at least
         * two different interfaces then we must just listen to all.
         */
        if (cur->mcast_ep.interface != denom
            && denom != htonl(INADDR_ANY))
            return htonl(INADDR_ANY);
    }

    /* In order to support unicast segments being received while we
     * also listen for mcast segments, we need to listen on INADDR_ANY
     * if the unicast iface address is different from the mcast
     * denominator iface address.
     */
    if (esk->bound && !IN_MULTICAST(ntohl(esk->bind.ip.addr.local)))
        if (esk->bind.ip.addr.local != denom)
            return htonl(INADDR_ANY);

    return denom;
}

int
exa_socket_ip_memberships_add(struct exa_socket *esk,
                              const struct exa_mcast_endpoint *emep)
{
    struct exa_mcast_membership *tmp;

    tmp = calloc(1, sizeof(*tmp));
    if (tmp == NULL)
        return -1;

    tmp->mcast_ep = *emep;
    tmp->parent_sock = esk;

    tmp->next = esk->ip_memberships;
    esk->ip_memberships = tmp;

    esk->mcast_listening_denominator_iface =
        exa_socket_ip_memberships_get_denominator_iface(esk);
    return 0;
}

struct exa_mcast_membership *
exa_socket_ip_memberships_find(struct exa_socket *esk,
                                 in_addr_t mc_mcast_addr,
                                 in_addr_t mc_iface_addr,
                                 struct exa_mcast_membership **ret_prev)
{
    struct exa_mcast_membership *cur, *prev;

    if (ret_prev)
        *ret_prev = NULL;

    prev = NULL;
    for (cur = esk->ip_memberships; cur != NULL;
         prev = cur, cur = cur->next)
    {
        if (cur->mcast_ep.multiaddr != mc_mcast_addr
            || cur->mcast_ep.interface != mc_iface_addr)
            continue;

        if (ret_prev)
            *ret_prev = prev;
        return cur;
    }

    return NULL;
}

struct exa_mcast_membership *
exa_socket_ip_memberships_remove(struct exa_socket *esk,
                                 const struct exa_mcast_endpoint *emep)
{
    struct exa_mcast_membership *tmp, *prev;

    tmp = exa_socket_ip_memberships_find(esk,
                                           emep->multiaddr,
                                           emep->interface,
                                           &prev);
    if (tmp == NULL)
        return NULL;

    if (prev != NULL)
        prev->next = tmp->next;
    else
        esk->ip_memberships = tmp->next;

    esk->mcast_listening_denominator_iface =
        exa_socket_ip_memberships_get_denominator_iface(esk);

    return tmp;
}

/* We have to split this off from the *_ip_memberships_del() function
 * because exa_udp_mcast_del() requires a (still) valid reference to
 * the exa_mcast_membership object after it has been removed from the
 * ip_memberships list. So we have a two-stage removal process -
 * first remove, then explicitly free() after calling exa_udp_mcast_del().
 *
 * This function is only needed when removing SINGLE items from the
 * ip_memberships list. But when cleaning up all of them at once
 * during close(), it is sufficient to call
 * exa_socket_ip_memberships_remove_and_free_all().
 */
void
exa_socket_ip_memberships_free(struct exa_mcast_membership *mc_memb)
{
    free(mc_memb);
}

void
exa_socket_ip_memberships_remove_and_free_all(struct exa_socket *esk)
{
    struct exa_mcast_membership *cur, *tmp;

    for (cur = esk->ip_memberships; cur != NULL;)
    {
        tmp = cur;
        cur = cur->next;
        exa_socket_ip_memberships_free(tmp);
    }

    esk->ip_memberships = NULL;
    esk->mcast_listening_denominator_iface =
        exa_socket_ip_memberships_get_denominator_iface(esk);
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

/* Read system global IP parameter from /proc interface */
static int exa_socket_get_param_from_proc(const char *param, int *val)
{
    int fd;
    char procfs_file[64];
    char buf[32] = {'\0'};
    char *endptr;
    int v;

    snprintf(procfs_file, sizeof(procfs_file), "/proc/sys/net/ipv4/%s", param);

    exasock_override_off();

    fd = open(procfs_file, O_RDONLY);
    if (fd == -1)
        goto err_open;

    exasock_libc_read(fd, buf, sizeof(buf) - 1);
    v = strtol(buf, &endptr, 10);
    if (*buf == '\0' || (*endptr != '\0' && !isspace(*endptr)))
        goto err_read;

    close(fd);
    exasock_override_on();

    *val = v;
    return 0;

err_read:
    close(fd);
err_open:
    exasock_override_on();
    return -1;
}

/* Update timestamping flags according to socket options */
void
exa_socket_update_timestamping(struct exa_socket * restrict sock)
{
    assert(exa_write_locked(&sock->lock));
    assert(sock->bypass_state == EXA_BYPASS_ACTIVE);

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
    src_addr = ntohl(INADDR_ANY);
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

    /* Source needs to be updated before destination. Destination setting
     * depends on source being up-to-date. */
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

int
exa_socket_get_tcp_keepintvl(struct exa_socket * restrict sock)
{
    int val;

    if (sock->tcp_keepintvl)
        return sock->tcp_keepintvl;
    else if (exa_socket_get_param_from_proc("tcp_keepalive_intvl",
                                            &val) == -1 || val < 0)
        return EXA_TCP_KEEPALIVE_INTVL_DEF;
    else
        return val;
}

int
exa_socket_get_tcp_keepcnt(struct exa_socket * restrict sock)
{
    int val;

    if (sock->tcp_keepcnt)
        return sock->tcp_keepcnt;
    else if (exa_socket_get_param_from_proc("tcp_keepalive_probes",
                                            &val) == -1 || val < 0)
        return EXA_TCP_KEEPALIVE_PROBES_DEF;
    else
        return val;
}

int
exa_socket_get_tcp_keepidle(struct exa_socket * restrict sock)
{
    int val;

    if (sock->tcp_keepidle)
        return sock->tcp_keepidle;
    else if (exa_socket_get_param_from_proc("tcp_keepalive_time",
                                            &val) == -1 || val < 0)
        return EXA_TCP_KEEPALIVE_TIME_DEF;
    else
        return val;
}

void
exa_socket_tcp_update_keepalive(struct exa_socket * restrict sock)
{
    struct exa_tcp_state * restrict tcp;

    assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
    assert(sock->domain == AF_INET);
    assert(sock->type == SOCK_STREAM);

    tcp = &sock->state->p.tcp;

    if (sock->so_keepalive)
    {
        /* Enable keep-alive */
        tcp->keepalive.intvl = exa_socket_get_tcp_keepintvl(sock);
        tcp->keepalive.probes = exa_socket_get_tcp_keepcnt(sock);
        tcp->keepalive.time = exa_socket_get_tcp_keepidle(sock);
    }
    else
    {
        /* Disable keep-alive */
        tcp->keepalive.intvl = 0;
        tcp->keepalive.probes = 0;
        tcp->keepalive.time = 0;
    }
}

void
exa_socket_tcp_update_user_timeout(struct exa_socket * restrict sock)
{
    assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
    assert(sock->domain == AF_INET);
    assert(sock->type == SOCK_STREAM);

    sock->state->p.tcp.user_timeout_ms = sock->tcp_user_timeout;
}

static void
exa_socket_tcp_init(struct exa_socket * restrict sock)
{
    struct exa_tcp_state * restrict tcp;
    int val;

    assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
    assert(sock->domain == AF_INET);
    assert(sock->type == SOCK_STREAM);

    tcp = &sock->state->p.tcp;

    /* Grab current slow_start_after_idle setting */
    if (exa_socket_get_param_from_proc("tcp_slow_start_after_idle", &val) == -1)
        tcp->ss_after_idle = EXA_TCP_SS_AFTER_IDLE_DEF;
    else
        tcp->ss_after_idle = (val == 0) ? 0 : 1;

    /* Initialize settings */
    exa_socket_tcp_update_keepalive(sock);
    exa_socket_tcp_update_user_timeout(sock);
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

    exa_socket_tcp_init(sock);

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
    assert(sock->bypass_state != EXA_BYPASS_ACTIVE);

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
    sock->bypass_state = EXA_BYPASS_ACTIVE;

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

    if (sock->warn.so_sndbuf)
        WARNING_SOCKOPT("SO_SNDBUF");
    if (sock->warn.so_rcvbuf)
        WARNING_SOCKOPT("SO_RCVBUF");

    return 0;

err_proto_enable_bypass:
    /* Can't revert to previous state, so just close the fd */
    tmpfd = fd;
err_sys_replace_fd:
    sock->bypass_state = EXA_BYPASS_AVAIL;
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

static bool
exa_mcast_membership_has_multiaddr(struct exa_socket *esk, in_addr_t multiaddr)
{
    struct exa_mcast_membership *cur;

    for (cur = esk->ip_memberships; cur != NULL; cur = cur->next)
    {
        if (multiaddr == cur->mcast_ep.multiaddr)
            return true;
    }

    return false;
}

static int
exa_socket_add_mcast_interface(struct exa_socket * restrict sock,
                               in_addr_t addr_local)
{

    if (addr_local == htonl(INADDR_ANY)
        || exa_mcast_membership_has_multiaddr(sock, addr_local))
    {
        if (exa_socket_update_interfaces(sock,
                                         sock->mcast_listening_denominator_iface) == -1)
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
        exa_mcast_membership_has_multiaddr(sock, sock->bind.ip.addr.local))
    {
        if (exa_socket_update_interfaces(sock,
                                         sock->mcast_listening_denominator_iface) == -1)
            return -1;
        sock->listen.mcast = true;
        exa_udp_mcast_insert(fd, mc_ep);
        /* We allow unicast segments to also be received
         * while listening for mcast.
         */
    }
    return 0;
}

int
exa_socket_del_mcast(struct exa_socket * restrict sock,
                     struct exa_mcast_endpoint * restrict mc_ep)
{
    int fd = exa_socket_fd(sock);
    in_addr_t listening_addr;

    assert(exa_write_locked(&sock->lock));
    assert(sock->bound);

    if (sock->ip_memberships != NULL)
    {
        /* The denominator listening iface may have changed when the
         * requested multiaddr was removed from ip_memberships.
         */
        listening_addr = sock->mcast_listening_denominator_iface;
    }
    else
        listening_addr = sock->bind.ip.addr.local;

    if (exa_socket_update_interfaces(sock, listening_addr) == -1)
        return -1;

    if (sock->ip_memberships == NULL)
        sock->listen.mcast = false;

    exa_udp_mcast_remove(fd, mc_ep);
    return 0;
}

int
exa_socket_udp_bind(struct exa_socket * restrict sock, in_addr_t addr,
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

    if (sock->ip_memberships != NULL)
        if (exa_socket_add_mcast_interface(sock, addr) == -1)
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
        exa_udp_mcast_insert_all(fd);
    if (exa_socket_holds_interfaces(sock))
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
exa_socket_udp_remove(struct exa_socket * restrict sock)
{
    int fd = exa_socket_fd(sock);

    assert(exa_read_locked(&sock->lock));

    if (sock->listen.mcast)
        exa_udp_mcast_remove_all(fd);
    if (exa_socket_holds_interfaces(sock))
        exa_udp_remove(fd);

    /* Wait for read critical section of socket to finish */
    exa_socket_reclaim_sync();
}

void
exa_socket_udp_free(struct exa_socket * restrict sock)
{
    int fd = exa_socket_fd(sock);

    assert(exa_write_locked(&sock->lock));

    exa_socket_release_interfaces(sock);
    exanic_udp_free(sock);

    sock->bound = false;
    sock->bypass_state = EXA_BYPASS_DISABLED;

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
    int saved_errno = 0;

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
        in_addr_t src_addr = endpoint.addr.local;

        /* Find a suitable local address for the socket and bind to it */
        if (exa_dst_lookup_src(addr, &src_addr) == -1)
            goto err_dst_lookup;

        if (exa_socket_update_interfaces(sock, src_addr) == -1)
            goto err_update_interfaces;

        endpoint.addr.local = src_addr;
    }

    /* initialize TCP state */
    if (exa_tcp_state_init_conn(fd, sock->state))
    {
        saved_errno = errno;
        goto err_sys_update;
    }

    /* Update kernel about the connection endpoint */
    if (exa_sys_update(fd, &endpoint) == -1)
    {
        saved_errno = errno;
        goto err_sys_update;
    }

    /* Enable ATE for the connection if requested */
    if (EXA_USE_ATE(sock))
    {
        if (exa_sys_ate_enable(fd, sock->ate_id) == -1)
        {
            saved_errno = errno;
            goto err_sys_ate_enable;
        }
        sock->ate_init_pending = true;
    }

    exanic_tcp_connect(sock, &endpoint);

    /* The kernel writes to the rx buffer, so we need to poll for updates */
    sock->need_rx_ready_poll = true;

    /* If already a member of exa_notify, the socket needs to be added to
     * exasock kernel epoll instance */
    if (sock->notify_parent)
        exa_notify_kern_epoll_add(sock->notify_parent, sock);

    sock->bind.ip = endpoint;
    if (exa_socket_holds_interfaces(sock))
        exa_tcp_insert(fd);

    sock->connected = true;

    return 0;

err_sys_ate_enable:
    /* Revert the connection endpoint update in kernel */
    exa_sys_update(fd, &sock->bind.ip);
err_sys_update:
    /* Revert to previously bound interface */
    exa_socket_update_interfaces(sock, sock->bind.ip.addr.local);
err_update_interfaces:
err_dst_lookup:
    if (exa_socket_holds_interfaces(sock))
        exa_tcp_insert(fd);
    if (saved_errno)
        errno = saved_errno;
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
    sock->need_rx_ready_poll = true;

    /* If member of exa_notify, a listening socket needs to be also added
     * to exasock kernel epoll instance
     */
    if (sock->notify_parent)
        exa_notify_kern_epoll_add(sock->notify_parent, sock);

    return 0;
}

int
exa_socket_tcp_accept(struct exa_endpoint * restrict endpoint,
                      struct exa_tcp_init_state * restrict tcp_state)
{
    int fd;
    struct exa_socket * restrict sock;
#ifdef TCP_LISTEN_SOCKET_PROFILING
    struct timespec begin_ts;
    struct timespec end_ts;
    struct timespec accept_duration;
    clock_gettime(CLOCK_REALTIME, &begin_ts);
#endif /* ifdef TCP_LISTEN_SOCKET_PROFILING */

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

    /* initialize TCP state */
    exa_tcp_state_init_acc(sock->state, tcp_state);

    /* Update kernel about the connection endpoint */
    if (exa_sys_update(fd, endpoint) == -1)
        goto err_sys_update;

    exanic_tcp_accept(sock, endpoint);

#ifdef TCP_LISTEN_SOCKET_PROFILING
    clock_gettime(CLOCK_REALTIME, &end_ts);
    ts_sub(&end_ts, &begin_ts, &accept_duration);
    sock->state->p.tcp.profile.accept_period.tv_nsec = accept_duration.tv_nsec;
    sock->state->p.tcp.profile.accept_period.tv_sec  = accept_duration.tv_sec;
#endif /* ifdef TCP_LISTEN_SOCKET_PROFILING */

    /* The kernel writes to the rx buffer, so we need to poll for updates */
    sock->need_rx_ready_poll = true;

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
    exa_write_unlock(&sock->lock);
err_socket_get:
    exasock_override_off();
    close(fd);
    exasock_override_on();
err_socket:
    return -1;
}

void
exa_socket_tcp_remove(struct exa_socket * restrict sock)
{
    int fd = exa_socket_fd(sock);

    assert(exa_read_locked(&sock->lock));

    if (exa_socket_holds_interfaces(sock))
        exa_tcp_remove(fd);

    /* Wait for read critical section of socket to finish */
    exa_socket_reclaim_sync();
}

void
exa_socket_tcp_free(struct exa_socket * restrict sock)
{
    int fd = exa_socket_fd(sock);

    assert(exa_write_locked(&sock->lock));

    exa_socket_release_interfaces(sock);
    exanic_tcp_free(sock);

    sock->bound = false;
    sock->bypass_state = EXA_BYPASS_DISABLED;

    exa_sys_buffer_munmap(fd, &sock->state, &sock->rx_buffer, &sock->tx_buffer);
}
