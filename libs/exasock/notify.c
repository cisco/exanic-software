#include "common.h"

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <sched.h>
#include <time.h>

#include "kernel/api.h"
#include "kernel/consts.h"
#include "kernel/structs.h"
#include "lock.h"
#include "rwlock.h"
#include "structs.h"
#include "exanic.h"
#include "checksum.h"
#include "tcp_buffer.h"
#include "tcp.h"
#include "udp_queue.h"
#include "sys.h"
#include "notify.h"

int
exa_notify_kern_epoll_add(struct exa_notify * restrict no,
                          struct exa_socket * restrict sock)
{
    int fd = exa_socket_fd(sock);

    assert(exa_write_locked(&sock->lock));

    exa_lock(&no->ep.lock);
    if (no->ep.ref_cnt++ == 0)
    {
        no->ep.fd = exa_sys_epoll_create();
        if (no->ep.fd == -1)
            goto err_create;
        if (exa_sys_epoll_mmap(no->ep.fd, &no->ep.state) == -1)
            goto err_mmap;
    }
    exa_unlock(&no->ep.lock);

    if (exa_sys_epoll_ctl(no->ep.fd, EXASOCK_EPOLL_CTL_ADD, fd) < 0)
        return -1;

    sock->kern_epoll_member = true;
    return 0;

err_mmap:
    exa_sys_epoll_close(no->ep.fd);
err_create:
    no->ep.ref_cnt = 0;
    exa_unlock(&no->ep.lock);
    return -1;
}

static int
exa_notify_kern_epoll_del(struct exa_notify * restrict no,
                          struct exa_socket * restrict sock, int fd)
{
    int ret;

    assert(exa_write_locked(&sock->lock));

    ret = exa_sys_epoll_ctl(no->ep.fd, EXASOCK_EPOLL_CTL_DEL, fd);
    if (ret != 0)
        return ret;

    sock->kern_epoll_member = false;
    exa_lock(&no->ep.lock);

    no->ep.ref_cnt--;

    /* Kernel epoll instance is kept for an exa_notify instance as long
     * as there is at least one exasock file descriptor registered. */
    if (no->ep.ref_cnt == 0)
    {
        exa_sys_epoll_munmap(no->ep.fd, &no->ep.state);
        ret = exa_sys_epoll_close(no->ep.fd);
        if (ret != 0)
        {
            exa_unlock(&no->ep.lock);
            return ret;
        }
        no->ep.fd = -1;
    }

    exa_unlock(&no->ep.lock);

    return 0;
}

struct exa_notify *
exa_notify_alloc(void)
{
    struct exa_notify *no;
    struct exa_notify_fd *table;

    no = malloc(sizeof(struct exa_notify));
    if (no == NULL)
        goto err_notify_malloc;

    table = malloc(sizeof(struct exa_notify_fd) * exa_socket_table_size);
    if (table == NULL)
        goto err_table_malloc;

    memset(table, 0, sizeof(struct exa_notify_fd) * exa_socket_table_size);

    memset(no, 0, sizeof(*no));
    no->fd_table = table;
    no->list_head = -1;
    no->ep.fd = -1;

    return no;

err_table_malloc:
    free(no);
err_notify_malloc:
    return NULL;
}

void
exa_notify_free(struct exa_notify * restrict no)
{
    while (no->list_head != -1)
    {
        int fd = no->list_head;
        struct exa_socket * restrict sock = exa_socket_get(fd);

        assert(sock != NULL);

        exa_write_lock(&sock->lock);
        exa_notify_remove_sock(no, sock);
        exa_write_unlock(&sock->lock);
    }

    free(no->fd_table);
    free(no);
}

void
exa_notify_udp_init(struct exa_socket * restrict sock)
{
    assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
    assert(sock->domain == AF_INET);
    assert(sock->type == SOCK_DGRAM);

    sock->rx_ready = exa_udp_queue_ready(sock);
    /* UDP sockets are always ready for writing */
    sock->tx_ready = true;
    /* UDP sockets never hang up */
    sock->eof_ready = false;

    if (sock->rx_ready)
        exa_notify_read_edge_all(sock);
    if (sock->tx_ready)
        exa_notify_write_edge_all(sock);
    if (sock->eof_ready)
        exa_notify_hangup_edge_all(sock);
}

void
exa_notify_tcp_init(struct exa_socket * restrict sock)
{
    assert(sock->bypass_state == EXA_BYPASS_ACTIVE);
    assert(sock->domain == AF_INET);
    assert(sock->type == SOCK_STREAM);

    sock->rx_ready = exa_tcp_rx_buffer_ready(sock);
    sock->tx_ready = !exanic_tcp_connecting(sock);
    sock->eof_ready = exanic_tcp_write_closed(sock);

    if (sock->rx_ready)
        exa_notify_read_edge_all(sock);
    if (sock->tx_ready)
        exa_notify_write_edge_all(sock);
    if (sock->eof_ready)
        exa_notify_hangup_edge_all(sock);
}

int
exa_notify_insert_sock(struct exa_notify * restrict no,
                       struct exa_socket * restrict sock,
                       uint32_t events)
{
    int fd = exa_socket_fd(sock);

    assert(no != NULL);
    assert(sock != NULL);
    assert(exa_write_locked(&sock->lock));
    assert(fd >= 0 && fd < exa_socket_table_size);

    if (sock->notify_parent != NULL)
    {
        /* Socket already belongs to an exa_notify instance */
        errno = EEXIST;
        return -1;
    }

    /* Check if exasock kernel epoll instance needs to be created
     * and/or updated */
    if (sock->bypass_state == EXA_BYPASS_ACTIVE
        && sock->domain == AF_INET
        && sock->type == SOCK_STREAM)
    {
        int ret = exa_notify_kern_epoll_add(no, sock);
        if (ret != 0)
            return ret;
    }

    sock->notify_parent = no;
    no->fd_table[fd].present = true;
    no->fd_table[fd].event_pending = false;
    no->fd_table[fd].events = events;

    /* Insert into linked list */
    if (no->list_head == -1)
    {
        no->list_head = fd;
        no->fd_table[fd].list_next = fd;
        no->fd_table[fd].list_prev = fd;
    }
    else
    {
        int head = no->list_head;
        int tail = no->fd_table[head].list_prev;
        no->fd_table[fd].list_prev = tail;
        no->fd_table[fd].list_next = head;
        no->fd_table[head].list_prev = fd;
        no->fd_table[tail].list_next = fd;
    }

    if (sock->bypass_state == EXA_BYPASS_ACTIVE)
    {
        /* Inserting a ready socket is considered to be an edge */
        if (sock->rx_ready)
            exa_notify_read_edge(no, sock);
        if (sock->tx_ready)
            exa_notify_write_edge(no, sock);
        if (sock->eof_ready)
            exa_notify_hangup_edge(no, sock);
    }

    exa_lock(&no->fd_cnt.lock);
    if (sock->bypass_state == EXA_BYPASS_ACTIVE)
        no->fd_cnt.bypass++;
    else
        no->fd_cnt.native++;
    exa_unlock(&no->fd_cnt.lock);

    return 0;
}

int
exa_notify_modify_sock(struct exa_notify * restrict no,
                       struct exa_socket * restrict sock,
                       uint32_t events)
{
    int fd = exa_socket_fd(sock);

    assert(no != NULL);
    assert(sock != NULL);
    assert(exa_write_locked(&sock->lock));
    assert(fd >= 0 && fd < exa_socket_table_size);

    if (sock->notify_parent != no)
    {
        /* Socket not registered on this exa_notify instance */
        errno = ENOENT;
        return -1;
    }

    no->fd_table[fd].events = events;

    if (sock->bypass_state == EXA_BYPASS_ACTIVE)
    {
        /* Trigger an edge if the socket is ready */
        if (sock->rx_ready)
            exa_notify_read_edge(no, sock);
        if (sock->tx_ready)
            exa_notify_write_edge(no, sock);
        if (sock->eof_ready)
            exa_notify_hangup_edge(no, sock);
    }

    return 0;
}

int
exa_notify_remove_sock(struct exa_notify * restrict no,
                       struct exa_socket * restrict sock)
{
    int fd = exa_socket_fd(sock);

    assert(no != NULL);
    assert(sock != NULL);
    assert(exa_write_locked(&sock->lock));
    assert(fd >= 0 && fd < exa_socket_table_size);

    if (sock->notify_parent != no)
    {
        /* Socket not registered on this exa_notify instance */
        errno = ENOENT;
        return -1;
    }

    /* Check if exasock kernel epoll instance needs to be updated/closed */
    if (sock->bypass_state == EXA_BYPASS_ACTIVE
        && sock->domain == AF_INET
        && sock->type == SOCK_STREAM
        && sock->kern_epoll_member)
    {
        int ret = exa_notify_kern_epoll_del(no, sock, fd);
        if (ret != 0)
            return ret;
    }

    sock->notify_parent = NULL;
    no->fd_table[fd].events = 0;
    no->fd_table[fd].present = false;

    /* Remove from linked list */
    {
        int next = no->fd_table[fd].list_next;
        int prev = no->fd_table[fd].list_prev;

        no->fd_table[next].list_prev = prev;
        no->fd_table[prev].list_next = next;

        if (no->list_head == fd)
        {
            if (fd == next)
                no->list_head = -1;
            else
                no->list_head = next;
        }
    }

    memset(&no->fd_table[fd], 0, sizeof(no->fd_table[fd]));

    /* Remove the socket from the maybe-ready queue */
    exa_notify_queue_remove(no, fd);

    exa_lock(&no->fd_cnt.lock);
    if (sock->bypass_state == EXA_BYPASS_ACTIVE)
        no->fd_cnt.bypass--;
    else
        no->fd_cnt.native--;
    exa_unlock(&no->fd_cnt.lock);

    return 0;
}

void
exa_notify_remove_sock_all(struct exa_socket * restrict sock)
{
    if (sock->notify_parent != NULL)
    {
        exa_notify_remove_sock(sock->notify_parent, sock);
    }
}
