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
#include "notify.h"

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
    assert(sock->bypass);
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
    assert(sock->bypass);
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

    if (sock->bypass)
    {
        /* Inserting a ready socket is considered to be an edge */
        if (sock->rx_ready)
            exa_notify_read_edge(no, sock);
        if (sock->tx_ready)
            exa_notify_write_edge(no, sock);
        if (sock->eof_ready)
            exa_notify_hangup_edge(no, sock);
    }
    else
    {
        /* epoll will need to check native sockets */
        no->have_native = true;
    }

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

    if (sock->bypass)
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

    /* Socket will be lazily removed from the maybe-ready queue */
    /* Does not currently recalculate no->have_native */

    return 0;
}

void
exa_notify_remove_sock_all(struct exa_socket *sock)
{
    if (sock->notify_parent != NULL)
    {
        exa_notify_remove_sock(sock->notify_parent, sock);
    }
}
