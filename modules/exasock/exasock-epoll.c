/**
 * Kernel support for the ExaSock library
 * Copyright (C) 2011-2017 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/compiler.h>
#include <linux/skbuff.h>
#include <net/neighbour.h>

#include "../../libs/exasock/kernel/api.h"
#include "../../libs/exasock/kernel/structs.h"

#include "exasock.h"

struct exasock_epoll *exasock_epoll_alloc(void)
{
    struct exasock_epoll *epoll;
    struct exasock_epoll_state *user_page;
    int err;

    /* Allocate structs and buffers */
    epoll = kzalloc(sizeof(struct exasock_epoll), GFP_KERNEL);
    user_page = vmalloc_user(PAGE_SIZE);
    if (epoll == NULL || user_page == NULL)
    {
        err = -ENOMEM;
        goto err_alloc;
    }

    epoll->type = EXASOCK_TYPE_EPOLL;
    epoll->user_page = user_page;
    INIT_LIST_HEAD(&epoll->fd_ready_backlog_list);

    /* Initialize user page */
    epoll->user_page->next_read = 0;
    epoll->user_page->next_write = 0;

    return epoll;

err_alloc:
    vfree(user_page);
    kfree(epoll);
    return ERR_PTR(err);
}

int exasock_epoll_ctl(struct exasock_epoll *epoll, bool add,
                      uint32_t local_addr, uint16_t local_port, int fd)
{
    struct exasock_epoll_notify *notify;
    int err;

    if (add)
    {
        /* Add the socket to epoll */
        notify = kzalloc(sizeof(struct exasock_epoll_notify), GFP_KERNEL);
        if (notify == NULL)
            return -ENOMEM;
        notify->epoll = epoll;
        notify->fd = fd;
        err = exasock_tcp_notify_add(local_addr, local_port, notify);
        if (err)
        {
            kfree(notify);
            return err;
        }
    }
    else
    {
        /* Remove the socket from epoll */
        err = exasock_tcp_notify_del(local_addr, local_port, &notify);
        if (err)
            return err;
        if (notify->epoll != epoll || notify->fd != fd)
        {
            /* Arguments mismatch. Revert the operation and return with error */
            exasock_tcp_notify_add(local_addr, local_port, notify);
            return -EINVAL;
        }
        kfree(notify);
    }

    return 0;
}

void exasock_epoll_free(struct exasock_epoll *epoll)
{
    BUG_ON(epoll->type != EXASOCK_TYPE_EPOLL);

    vfree(epoll->user_page);
    kfree(epoll);
}

int exasock_epoll_state_mmap(struct exasock_epoll *epoll,
                             struct vm_area_struct *vma)
{
    if (epoll == NULL)
        return -EINVAL;

    if (epoll->type != EXASOCK_TYPE_EPOLL)
        return -EINVAL;

    return remap_vmalloc_range(vma, epoll->user_page,
            vma->vm_pgoff - (EXASOCK_OFFSET_EPOLL_STATE / PAGE_SIZE));
}

void exasock_epoll_update(struct exasock_epoll_notify *notify)
{
    struct exasock_epoll *epoll = notify->epoll;
    volatile struct exasock_epoll_state *state = epoll->user_page;
    int next_wr;

    /* No need for a lock protection of struct exasock_epoll since it gets
     * accessed in a single worker thread only
     */

    next_wr = state->next_write;

    /* First check if there is anything to move from backlog to fd_ready
     * ring
     */
    if (unlikely(!list_empty(&epoll->fd_ready_backlog_list)))
    {
        struct exasock_epoll_notify *no, *_no;

        list_for_each_entry_safe(no, _no, &epoll->fd_ready_backlog_list, node)
        {
            if (EXASOCK_EPOLL_FD_READY_RING_FULL(state->next_read, next_wr))
                break;

            state->fd_ready[next_wr] = no->fd;
            EXASOCK_EPOLL_FD_READY_IDX_INC(next_wr);
            list_del(&no->node);
        }
        wmb();
        state->next_write = next_wr;
    }

    /* In case fd_ready ring is full we store the socket in a backlog list
     * and leave.
     */
    if (unlikely(EXASOCK_EPOLL_FD_READY_RING_FULL(state->next_read,
                                                  next_wr)))
    {
        list_add(&notify->node, &epoll->fd_ready_backlog_list);
        return;
    }

    /* Add the socket to fd_ready ring */
    state->fd_ready[next_wr] = notify->fd;
    EXASOCK_EPOLL_FD_READY_IDX_INC(next_wr);
    wmb();
    state->next_write = next_wr;
}
