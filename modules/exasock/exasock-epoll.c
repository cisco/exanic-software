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

    spin_lock_init(&epoll->fd_list_lock);
    INIT_LIST_HEAD(&epoll->fd_list);
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

int exasock_epoll_notify_add(struct exasock_epoll *epoll,
                             struct exasock_epoll_notify *notify, int fd)
{
restart:
    spin_lock(&notify->lock);
    if (notify->epoll != NULL)
    {
        spin_unlock(&notify->lock);
        return -EINVAL;
    }

    if (!spin_trylock(&epoll->fd_list_lock))
    {
        spin_unlock(&notify->lock);
        goto restart;
    }

    notify->epoll = epoll;
    notify->fd = fd;
    list_add(&notify->node, &epoll->fd_list);

    spin_unlock(&epoll->fd_list_lock);
    spin_unlock(&notify->lock);
    return 0;
}

int exasock_epoll_notify_del_check(struct exasock_epoll *epoll,
                                   struct exasock_epoll_notify *notify)
{
restart:
    spin_lock(&notify->lock);
    if (notify->epoll != epoll)
    {
        spin_unlock(&notify->lock);
        return -EINVAL;
    }

    if (!spin_trylock(&epoll->fd_list_lock))
    {
        spin_unlock(&notify->lock);
        goto restart;
    }

    notify->epoll = NULL;
    list_del(&notify->node);

    spin_unlock(&epoll->fd_list_lock);
    spin_unlock(&notify->lock);
    return 0;
}

void exasock_epoll_notify_del(struct exasock_epoll_notify *notify)
{
    struct exasock_epoll *epoll;

restart:
    spin_lock(&notify->lock);
    epoll = notify->epoll;

    if (epoll == NULL)
    {
        spin_unlock(&notify->lock);
        return;
    }

    if (!spin_trylock(&epoll->fd_list_lock))
    {
        spin_unlock(&notify->lock);
        goto restart;
    }

    notify->epoll = NULL;
    list_del(&notify->node);

    spin_unlock(&epoll->fd_list_lock);
    spin_unlock(&notify->lock);
}

void exasock_epoll_free(struct exasock_epoll *epoll)
{
    struct exasock_epoll_notify *no, *_no;

    BUG_ON(epoll->type != EXASOCK_TYPE_EPOLL);

    spin_lock(&epoll->fd_list_lock);

    list_for_each_entry_safe(no, _no, &epoll->fd_list, node)
    {
        spin_lock(&no->lock);
        no->epoll = NULL;
        list_del(&no->node);
        spin_unlock(&no->lock);
    }

    list_for_each_entry_safe(no, _no, &epoll->fd_ready_backlog_list, node)
    {
        spin_lock(&no->lock);
        no->epoll = NULL;
        list_del(&no->node);
        spin_unlock(&no->lock);
    }

    spin_unlock(&epoll->fd_list_lock);

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
    struct exasock_epoll *epoll;
    volatile struct exasock_epoll_state *state;
    int next_wr;

restart:
    spin_lock(&notify->lock);
    epoll = notify->epoll;

    if (epoll == NULL)
    {
        spin_unlock(&notify->lock);
        return;
    }

    if (!spin_trylock(&epoll->fd_list_lock))
    {
        spin_unlock(&notify->lock);
        goto restart;
    }

    state = epoll->user_page;
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
            list_move(&no->node, &epoll->fd_list);
        }
        wmb();
        state->next_write = next_wr;
    }

    /* In case fd_ready ring is full we store the socket in a backlog list
     * and leave.
     */
    if (unlikely(EXASOCK_EPOLL_FD_READY_RING_FULL(state->next_read, next_wr)))
    {
        list_move(&notify->node, &epoll->fd_ready_backlog_list);
        spin_unlock(&epoll->fd_list_lock);
        spin_unlock(&notify->lock);
        return;
    }

    /* Add the socket to fd_ready ring */
    state->fd_ready[next_wr] = notify->fd;
    EXASOCK_EPOLL_FD_READY_IDX_INC(next_wr);
    wmb();
    state->next_write = next_wr;

    spin_unlock(&epoll->fd_list_lock);
    spin_unlock(&notify->lock);
}
