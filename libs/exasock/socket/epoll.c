
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
#include <sched.h>
#include <poll.h>
#include <time.h>

#include "../kernel/structs.h"
#include "../lock.h"
#include "../rwlock.h"
#include "../structs.h"
#include "../sockets.h"
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

/* How often to call system calls when polling */
#define SYS_POLL_NS 160000

#define MIN_ITERS 1
#define MAX_ITERS 1048576
#define DEFAULT_ITERS 16384

/* Adjust number of iterations so that polling runs for between SYS_POLL_NS/2
 * and SYS_POLL_NS nanoseconds */
static void
adjust_iters(const struct timespec *duration, unsigned long *iters)
{
    if (duration->tv_sec == 0)
    {
        if (duration->tv_nsec > SYS_POLL_NS && *iters > MIN_ITERS)
            *iters /= 2;
        else if (duration->tv_nsec < SYS_POLL_NS / 2 && *iters < MAX_ITERS)
            *iters *= 2;
    }
}

static uint32_t
from_epoll_events(uint32_t epoll_events)
{
    uint32_t events = 0;

    if (epoll_events & EPOLLIN)
        events |= EXA_NOTIFY_IN;
    if (epoll_events & EPOLLOUT)
        events |= EXA_NOTIFY_OUT;
    if (epoll_events & EPOLLERR)
        events |= EXA_NOTIFY_ERR;
    if (epoll_events & EPOLLHUP)
        events |= EXA_NOTIFY_HUP;
    if (epoll_events & EPOLLET)
        events |= EXA_NOTIFY_ET;

    return events;
}

/* Init exasock structs, closes fd and return -1 if not successful */
static int
epoll_fd_init(int fd)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);
    struct exa_notify * restrict no;

    if (sock == NULL)
    {
        errno = ENOMEM;
        goto err_socket_get;
    }

    no = exa_notify_alloc();
    if (no == NULL)
    {
        errno = ENOMEM;
        goto err_notify_alloc;
    }

    exa_write_lock(&sock->lock);

    exa_socket_zero(sock);
    sock->valid = true;
    sock->notify = no;

    exa_write_unlock(&sock->lock);

    return fd;

err_notify_alloc:
err_socket_get:
    LIBC(close, fd);
    return -1;
}

__attribute__((visibility("default")))
int
epoll_create(int size)
{
    int fd;

    TRACE_CALL("epoll_create");
    TRACE_LAST_ARG(INT, size);
    TRACE_FLUSH();

    fd = LIBC(epoll_create, size);
    fd = epoll_fd_init(fd);

    TRACE_RETURN(INT, fd);
    return fd;
}

__attribute__((visibility("default")))
int
epoll_create1(int flags)
{
    int fd;

    TRACE_CALL("epoll_create1");
    TRACE_LAST_ARG(BITS, flags, epoll_flags);
    TRACE_FLUSH();

    fd = LIBC(epoll_create1, flags);
    fd = epoll_fd_init(fd);

    TRACE_RETURN(INT, fd);
    return fd;
}

static int
epoll_ctl_add(struct exa_notify * restrict no, int epfd,
              struct exa_socket * restrict sock, int fd,
              struct epoll_event *event)
{
    uint32_t notify_events = from_epoll_events(event->events);

    assert(no != NULL);
    assert(sock != NULL);
    assert(exa_write_locked(&sock->lock));

    if (sock->bypass_state != EXA_BYPASS_ACTIVE)
    {
        /* Check that we have space to record the epoll membership */
        if (sock->num_epoll_fd >= MAX_NUM_EPOLL)
        {
            errno = ENOMEM;
            return -1;
        }

        /* Add to kernel epoll instance */
        if (LIBC(epoll_ctl, epfd, EPOLL_CTL_ADD, fd, event) == -1)
            return -1;

        /* Record epoll membership */
        sock->epoll_fd[sock->num_epoll_fd] = epfd;
        sock->num_epoll_fd++;
    }

    /* Try to add to exa_notify */
    if (exa_notify_insert_sock(no, sock, notify_events) == -1)
    {
        /* Failed to add to exa_notify, so we remove the fd from
         * the kernel epoll instance to keep things consistent */
        LIBC(epoll_ctl, epfd, EPOLL_CTL_DEL, fd, event);
        return -1;
    }

    no->fd_table[fd].data = event->data.u64;

    return 0;
}

static int
epoll_ctl_mod(struct exa_notify * restrict no, int epfd,
              struct exa_socket * restrict sock, int fd,
              struct epoll_event *event)
{
    assert(no != NULL);
    assert(sock != NULL);
    assert(exa_write_locked(&sock->lock));

    if (sock->bypass_state != EXA_BYPASS_ACTIVE)
    {
        /* Update kernel epoll */
        if (LIBC(epoll_ctl, epfd, EPOLL_CTL_MOD, fd, event) == -1)
            return -1;
    }

    if (exa_notify_has_sock(no, sock))
    {
        /* Update exa_notify */
        uint32_t notify_events = from_epoll_events(event->events);

        assert(fd >= 0 && fd < exa_socket_table_size);

        exa_notify_modify_sock(no, sock, notify_events);
        no->fd_table[fd].data = event->data.u64;
    }

    return 0;
}

static int
epoll_ctl_del(struct exa_notify * restrict no, int epfd,
              struct exa_socket * restrict sock, int fd)
{
    unsigned i;

    assert(no != NULL);
    assert(sock != NULL);
    assert(exa_write_locked(&sock->lock));

    if (sock->bypass_state != EXA_BYPASS_ACTIVE)
    {
        /* Remove from kernel epoll */
        LIBC(epoll_ctl, epfd, EPOLL_CTL_DEL, fd, NULL);

        /* Remove from membership record */
        for (i = 0; i < sock->num_epoll_fd; i++)
        {
            if (sock->epoll_fd[i] == epfd)
            {
                sock->epoll_fd[i] = sock->epoll_fd[sock->num_epoll_fd - 1];
                sock->num_epoll_fd--;
            }
        }
    }

    /* Remove the fd from exa_notify */
    return exa_notify_remove_sock(no, sock);
}

__attribute__((visibility("default")))
int
epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);
    struct exa_socket * restrict epsock = exa_socket_get(epfd);
    int ret;

    if (override_disabled)
        return LIBC(epoll_ctl, epfd, op, fd, event);

    TRACE_CALL("epoll_ctl");
    TRACE_ARG(INT, epfd);
    TRACE_ARG(ENUM, op, epoll_op);
    TRACE_ARG(INT, fd);
    TRACE_LAST_ARG(EPOLL_EVENT_PTR, event);
    TRACE_FLUSH();

    if (epsock == NULL || sock == NULL)
    {
        ret = LIBC(epoll_ctl, epfd, op, fd, event);
        TRACE_RETURN(INT, ret);
        return ret;
    }

    exa_write_lock(&epsock->lock);

    if (epsock->notify == NULL)
    {
        exa_write_unlock(&epsock->lock);
        ret = LIBC(epoll_ctl, epfd, op, fd, event);
        TRACE_RETURN(INT, ret);
        return ret;
    }

    /* FIXME: This may deadlock if fd is a epoll file descriptor! */
    exa_write_lock(&sock->lock);

    if (op == EPOLL_CTL_ADD)
        ret = epoll_ctl_add(epsock->notify, epfd, sock, fd, event);
    else if (op == EPOLL_CTL_MOD)
        ret = epoll_ctl_mod(epsock->notify, epfd, sock, fd, event);
    else if (op == EPOLL_CTL_DEL)
        ret = epoll_ctl_del(epsock->notify, epfd, sock, fd);
    else
    {
        errno = EINVAL;
        ret = -1;
    }

    exa_write_unlock(&sock->lock);
    exa_write_unlock(&epsock->lock);
    TRACE_RETURN(INT, ret);
    return ret;
}

#define NATIVE_FD_ONLY -256

/* Called from epoll_pwait_spin()
 * Returns true if the event needs to be re-armed */
static bool
epoll_pwait_spin_test_fd(struct exa_notify * restrict no, int fd,
                         struct epoll_event *events, int maxevents,
                         int * restrict nevents)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);
    struct exa_notify_fd * restrict nf = &no->fd_table[fd];
    uint32_t revents = 0;

    LATENCY_START_POINT(11);
    if (!nf->event_pending)
        return false;

    exa_read_lock(&sock->lock);

    if (sock->bypass_state != EXA_BYPASS_ACTIVE)
    {
        exa_read_unlock(&sock->lock);
        return false;
    }

    if ((nf->events & EXA_NOTIFY_IN) && sock->rx_ready)
        revents |= EPOLLIN;
    if ((nf->events & EXA_NOTIFY_OUT) && sock->tx_ready)
        revents |= EPOLLOUT;
    if (sock->eof_ready)
        revents |= EPOLLHUP;

    exa_read_unlock(&sock->lock);

    if (revents == 0)
    {
        /* No event */
        return false;
    }
    else if (*nevents < maxevents)
    {
        /* Deliver event */
        events[*nevents].events = revents;
        events[*nevents].data.u64 = nf->data;
        (*nevents)++;

        LATENCY_END_POINT(11);
        if (nf->events & EXA_NOTIFY_ET)
        {
            /* Clear edge-triggered events that are being delivered
             * Do not re-arm events */
            exa_notify_clear(no, fd);
            return false;
        }
        else
        {
            /* Events are not edge-triggered, must re-arm */
            return true;
        }
    }
    else
    {
        /* Can't deliver event, must re-arm */
        return true;
    }
}

static void
epoll_pwait_spin_check_fd(int fd)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);

    if (sock == NULL || !sock->need_rx_ready_poll)
        return;

    exa_read_lock(&sock->lock);

    /* Check if socket still exists */
    if (sock->state == NULL)
    {
        exa_read_unlock(&sock->lock);
        return;
    }

    exa_lock(&sock->state->rx_lock);
    exa_notify_tcp_read_update(sock);
    exa_unlock(&sock->state->rx_lock);

    exa_read_unlock(&sock->lock);
}

static int
epoll_pwait_spin(int epfd, struct epoll_event *events, int maxevents,
                 int timeout, const sigset_t *sigmask)
{
    struct exa_socket * restrict epsock = exa_socket_get(epfd);
    struct exa_notify * restrict no;
    bool have_native;
    bool have_poll_lock;
    struct timespec end_time = {0, 0};
    unsigned long iters;
    int ret = 0;

    if (maxevents <= 0)
    {
        errno = EINVAL;
        return -1;
    }

    if (epsock == NULL)
        return NATIVE_FD_ONLY;

    exa_read_lock(&epsock->lock);

    no = epsock->notify;
    if (no == NULL)
    {
        exa_read_unlock(&epsock->lock);
        return NATIVE_FD_ONLY;
    }

    exa_lock(&no->fd_cnt.lock);
    if (no->fd_cnt.bypass == 0)
    {
        exa_unlock(&no->fd_cnt.lock);
        exa_read_unlock(&epsock->lock);
        return NATIVE_FD_ONLY;
    }
    have_native = (no->fd_cnt.native != 0);
    exa_unlock(&no->fd_cnt.lock);

    iters = DEFAULT_ITERS;
    signal_received = false;

    have_poll_lock = exa_trylock(&exasock_poll_lock);

    if (have_poll_lock)
        exanic_poll(NULL);

    /* Check if there are any listening sockets ready and if so, add them
     * to the maybe-ready queue
     */
    if (exa_trylock(&no->ep.lock))
    {
        if (no->ep.ref_cnt)
        {
            volatile struct exasock_epoll_state *s = no->ep.state;
            struct exa_socket * restrict sock;
            int next_rd = s->next_read;

            while (next_rd != s->next_write)
            {
                sock = exa_socket_get(s->fd_ready[next_rd]);

                if (!exa_read_trylock(&sock->lock))
                    break;

                if (sock->state == NULL)
                {
                    /* Socket no longer exists */
                    exa_read_unlock(&sock->lock);
                    EXASOCK_EPOLL_FD_READY_IDX_INC(next_rd);
                    continue;
                }

                if (!exa_trylock(&sock->state->rx_lock))
                {
                    exa_read_unlock(&sock->lock);
                    break;
                }
                exa_notify_tcp_read_update(sock);
                exa_unlock(&sock->state->rx_lock);

                exa_read_unlock(&sock->lock);

                EXASOCK_EPOLL_FD_READY_IDX_INC(next_rd);
            }
            s->next_read = next_rd;
        }
        exa_unlock(&no->ep.lock);
    }

    /* Initial check for sockets that are ready */
    {
        int queue[EXA_NOTIFY_MAX_QUEUE];
        int queue_len;
        int nevents = 0;
        int fd;

        exa_lock(&no->queue_lock);

        queue_len = exa_notify_queue_get(no, queue);
        if (queue_len >= 0)
        {
            int i;

            /* Check sockets in the maybe-ready queue */
            for (i = 0; i < queue_len; i++)
            {
                if (no->fd_table[queue[i]].enqueued)
                {
                    if (epoll_pwait_spin_test_fd(no, queue[i], events,
                                                 maxevents, &nevents))
                        exa_notify_queue_reinsert(no, queue[i]);
                    else
                        exa_notify_queue_clear(no, queue[i]);
                }
            }
        }
        else
        {
            /* Check every socket */
            fd = no->list_head;
            while (fd != -1)
            {
                if (no->fd_table[fd].enqueued)
                {
                    if (epoll_pwait_spin_test_fd(no, fd, events, maxevents,
                                                 &nevents))
                        exa_notify_queue_reinsert(no, fd);
                    else
                        exa_notify_queue_clear(no, fd);
                }

                fd = no->fd_table[fd].list_next;
                if (fd == no->list_head)
                    break;
            }
        }

        exa_unlock(&no->queue_lock);

        /* Check for ready native file descriptors or masked signals */
        if ((have_native || sigmask != NULL) && nevents < maxevents)
        {
            ret = LIBC(epoll_pwait, epfd, events + nevents,
                       maxevents - nevents, 0, sigmask);
            if (ret == -1)
            {
                /* Return error code only if there are no events to deliver */
                if (nevents == 0)
                    goto epoll_exit;
            }
            else if (ret > 0)
                nevents += ret;
        }

        if (nevents > 0)
        {
            /* Have events, exit now */
            ret = nevents;
            goto epoll_exit;
        }
    }

    if (timeout == 0)
    {
        /* Exit immediately */
        ret = 0;
        goto epoll_exit;
    }
    else if (timeout > 0)
    {
        /* Calculate when we need to exit the loop */
        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &end_time) == -1)
        {
            ret = -1;
            goto epoll_exit;
        }
        ts_add_ms(&end_time, timeout);
    }

    /* Spin until data is available */
    while (true)
    {
        struct timespec t1, t2, d;
        unsigned long i, j;
        int poll_fd;

        /* Call native epoll if we have any native file descriptors,
         * or if we need to check for masked signals */
        if (have_native || sigmask != NULL)
        {
            ret = LIBC(epoll_pwait, epfd, events, maxevents, 0, sigmask);
            if (ret != 0)
                goto epoll_exit;
        }

        /* Check signals, including those with SA_RESTART set */
        if (signal_received)
        {
            errno = EINTR;
            ret = -1;
            goto epoll_exit;
        }

        /* Try to grab the lock again if we don't already have it */
        if (!have_poll_lock)
            have_poll_lock = exa_trylock(&exasock_poll_lock);

        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t1) == -1)
        {
            ret = -1;
            goto epoll_exit;
        }

        /* Check for timeout */
        if (timeout > 0 && ts_after_eq(&t1, &end_time))
        {
            ret = 0;
            goto epoll_exit;
        }

        poll_fd = no->list_head;
        i = 0;
        while (true)
        {
            if (have_poll_lock)
            {
                struct fd_list* fdl_head = NULL;
                int fdlist_size = 0;
                int expected_fd = -1;

                /* Poll ExaNIC for packets */
                LATENCY_START_POINT(10);
                for (j = 0; j < iters; j++)
                {
                    expected_fd = -1;
                    int fd;

                    fd = exanic_poll(&expected_fd);
                    if (fd < 0 && expected_fd == -1 && fdlist_size == 0)
                        continue;

                    if (fd >= 0)
                    {
                        epoll_pwait_spin_test_fd(no, fd, events, maxevents, &ret);
                        if (ret > 0)
                        {
                            LATENCY_END_POINT(10);
                            goto epoll_exit;
                        }
                        continue;
                    }
                    if (expected_fd >= 0 && no->fd_table[expected_fd].present)
                    {
                        bool added = fdlist_insert(&fdl_head, expected_fd);
                        if (added)
                            fdlist_size++;
                    }

                    if (fdlist_size > 0)
                    {
                        struct fd_list* current;
                        for (current = fdl_head; current; current = current->next)
                        {
                            epoll_pwait_spin_check_fd(current->fd);
                            epoll_pwait_spin_test_fd(no, current->fd, events, maxevents, &ret);
                            if (ret > 0)
                            {
                                fdlist_clear(fdl_head);
                                goto epoll_exit;
                            }
                        }
                    }
                }
                if (fdl_head)
                    fdlist_clear(fdl_head);
            }

            /* we may not have a poll-lock there, but we still need to check the sockets from epoll_fd
               for readiness.  */
            if (poll_fd != -1)
            {
                /* Poll a socket for readiness */
                LATENCY_START_POINT(12);
                epoll_pwait_spin_check_fd(poll_fd);
                epoll_pwait_spin_test_fd(no, poll_fd, events, maxevents, &ret);
                LATENCY_END_POINT(12);
                if (ret > 0)
                    goto epoll_exit;

                /* Go to next socket */
                poll_fd = no->fd_table[poll_fd].list_next;
            }

            if (poll_fd == no->list_head)
            {
                /* Outer loop executes once per fd if have_poll_lock is true
                 * or iters times per fd if have_poll_lock is false */
                if (have_poll_lock || i >= iters)
                    break;
                i++;
            }
        }

        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t2) == -1)
        {
            ret = -1;
            goto epoll_exit;
        }

        ts_sub(&t2, &t1, &d);
        adjust_iters(&d, &iters);

        /* Allow other threads to make changes to the epoll instance */
        exa_read_unlock(&epsock->lock);
        exa_read_lock(&epsock->lock);
        no = epsock->notify;
        if (no == NULL)
        {
            errno = EBADF;
            ret = -1;
            goto epoll_exit;
        }
    }

epoll_exit:
    if (have_poll_lock)
        exa_unlock(&exasock_poll_lock);
    exa_read_unlock(&epsock->lock);
    return ret;
}

__attribute__((visibility("default")))
int
epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    int ret;

    TRACE_CALL("epoll_wait");
    TRACE_ARG(INT, epfd);
    TRACE_FLUSH();

    ret = epoll_pwait_spin(epfd, events, maxevents, timeout, NULL);
    if (ret == NATIVE_FD_ONLY)
        ret = LIBC(epoll_wait, epfd, events, maxevents, timeout);

    TRACE_ARG(EPOLL_EVENT_ARRAY, events, ret);
    TRACE_ARG(INT, maxevents);
    TRACE_LAST_ARG(INT, timeout);
    TRACE_RETURN(INT, ret);

    return ret;
}

__attribute__((visibility("default")))
int
epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout,
            const sigset_t *sigmask)
{
    int ret;

    TRACE_CALL("epoll_wait");
    TRACE_ARG(INT, epfd);
    TRACE_FLUSH();

    ret = epoll_pwait_spin(epfd, events, maxevents, timeout, sigmask);
    if (ret == NATIVE_FD_ONLY)
        ret = LIBC(epoll_pwait, epfd, events, maxevents, timeout, sigmask);

    TRACE_ARG(EPOLL_EVENT_ARRAY, events, ret);
    TRACE_ARG(INT, maxevents);
    TRACE_ARG(INT, timeout);
    TRACE_LAST_ARG(SIGSET_PTR, sigmask);
    TRACE_RETURN(INT, ret);

    return ret;
}
