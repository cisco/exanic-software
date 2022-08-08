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

#define NATIVE_FD_ONLY -256

static int
pselect_spin(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
             const struct timespec *timeout, const sigset_t *sigmask)
{
    int set_words = (nfds + NFDBITS - 1) / NFDBITS;
    int set_bytes = set_words * sizeof(fd_mask);
    fd_mask bypass_readfds[set_words];
    fd_mask bypass_writefds[set_words];
    fd_mask native_readfds[set_words];
    fd_mask native_writefds[set_words];
    fd_mask native_exceptfds[set_words];
    int fd;
    int bypass_read_count = 0;
    int bypass_write_count = 0;
    int bypass_except_count = 0;
    bool have_native;
    struct timespec end_time;
    unsigned long iters, poll_iters;
    int ready_count;
    int ret = 0;
    bool have_poll_lock;

    memset(bypass_readfds, 0, set_bytes);
    memset(bypass_writefds, 0, set_bytes);
    memset(native_readfds, 0, set_bytes);
    memset(native_writefds, 0, set_bytes);
    memset(native_exceptfds, 0, set_bytes);

    LATENCY_START_POINT(0);
    /* Look for sockets with bypass enabled */
    if (readfds != NULL)
    {
        for (fd = 0; fd < nfds; fd++)
        {
            if (FD_ISSET(fd, readfds))
            {
                struct exa_socket * restrict sock = exa_socket_get(fd);
                if (sock != NULL && sock->bypass_state == EXA_BYPASS_ACTIVE)
                {
                    FD_SET(fd, (fd_set *)bypass_readfds);
                    bypass_read_count++;
                }
                else
                {
                    FD_SET(fd, (fd_set *)native_readfds);
                    have_native = true;
                }
            }
        }
    }

    if (writefds != NULL)
    {
        for (fd = 0; fd < nfds; fd++)
        {
            if (FD_ISSET(fd, writefds))
            {
                struct exa_socket * restrict sock = exa_socket_get(fd);
                if (sock != NULL && sock->bypass_state == EXA_BYPASS_ACTIVE)
                {
                    FD_SET(fd, (fd_set *)bypass_writefds);
                    bypass_write_count++;
                }
                else
                {
                    FD_SET(fd, (fd_set *)native_writefds);
                    have_native = true;
                }
            }
        }
    }

    if (exceptfds != NULL)
    {
        for (fd = 0; fd < nfds; fd++)
        {
            if (FD_ISSET(fd, exceptfds))
            {
                struct exa_socket * restrict sock = exa_socket_get(fd);
                if (sock != NULL && sock->bypass_state == EXA_BYPASS_ACTIVE)
                    bypass_except_count++;
                else
                {
                    FD_SET(fd, (fd_set *)native_exceptfds);
                    have_native = true;
                }
            }
        }
    }

    if (bypass_read_count == 0 &&
        bypass_write_count == 0 &&
        bypass_except_count == 0)
    {
        /* Native sockets only, call libc select() or pselect() directly */
        return NATIVE_FD_ONLY;
    }

    if (readfds)
        memset(readfds, 0, set_bytes);
    if (writefds)
        memset(writefds, 0, set_bytes);
    if (exceptfds)
        memset(exceptfds, 0, set_bytes);

    if (timeout)
    {
        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &end_time) == -1)
            return -1;
        ts_add(&end_time, timeout);
    }

    iters = DEFAULT_ITERS;
    signal_received = false;

    LATENCY_END_POINT(0);
    have_poll_lock = exa_trylock(&exasock_poll_lock);

    /* Initial poll of ExaNICs, no spinning yet */
    if (have_poll_lock)
        exanic_poll(NULL);

    LATENCY_START_POINT(1);
    /* Initial check for sockets that are ready */
    ready_count = 0;
    for (fd = 0; fd < nfds; fd++)
    {
        struct exa_socket * restrict sock = exa_socket_get(fd);

        if (sock == NULL)
            continue;

        exa_read_lock(&sock->lock);

        if (sock->need_rx_ready_poll)
        {
            exa_lock(&sock->state->rx_lock);
            exa_notify_tcp_read_update(sock);
            exa_unlock(&sock->state->rx_lock);
        }

        if (FD_ISSET(fd, (fd_set *)bypass_readfds) && sock->rx_ready)
        {
            FD_SET(fd, readfds);
            ready_count++;
        }

        if (FD_ISSET(fd, (fd_set *)bypass_writefds) && sock->tx_ready)
        {
            FD_SET(fd, writefds);
            ready_count++;
        }

        exa_read_unlock(&sock->lock);
    }
    LATENCY_END_POINT(1);

    if (ready_count > 0)
    {
        if (have_poll_lock)
            exa_unlock(&exasock_poll_lock);
        return ready_count;
    }

    /* Spin until data is available */
    while (true)
    {
        struct timespec t1, t2, d;
        unsigned long i;

        /* Call native select() if we have any native file descriptors,
         * or if we need to check for masked signals. */
        if (have_native || sigmask != NULL)
        {
            struct timespec zero;

            if (readfds)
                memcpy(readfds, native_readfds, set_bytes);
            if (writefds)
                memcpy(writefds, native_writefds, set_bytes);
            if (exceptfds)
                memcpy(exceptfds, native_exceptfds, set_bytes);

            zero.tv_sec = zero.tv_nsec = 0;

            ret = LIBC(pselect, nfds, readfds, writefds, exceptfds, &zero, sigmask);
            if (ret != 0)
                goto select_exit;
        }

        /* Check signals, including those with SA_RESTART set */
        if (signal_received)
        {
            errno = EINTR;
            ret = -1;
            goto select_exit;
        }

        /* Try to grab the lock again if we don't already have it */
        if (!have_poll_lock)
            have_poll_lock = exa_trylock(&exasock_poll_lock);

        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t1) == -1)
        {
            ret = -1;
            goto select_exit;
        }

        /* Check for timeout */
        if (timeout && ts_after_eq(&t1, &end_time))
        {
            ret = 0;
            goto select_exit;
        }

        if (have_poll_lock)
        {
            fd_mask expected_readfds[set_words];
            int e_nfds = 0;
            int expected_fd;
            memset(expected_readfds, 0, set_bytes);

            /* Poll ExaNICs for packets */

            for (i = 0; i < iters; i++)
            {
                struct exa_socket * restrict sock;
                expected_fd = -1;

                LATENCY_START_POINT(3);
                fd = exanic_poll(&expected_fd);
                if (fd < 0 || fd >= nfds)
                {
                    if (expected_fd >= 0 && expected_fd < nfds &&
                        FD_ISSET(expected_fd, (fd_set *)bypass_readfds))
                    {
                        /* Add to expected_readfds, no need to check
                         * with bypass, because expected_fd is set when there is some activity on
                         * one of the exasock listenning sockets as of pending connection
                         * and they may be ready anytime soon */
                        FD_SET(expected_fd, (fd_set*)expected_readfds);
                        e_nfds = expected_fd + 1;
                    }

                    if (e_nfds > 0)
                    {
                        int j;
                        for (j = 0; j < e_nfds; j++)
                        {
                            if (!FD_ISSET(j, (fd_set *)expected_readfds))
                                continue;

                            struct exa_socket * restrict sock = exa_socket_get(j);
                            if (sock == NULL)
                                continue;

                            exa_read_lock(&sock->lock);

                            /* May be sock->state->rx_lock is needed? todo */
                            if (sock->need_rx_ready_poll)
                                exa_notify_tcp_read_update(sock);

                            if (sock->rx_ready)
                            {
                                exa_read_unlock(&sock->lock);
                                FD_SET(j, readfds);
                                ret = 1;
                                goto select_exit;
                            }
                            exa_read_unlock(&sock->lock);
                        }
                    }
                    continue;
                }
                sock = exa_socket_get(fd);

                exa_read_lock(&sock->lock);

                if (FD_ISSET(fd, (fd_set *)bypass_readfds) && sock->rx_ready)
                {
                    exa_read_unlock(&sock->lock);
                    FD_SET(fd, readfds);
                    ret = 1;
                    LATENCY_END_POINT(3);
                    goto select_exit;
                }

                if (FD_ISSET(fd, (fd_set *)bypass_writefds) && sock->tx_ready)
                {
                    exa_read_unlock(&sock->lock);
                    FD_SET(fd, writefds);
                    ret = 1;
                    goto select_exit;
                }

                exa_read_unlock(&sock->lock);
            }
        }

        /* Poll sockets for readiness */
        poll_iters = have_poll_lock ? 1 : iters;
        for (i = 0; i < poll_iters; i++)
        {
            for (fd = 0; fd < nfds; fd++)
            {
                struct exa_socket * restrict sock = exa_socket_get(fd);

                if (sock == NULL)
                    continue;

                exa_read_lock(&sock->lock);

                if (sock->bypass_state != EXA_BYPASS_ACTIVE)
                {
                    exa_read_unlock(&sock->lock);
                    continue;
                }

                if (sock->need_rx_ready_poll)
                {
                    exa_lock(&sock->state->rx_lock);
                    exa_notify_tcp_read_update(sock);
                    exa_unlock(&sock->state->rx_lock);
                }

                if (FD_ISSET(fd, (fd_set *)bypass_readfds) && sock->rx_ready)
                {
                    exa_read_unlock(&sock->lock);
                    FD_SET(fd, readfds);
                    ret = 1;
                    goto select_exit;
                }

                if (FD_ISSET(fd, (fd_set *)bypass_writefds) && sock->tx_ready)
                {
                    exa_read_unlock(&sock->lock);
                    FD_SET(fd, writefds);
                    ret = 1;
                    goto select_exit;
                }

                exa_read_unlock(&sock->lock);
            }
        }

        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t2) == -1)
        {
            ret = -1;
            goto select_exit;
        }

        ts_sub(&t2, &t1, &d);
        adjust_iters(&d, &iters);
    }

select_exit:
    if (have_poll_lock)
        exa_unlock(&exasock_poll_lock);
    return ret;
}

__attribute__((visibility("default")))
int
select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
       struct timeval *timeout)
{
    struct timespec ts;
    int ret;

    TRACE_CALL("select");
    TRACE_ARG(INT, nfds);
    TRACE_ARG(FDSET_PTR, readfds, nfds);
    TRACE_ARG(FDSET_PTR, writefds, nfds);
    TRACE_ARG(FDSET_PTR, exceptfds, nfds);
    TRACE_LAST_ARG(TIMEVAL_PTR, timeout);
    TRACE_FLUSH();

    if (timeout)
    {
        ts.tv_sec = timeout->tv_sec;
        ts.tv_nsec = timeout->tv_usec * 1000;
    }

    ret = pselect_spin(nfds, readfds, writefds, exceptfds,
                       timeout ? &ts : NULL, NULL);

    if (ret == NATIVE_FD_ONLY)
        ret = LIBC(select, nfds, readfds, writefds, exceptfds, timeout);

    TRACE_RETURN_ARG(INT, ret, TRACE_LAST_ARG(SELECT_RESULT,
                     readfds, writefds, exceptfds, nfds));

    return ret;
}

__attribute__((visibility("default")))
int
pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
        const struct timespec *timeout, const sigset_t *sigmask)
{
    int ret;

    TRACE_CALL("pselect");
    TRACE_ARG(INT, nfds);
    TRACE_ARG(FDSET_PTR, readfds, nfds);
    TRACE_ARG(FDSET_PTR, writefds, nfds);
    TRACE_ARG(FDSET_PTR, exceptfds, nfds);
    TRACE_ARG(TIMESPEC_PTR, timeout);
    TRACE_LAST_ARG(SIGSET_PTR, sigmask);
    TRACE_FLUSH();

    ret = pselect_spin(nfds, readfds, writefds, exceptfds, timeout, sigmask);

    if (ret == NATIVE_FD_ONLY)
        ret = LIBC(pselect, nfds, readfds, writefds, exceptfds, timeout,
                   sigmask);

    TRACE_RETURN_ARG(INT, ret, TRACE_LAST_ARG(SELECT_RESULT,
                     readfds, writefds, exceptfds, nfds));

    return ret;
}

static int
ppoll_spin(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout,
           const sigset_t *sigmask)
{
    int bypass_count = 0;
    int native_count = 0;
    int ready_count = 0;
    int fd;
    unsigned long i, j;
    struct timespec end_time;
    unsigned long iters, poll_iters;
    int ret = 0;
    bool have_poll_lock;

    LATENCY_START_POINT(7);
    for (i = 0; i < nfds; i++)
    {
        struct pollfd * restrict pollfd = &fds[i];
        struct exa_socket * restrict sock = exa_socket_get(pollfd->fd);

        if (pollfd->fd < 0)
        {
            pollfd->revents = 0;
            continue;
        }

        if (sock != NULL && sock->bypass_state == EXA_BYPASS_ACTIVE)
        {
            pollfd->revents = 0;
            bypass_count++;
        }
        else
        {
            pollfd->revents = 0;
            native_count++;
        }
    }

    if (bypass_count == 0)
    {
        /* Native sockets only, call libc poll() or ppoll() directly */
        return NATIVE_FD_ONLY;
    }
    LATENCY_END_POINT(7);

    if (timeout)
    {
        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &end_time) == -1)
            return -1;
        ts_add(&end_time, timeout);
    }

    iters = DEFAULT_ITERS;
    signal_received = false;

    have_poll_lock = exa_trylock(&exasock_poll_lock);

    /* Initial poll of ExaNICs, no spinning yet */
    if (have_poll_lock)
        exanic_poll(NULL);

    LATENCY_START_POINT(8);
    /* Initial check for sockets that are ready */
    for (i = 0; i < nfds; i++)
    {
        struct pollfd * restrict pollfd = &fds[i];
        struct exa_socket * restrict sock = exa_socket_get(pollfd->fd);
        short revents = 0;

        if (sock == NULL)
            continue;

        exa_read_lock(&sock->lock);
        if (sock->bypass_state != EXA_BYPASS_ACTIVE)
        {
            exa_read_unlock(&sock->lock);
            continue;
        }

        if (sock->need_rx_ready_poll)
        {
            exa_lock(&sock->state->rx_lock);
            exa_notify_tcp_read_update(sock);
            exa_unlock(&sock->state->rx_lock);
        }

        if (sock->rx_ready)
            revents |= POLLIN | POLLRDNORM;
        if (sock->tx_ready)
            revents |= POLLOUT | POLLWRNORM;
        if (sock->eof_ready)
            revents |= POLLHUP;

        exa_read_unlock(&sock->lock);

        revents &= pollfd->events | POLLHUP | POLLERR;
        if (revents == 0)
            continue;

        pollfd->revents = revents;
        ready_count++;
    }
    LATENCY_END_POINT(8);

    if (ready_count > 0)
    {
        /* Some sockets were ready, return straight away */
        if (have_poll_lock)
            exa_unlock(&exasock_poll_lock);
        return ready_count;
    }

    /* Spin until data is available */
    while (true)
    {
        struct timespec t1, t2, d;
        unsigned long i;

        /* Call native ppoll() if we have any native file descriptors,
         * or if we need to check for masked signals. */
        if (native_count > 0 || sigmask != NULL)
        {
            struct timespec zero;

            zero.tv_sec = zero.tv_nsec = 0;

            ret = LIBC(ppoll, fds, nfds, &zero, sigmask);
            if (ret != 0)
                goto poll_exit;
        }

        /* Check signals, including those with SA_RESTART set */
        if (signal_received)
        {
            errno = EINTR;
            ret = -1;
            goto poll_exit;
        }

        /* Try to grab the lock again if we don't already have it */
        if (!have_poll_lock)
            have_poll_lock = exa_trylock(&exasock_poll_lock);

        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t1) == -1)
        {
            ret = -1;
            goto poll_exit;
        }

        /* Check for timeout */
        if (timeout && ts_after_eq(&t1, &end_time))
        {
            ret = 0;
            goto poll_exit;
        }

        if (have_poll_lock)
        {
			struct fd_list* fdl_head = NULL;
			int fdlist_size = 0;
			int expected_fd = -1;

            /* Poll ExaNICs for packets */
            for (i = 0; i < iters; i++)
            {
                int j;
                expected_fd = -1;
                LATENCY_START_POINT(9);
                fd = exanic_poll(&expected_fd);
                if (fd < 0 && expected_fd == -1 && fdlist_size == 0)
                    continue;

                if (fd >= 0)
                {
                    struct exa_socket * restrict sock = exa_socket_get(fd);
                    short revents = 0;

                    exa_read_lock(&sock->lock);

                    /* May be sock->state->rx_lock is needed? todo */
                    if (sock->need_rx_ready_poll)
                        exa_notify_tcp_read_update(sock);

                    if (sock->rx_ready)
                        revents |= POLLIN | POLLRDNORM;
                    if (sock->tx_ready)
                        revents |= POLLOUT | POLLWRNORM;
                    if (sock->eof_ready)
                        revents |= POLLHUP;

                    exa_read_unlock(&sock->lock);

                    /* FIXME: Need a table for looking up by fd */
                    for (j = 0; j < nfds; j++)
                    {
                        if (fds[j].fd == fd)
                        {
                            revents &= fds[j].events | POLLHUP | POLLERR;
                            if (revents == 0)
                                continue;
                            fds[j].revents = revents;
                            ret = 1;
                            LATENCY_END_POINT(9);
                            goto poll_exit;
                        }
                    }
                }
                if (expected_fd >= 0)
                {
                    for (j = 0; j < nfds; j++)
                    {
                        if (fds[j].fd == expected_fd && (fds[j].events & POLLIN))
                        {
                            int added = fdlist_insert(&fdl_head, expected_fd);
                            if (added)
                                fdlist_size++;
                        }
                    }
                }

                if (fdlist_size > 0)
                {
                    struct fd_list* current;
                    for (current = fdl_head; current; current = current->next)
                    {
                        struct exa_socket * restrict sock = exa_socket_get(current->fd);
                        short revents = 0;

                        exa_read_lock(&sock->lock);

                        /* May be sock->state->rx_lock is needed? todo */
                        if (sock->need_rx_ready_poll)
                            exa_notify_tcp_read_update(sock);

                        if (sock->rx_ready)
                            revents |= POLLIN | POLLRDNORM;

                        exa_read_unlock(&sock->lock);
                        /* FIXME: Need a table for looking up by fd */
                        for (j = 0; j < nfds; j++)
                        {
                            if (fds[j].fd == current->fd)
                            {
                                revents &= fds[j].events;
                                if (revents == 0)
                                    continue;
                                fds[j].revents = revents;
                                ret = 1;
                                goto poll_exit;
                            }
                        }
                    }
                }
            }

            if (fdl_head)
                fdlist_clear(fdl_head);
        }

        /* Poll sockets for readiness */
        poll_iters = have_poll_lock ? 1 : iters;
        for (i = 0; i < poll_iters; i++)
        {
            for (j = 0; j < nfds; j++)
            {
                struct pollfd * restrict pollfd = &fds[j];
                struct exa_socket * restrict sock = exa_socket_get(pollfd->fd);
                short revents = 0;

                if (sock == NULL)
                    continue;

                exa_read_lock(&sock->lock);

                if (sock->bypass_state != EXA_BYPASS_ACTIVE)
                {
                    exa_read_unlock(&sock->lock);
                    continue;
                }

                if (sock->need_rx_ready_poll)
                {
                    exa_lock(&sock->state->rx_lock);
                    exa_notify_tcp_read_update(sock);
                    exa_unlock(&sock->state->rx_lock);
                }

                if (sock->rx_ready)
                    revents |= POLLIN | POLLRDNORM;
                if (sock->tx_ready)
                    revents |= POLLOUT | POLLWRNORM;
                if (sock->eof_ready)
                    revents |= POLLHUP;

                exa_read_unlock(&sock->lock);

                revents &= pollfd->events | POLLHUP | POLLERR;
                if (revents == 0)
                    continue;

                pollfd->revents = revents;
                ret = 1;
                goto poll_exit;
            }
        }

        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t2) == -1)
        {
            ret = -1;
            goto poll_exit;
        }

        ts_sub(&t2, &t1, &d);
        adjust_iters(&d, &iters);
    }

poll_exit:
    if (have_poll_lock)
        exa_unlock(&exasock_poll_lock);
    return ret;
}

static inline int
poll_common(struct pollfd *fds, nfds_t nfds, int timeout)
{
    struct timespec ts;
    int ret;

    if (timeout >= 0)
    {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
    }

    ret = ppoll_spin(fds, nfds, timeout >= 0 ? &ts : NULL, NULL);

    if (ret == NATIVE_FD_ONLY)
        ret = LIBC(poll, fds, nfds, timeout);

    return ret;
}

__attribute__((visibility("default")))
int
poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int ret;

    TRACE_CALL("poll");
    TRACE_ARG(POLLFD_ARRAY, fds, nfds);
    TRACE_ARG(LONG, nfds);
    TRACE_LAST_ARG(INT, timeout);
    TRACE_FLUSH();

    ret = poll_common(fds, nfds, timeout);

    TRACE_RETURN_ARG(INT, ret, TRACE_LAST_ARG(POLL_RESULT, fds, nfds));

    return ret;
}

__attribute__((visibility("default")))
int
__poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int ret;

    TRACE_CALL("__poll");
    TRACE_ARG(POLLFD_ARRAY, fds, nfds);
    TRACE_ARG(LONG, nfds);
    TRACE_LAST_ARG(INT, timeout);
    TRACE_FLUSH();

    ret = poll_common(fds, nfds, timeout);

    TRACE_RETURN_ARG(INT, ret, TRACE_LAST_ARG(POLL_RESULT, fds, nfds));

    return ret;
}

__attribute__((visibility("default")))
int
__poll_chk(struct pollfd *fds, nfds_t nfds, int timeout, size_t fdslen)
{
    if (fdslen / sizeof(*fds) < nfds)
        __chk_fail();
    return poll(fds, nfds, timeout);
}

__attribute__((visibility("default")))
int
ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout,
      const sigset_t *sigmask)
{
    int ret;

    TRACE_CALL("ppoll");
    TRACE_ARG(POLLFD_ARRAY, fds, nfds);
    TRACE_ARG(LONG, nfds);
    TRACE_ARG(TIMESPEC_PTR, timeout);
    TRACE_LAST_ARG(SIGSET_PTR, sigmask);
    TRACE_FLUSH();

    ret = ppoll_spin(fds, nfds, timeout, sigmask);

    if (ret == NATIVE_FD_ONLY)
        ret = LIBC(ppoll, fds, nfds, timeout, sigmask);

    TRACE_RETURN_ARG(INT, ret, TRACE_LAST_ARG(POLL_RESULT, fds, nfds));

    return ret;
}

__attribute__((visibility("default")))
int
__ppoll_chk(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout,
      const sigset_t *sigmask, size_t fdslen)
{
    if (fdslen / sizeof(*fds) < nfds)
        __chk_fail();
    return ppoll(fds, nfds, timeout, sigmask);
}
