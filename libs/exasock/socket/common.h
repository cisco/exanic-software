#ifndef SOCKET_COMMON_H_635E3BA536F842F086741FD05818EB70
#define SOCKET_COMMON_H_635E3BA536F842F086741FD05818EB70

/* Socket read lock must be held on entry */
#define do_socket_wait(sock, fd, nonblock, ready_func, ret, ...)        \
    do                                                                  \
    {                                                                   \
        int gen_id = sock->gen_id;                                      \
        assert(exa_read_locked(&sock->lock));                           \
        signal_interrupted = false;                                     \
        while (exa_trylock(&exasock_poll_lock) == 0)                    \
        {                                                               \
            if (ready_func(sock, &ret, __VA_ARGS__))                    \
                goto __do_socket_wait_end;                              \
            if (nonblock)                                               \
            {                                                           \
                errno = EAGAIN;                                         \
                ret = -1;                                               \
                goto __do_socket_wait_end;                              \
            }                                                           \
            if (signal_interrupted)                                     \
            {                                                           \
                errno = EINTR;                                          \
                ret = -1;                                               \
                goto __do_socket_wait_end;                              \
            }                                                           \
            exa_read_unlock(&sock->lock);                               \
            exa_read_lock(&sock->lock);                                 \
            if (gen_id != sock->gen_id)                                 \
            {                                                           \
                errno = EBADF;                                          \
                ret = -1;                                               \
                goto __do_socket_wait_end;                              \
            }                                                           \
        }                                                               \
        if (ready_func(sock, &ret, __VA_ARGS__))                        \
        {                                                               \
            exa_unlock(&exasock_poll_lock);                             \
            goto __do_socket_wait_end;                                  \
        }                                                               \
        while (true)                                                    \
        {                                                               \
            int r;                                                      \
            exa_read_unlock(&sock->lock);                               \
            r = exanic_poll();                                          \
            exa_read_lock(&sock->lock);                                 \
            if (gen_id != sock->gen_id)                                 \
            {                                                           \
                errno = EBADF;                                          \
                ret = -1;                                               \
                goto __do_socket_wait_end;                              \
            }                                                           \
            if (r == fd && ready_func(sock, &ret, __VA_ARGS__))         \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                goto __do_socket_wait_end;                              \
            }                                                           \
            if (nonblock)                                               \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                errno = EAGAIN;                                         \
                ret = -1;                                               \
                goto __do_socket_wait_end;                              \
            }                                                           \
            if (signal_interrupted)                                     \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                errno = EINTR;                                          \
                ret = -1;                                               \
                goto __do_socket_wait_end;                              \
            }                                                           \
        }                                                               \
    __do_socket_wait_end:                                               \
        break;                                                          \
    } while (0)

/* Used for sockets not handled by exanic_poll()
 * Socket read lock must be held on entry */
#define do_socket_poll(sock, fd, nonblock, ready_func, ret, ...)        \
    do                                                                  \
    {                                                                   \
        int gen_id = sock->gen_id;                                      \
        assert(exa_read_locked(&sock->lock));                           \
        signal_interrupted = false;                                     \
        while (exa_trylock(&exasock_poll_lock) == 0)                    \
        {                                                               \
            if (ready_func(sock, &ret, __VA_ARGS__))                    \
                goto __do_socket_poll_end;                              \
            if (nonblock)                                               \
            {                                                           \
                errno = EAGAIN;                                         \
                ret = -1;                                               \
                goto __do_socket_poll_end;                              \
            }                                                           \
            if (signal_interrupted)                                     \
            {                                                           \
                errno = EINTR;                                          \
                ret = -1;                                               \
                goto __do_socket_poll_end;                              \
            }                                                           \
            exa_read_unlock(&sock->lock);                               \
            exa_read_lock(&sock->lock);                                 \
            if (gen_id != sock->gen_id)                                 \
            {                                                           \
                errno = EBADF;                                          \
                ret = -1;                                               \
                goto __do_socket_poll_end;                              \
            }                                                           \
        }                                                               \
        while (true)                                                    \
        {                                                               \
            if (ready_func(sock, &ret, __VA_ARGS__))                    \
                goto __do_socket_poll_unlock_end;                       \
            if (nonblock)                                               \
            {                                                           \
                errno = EAGAIN;                                         \
                ret = -1;                                               \
                goto __do_socket_poll_unlock_end;                       \
            }                                                           \
            if (signal_interrupted)                                     \
            {                                                           \
                errno = EINTR;                                          \
                ret = -1;                                               \
                goto __do_socket_poll_unlock_end;                       \
            }                                                           \
            exa_read_unlock(&sock->lock);                               \
            exanic_poll();                                              \
            exa_read_lock(&sock->lock);                                 \
            if (gen_id != sock->gen_id)                                 \
            {                                                           \
                errno = EBADF;                                          \
                ret = -1;                                               \
                goto __do_socket_poll_unlock_end;                       \
            }                                                           \
        }                                                               \
    __do_socket_poll_unlock_end:                                        \
        exa_unlock(&exasock_poll_lock);                                 \
    __do_socket_poll_end:                                               \
        break;                                                          \
    } while (0)

/* d = a - b */
static inline void
ts_sub(const struct timespec *a, const struct timespec *b, struct timespec *d)
{
    if (a->tv_nsec < b->tv_nsec)
    {
        d->tv_sec = a->tv_sec - b->tv_sec - 1;
        d->tv_nsec = 1000000000 - b->tv_nsec + a->tv_nsec;
    }
    else
    {
        d->tv_sec = a->tv_sec - b->tv_sec;
        d->tv_nsec = a->tv_nsec - b->tv_nsec;
    }
}

/* a += b */
static inline void
ts_add(struct timespec *a, const struct timespec *b)
{
    a->tv_sec += b->tv_sec;
    a->tv_nsec += b->tv_nsec;
    if (a->tv_nsec >= 1000000000)
    {
        a->tv_nsec -= 1000000000;
        a->tv_sec++;
    }
}

/* Add ms milliseconds to ts */
static inline void
ts_add_ms(struct timespec *ts, unsigned long ms)
{
    ts->tv_sec += ms / 1000;
    ts->tv_nsec += (ms % 1000) * 1000000;
    if (ts->tv_nsec >= 1000000000)
    {
        ts->tv_nsec -= 1000000000;
        ts->tv_sec++;
    }
}

/* Return true if a is after or equal to b */
static inline bool
ts_after_eq(const struct timespec *a, const struct timespec *b)
{
    return (a->tv_sec > b->tv_sec) ||
           (a->tv_sec == b->tv_sec && a->tv_nsec >= b->tv_nsec);
}

#endif /* SOCKET_COMMON_H_635E3BA536F842F086741FD05818EB70 */
