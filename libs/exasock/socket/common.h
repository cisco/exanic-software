#ifndef EXASOCK_SOCKET_COMMON_H
#define EXASOCK_SOCKET_COMMON_H

struct fd_list
{
    int    fd;
    struct fd_list* next;
};

static inline bool
ts_vld(const struct timespec *ts)
{
    if (ts->tv_sec < 0)
        return false;

    if ((unsigned long)ts->tv_nsec >= 1000000000) // nanos per second
        return false;

    return true;
}

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

static inline int 
fdlist_search(struct fd_list* head, int fd)
{
    struct fd_list* current = head;
    while(current)
    {
        if (current->fd == fd)
            return true;
        current = current->next;
    }
    return false;
}

static inline void 
fdlist_clear(struct fd_list* head)
{
    struct fd_list* current = head;
    while(current)
    {
        struct fd_list* next = current->next;
        free(current);
        current = next;
    }
}

static inline int 
fdlist_insert(struct fd_list** head, int fd)
{
    if (*head == NULL)
    {
        *head = (struct fd_list*) malloc(sizeof(struct fd_list));
        (*head)->next = NULL;
        (*head)->fd = fd;
        return 1;
    }
    else if (!fdlist_search(*head, fd))
    {
        /* append to the list only when fd is not present there already */
        struct fd_list* new;
        new = (struct fd_list*) malloc(sizeof(struct fd_list));
        new->next = *head;
        new->fd = fd;
        *head = new;
        return 1;
    }
    return 0;
}

/* Socket read lock must be held on entry */
#define do_socket_poll_nonblock(sock, ready_func, ret, ...)             \
    do                                                                  \
    {                                                                   \
        assert(exa_read_locked(&sock->lock));                           \
        if (!ready_func(sock, &ret, __VA_ARGS__))                       \
        {                                                               \
            errno = EAGAIN;                                             \
            ret = -1;                                                   \
        }                                                               \
    } while (0)

/* Socket read lock must be held on entry */
#define do_socket_poll_block(sock, ready_func, ret, ...)                \
    do                                                                  \
    {                                                                   \
        int gen_id = sock->gen_id;                                      \
        assert(exa_read_locked(&sock->lock));                           \
        signal_interrupted = false;                                     \
        while (exa_trylock(&exasock_poll_lock) == 0)                    \
        {                                                               \
            if (ready_func(sock, &ret, __VA_ARGS__))                    \
                goto __do_socket_poll_block_end;                        \
            if (signal_interrupted)                                     \
            {                                                           \
                errno = EINTR;                                          \
                ret = -1;                                               \
                goto __do_socket_poll_block_end;                        \
            }                                                           \
            exa_read_unlock(&sock->lock);                               \
            exa_read_lock(&sock->lock);                                 \
            if (gen_id != sock->gen_id)                                 \
            {                                                           \
                errno = EBADF;                                          \
                ret = -1;                                               \
                goto __do_socket_poll_block_end;                        \
            }                                                           \
        }                                                               \
        while (true)                                                    \
        {                                                               \
            if (ready_func(sock, &ret, __VA_ARGS__))                    \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                goto __do_socket_poll_block_end;                        \
            }                                                           \
            if (signal_interrupted)                                     \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                errno = EINTR;                                          \
                ret = -1;                                               \
                goto __do_socket_poll_block_end;                        \
            }                                                           \
            exa_read_unlock(&sock->lock);                               \
            exanic_poll(NULL);                                          \
            exa_read_lock(&sock->lock);                                 \
            if (gen_id != sock->gen_id)                                 \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                errno = EBADF;                                          \
                ret = -1;                                               \
                goto __do_socket_poll_block_end;                        \
            }                                                           \
        }                                                               \
    __do_socket_poll_block_end:                                         \
        break;                                                          \
    } while (0)

/* Socket read lock must be held on entry */
#define do_socket_poll_timeout(sock, to_val, ready_func, ret, ...)      \
    do                                                                  \
    {                                                                   \
        const struct timespec *to = (const struct timespec *)&to_val;   \
        struct timespec t_limit, t_now;                                 \
        int gen_id = sock->gen_id;                                      \
        assert(exa_read_locked(&sock->lock));                           \
        signal_interrupted = false;                                     \
        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t_limit))            \
        {                                                               \
            ret = -1;                                                   \
            goto __do_socket_poll_timeout_end;                          \
        }                                                               \
        ts_add(&t_limit, to);                                           \
        while (exa_trylock(&exasock_poll_lock) == 0)                    \
        {                                                               \
            if (ready_func(sock, &ret, __VA_ARGS__))                    \
                goto __do_socket_poll_timeout_end;                      \
            if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t_now))          \
            {                                                           \
                ret = -1;                                               \
                goto __do_socket_poll_timeout_end;                      \
            }                                                           \
            if (ts_after_eq(&t_now, &t_limit))                          \
            {                                                           \
                errno = EAGAIN;                                         \
                ret = -1;                                               \
                goto __do_socket_poll_timeout_end;                      \
            }                                                           \
            if (signal_interrupted)                                     \
            {                                                           \
                errno = EINTR;                                          \
                ret = -1;                                               \
                goto __do_socket_poll_timeout_end;                      \
            }                                                           \
            exa_read_unlock(&sock->lock);                               \
            exa_read_lock(&sock->lock);                                 \
            if (gen_id != sock->gen_id)                                 \
            {                                                           \
                errno = EBADF;                                          \
                ret = -1;                                               \
                goto __do_socket_poll_timeout_end;                      \
            }                                                           \
        }                                                               \
        while (true)                                                    \
        {                                                               \
            if (ready_func(sock, &ret, __VA_ARGS__))                    \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                goto __do_socket_poll_timeout_end;                      \
            }                                                           \
            if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t_now))          \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                ret = -1;                                               \
                goto __do_socket_poll_timeout_end;                      \
            }                                                           \
            if (ts_after_eq(&t_now, &t_limit))                          \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                errno = EAGAIN;                                         \
                ret = -1;                                               \
                goto __do_socket_poll_timeout_end;                      \
            }                                                           \
            if (signal_interrupted)                                     \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                errno = EINTR;                                          \
                ret = -1;                                               \
                goto __do_socket_poll_timeout_end;                      \
            }                                                           \
            exa_read_unlock(&sock->lock);                               \
            exanic_poll(NULL);                                          \
            exa_read_lock(&sock->lock);                                 \
            if (gen_id != sock->gen_id)                                 \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                errno = EBADF;                                          \
                ret = -1;                                               \
                goto __do_socket_poll_timeout_end;                      \
            }                                                           \
        }                                                               \
    __do_socket_poll_timeout_end:                                       \
        break;                                                          \
    } while (0)

/* Socket read lock must be held on entry */
#define do_socket_wait_nonblock(sock, fd, ready_func, ret, ...)         \
    do                                                                  \
    {                                                                   \
        int gen_id = sock->gen_id;                                      \
        int r;                                                          \
        assert(exa_read_locked(&sock->lock));                           \
        if (ready_func(sock, &ret, __VA_ARGS__))                        \
            goto __do_socket_wait_nonblock_end;                         \
        if (exa_trylock(&exasock_poll_lock) == 0)                       \
        {                                                               \
            errno = EAGAIN;                                             \
            ret = -1;                                                   \
            goto __do_socket_wait_nonblock_end;                         \
        }                                                               \
        exa_read_unlock(&sock->lock);                                   \
        r = exanic_poll(NULL);                                          \
        exa_read_lock(&sock->lock);                                     \
        exa_unlock(&exasock_poll_lock);                                 \
        if (gen_id != sock->gen_id)                                     \
        {                                                               \
            errno = EBADF;                                              \
            ret = -1;                                                   \
            goto __do_socket_wait_nonblock_end;                         \
        }                                                               \
        if (r == fd && ready_func(sock, &ret, __VA_ARGS__))             \
            goto __do_socket_wait_nonblock_end;                         \
        errno = EAGAIN;                                                 \
        ret = -1;                                                       \
    __do_socket_wait_nonblock_end:                                      \
        break;                                                          \
    } while (0)

/* Socket read lock must be held on entry */
#define do_socket_wait_block(sock, fd, ready_func, ret, ...)            \
    do                                                                  \
    {                                                                   \
        int gen_id = sock->gen_id;                                      \
        assert(exa_read_locked(&sock->lock));                           \
        signal_interrupted = false;                                     \
        while (exa_trylock(&exasock_poll_lock) == 0)                    \
        {                                                               \
            if (ready_func(sock, &ret, __VA_ARGS__))                    \
                goto __do_socket_wait_block_end;                        \
            if (signal_interrupted)                                     \
            {                                                           \
                errno = EINTR;                                          \
                ret = -1;                                               \
                goto __do_socket_wait_block_end;                        \
            }                                                           \
            exa_read_unlock(&sock->lock);                               \
            exa_read_lock(&sock->lock);                                 \
            if (gen_id != sock->gen_id)                                 \
            {                                                           \
                errno = EBADF;                                          \
                ret = -1;                                               \
                goto __do_socket_wait_block_end;                        \
            }                                                           \
        }                                                               \
        if (ready_func(sock, &ret, __VA_ARGS__))                        \
        {                                                               \
            exa_unlock(&exasock_poll_lock);                             \
            goto __do_socket_wait_block_end;                            \
        }                                                               \
        while (true)                                                    \
        {                                                               \
            int r;                                                      \
            exa_read_unlock(&sock->lock);                               \
            r = exanic_poll(NULL);                                      \
            exa_read_lock(&sock->lock);                                 \
            if (gen_id != sock->gen_id)                                 \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                errno = EBADF;                                          \
                ret = -1;                                               \
                goto __do_socket_wait_block_end;                        \
            }                                                           \
            if (r == fd && ready_func(sock, &ret, __VA_ARGS__))         \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                goto __do_socket_wait_block_end;                        \
            }                                                           \
            if (signal_interrupted)                                     \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                errno = EINTR;                                          \
                ret = -1;                                               \
                goto __do_socket_wait_block_end;                        \
            }                                                           \
        }                                                               \
    __do_socket_wait_block_end:                                         \
        break;                                                          \
    } while (0)

/* Socket read lock must be held on entry */
#define do_socket_wait_timeout(sock, fd, to_val, ready_func, ret, ...)  \
    do                                                                  \
    {                                                                   \
        const struct timespec *to = (const struct timespec *)&to_val;   \
        struct timespec t_limit, t_now;                                 \
        int gen_id = sock->gen_id;                                      \
        assert(exa_read_locked(&sock->lock));                           \
        signal_interrupted = false;                                     \
        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t_limit))            \
        {                                                               \
            ret = -1;                                                   \
            goto __do_socket_wait_timeout_end;                          \
        }                                                               \
        ts_add(&t_limit, to);                                           \
        while (exa_trylock(&exasock_poll_lock) == 0)                    \
        {                                                               \
            if (ready_func(sock, &ret, __VA_ARGS__))                    \
                goto __do_socket_wait_timeout_end;                      \
            if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t_now))          \
            {                                                           \
                ret = -1;                                               \
                goto __do_socket_wait_timeout_end;                      \
            }                                                           \
            if (ts_after_eq(&t_now, &t_limit))                          \
            {                                                           \
                errno = EAGAIN;                                         \
                ret = -1;                                               \
                goto __do_socket_wait_timeout_end;                      \
            }                                                           \
            if (signal_interrupted)                                     \
            {                                                           \
                errno = EINTR;                                          \
                ret = -1;                                               \
                goto __do_socket_wait_timeout_end;                      \
            }                                                           \
            exa_read_unlock(&sock->lock);                               \
            exa_read_lock(&sock->lock);                                 \
            if (gen_id != sock->gen_id)                                 \
            {                                                           \
                errno = EBADF;                                          \
                ret = -1;                                               \
                goto __do_socket_wait_timeout_end;                      \
            }                                                           \
        }                                                               \
        if (ready_func(sock, &ret, __VA_ARGS__))                        \
        {                                                               \
            exa_unlock(&exasock_poll_lock);                             \
            goto __do_socket_wait_timeout_end;                          \
        }                                                               \
        while (true)                                                    \
        {                                                               \
            int r;                                                      \
            exa_read_unlock(&sock->lock);                               \
            r = exanic_poll(NULL);                                      \
            exa_read_lock(&sock->lock);                                 \
            if (gen_id != sock->gen_id)                                 \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                errno = EBADF;                                          \
                ret = -1;                                               \
                goto __do_socket_wait_timeout_end;                      \
            }                                                           \
            if (r == fd && ready_func(sock, &ret, __VA_ARGS__))         \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                goto __do_socket_wait_timeout_end;                      \
            }                                                           \
            if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t_now))          \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                ret = -1;                                               \
                goto __do_socket_wait_timeout_end;                      \
            }                                                           \
            if (ts_after_eq(&t_now, &t_limit))                          \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                errno = EAGAIN;                                         \
                ret = -1;                                               \
                goto __do_socket_wait_timeout_end;                      \
            }                                                           \
            if (signal_interrupted)                                     \
            {                                                           \
                exa_unlock(&exasock_poll_lock);                         \
                errno = EINTR;                                          \
                ret = -1;                                               \
                goto __do_socket_wait_timeout_end;                      \
            }                                                           \
        }                                                               \
    __do_socket_wait_timeout_end:                                       \
        break;                                                          \
    } while (0)

/* Socket read lock must be held on entry */
#define do_socket_wait_tcp_nonblock(sock, ready_func, ret, ...)         \
    do                                                                  \
    {                                                                   \
        int gen_id = sock->gen_id;                                      \
        assert(exa_read_locked(&sock->lock));                           \
        if (ready_func(sock, &ret, __VA_ARGS__))                        \
            goto __do_socket_wait_tx_nonblock_end;                      \
        if (exa_trylock(&exasock_poll_lock) == 0)                       \
        {                                                               \
            errno = EAGAIN;                                             \
            ret = -1;                                                   \
            goto __do_socket_wait_tx_nonblock_end;                      \
        }                                                               \
        exa_read_unlock(&sock->lock);                                   \
        exanic_poll(NULL);                                              \
        exa_read_lock(&sock->lock);                                     \
        exa_unlock(&exasock_poll_lock);                                 \
        if (gen_id != sock->gen_id)                                     \
        {                                                               \
            errno = EBADF;                                              \
            ret = -1;                                                   \
            goto __do_socket_wait_tx_nonblock_end;                      \
        }                                                               \
        if (ready_func(sock, &ret, __VA_ARGS__))                        \
            goto __do_socket_wait_tx_nonblock_end;                      \
        errno = EAGAIN;                                                 \
        ret = -1;                                                       \
    __do_socket_wait_tx_nonblock_end:                                   \
        break;                                                          \
    } while (0)

/* Socket read lock must be held on entry */
#define do_socket_wait_tcp_block     do_socket_poll_block

/* Socket read lock must be held on entry */
#define do_socket_wait_tcp_timeout   do_socket_poll_timeout

/* Used for sockets not handled by exanic_poll()
 * Socket read lock must be held on entry */
#define do_socket_poll(sock, nonblock, timeo, ready_func, ret, ...)         \
    do                                                                      \
    {                                                                       \
        if (nonblock)                                                       \
            do_socket_poll_nonblock(sock, ready_func, ret, __VA_ARGS__);    \
        else if (timeo.enabled)                                             \
            do_socket_poll_timeout(sock, timeo.val, ready_func, ret,        \
                                   __VA_ARGS__);                            \
        else                                                                \
            do_socket_poll_block(sock, ready_func, ret, __VA_ARGS__);       \
    } while (0)

/* Used for sockets handled by exanic_poll() and waiting for updates from
 * exanic_poll() only.
 * Socket read lock must be held on entry */
#define do_socket_wait(sock, fd, nonblock, timeo, ready_func, ret, ...)     \
    do                                                                      \
    {                                                                       \
        if (nonblock)                                                       \
            do_socket_wait_nonblock(sock, fd, ready_func, ret, __VA_ARGS__);\
        else if (timeo.enabled)                                             \
            do_socket_wait_timeout(sock, fd, timeo.val, ready_func, ret,    \
                                   __VA_ARGS__);                            \
        else                                                                \
            do_socket_wait_block(sock, fd, ready_func, ret, __VA_ARGS__);   \
    } while (0)

/* Used for TCP sockets handled by exanic_poll() with updates expected either
 * from exanic_poll() or kernel.
 * Socket read lock must be held on entry */
#define do_socket_wait_tcp(sock, nonblock, timeo, ready_func, ret, ...)     \
    do                                                                      \
    {                                                                       \
        if (nonblock)                                                       \
            do_socket_wait_tcp_nonblock(sock, ready_func, ret, __VA_ARGS__);\
        else if (timeo.enabled)                                             \
            do_socket_wait_tcp_timeout(sock, timeo.val, ready_func, ret,    \
                                      __VA_ARGS__);                         \
        else                                                                \
            do_socket_wait_tcp_block(sock, ready_func, ret, __VA_ARGS__);   \
    } while (0)

#endif /* EXASOCK_SOCKET_COMMON_H */
