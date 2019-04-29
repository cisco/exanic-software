#ifndef EXASOCK_SOCKET_TRACE_H
#define EXASOCK_SOCKET_TRACE_H

#ifndef NDEBUG

struct __trace_enum_table
{
    int n;
    const char *s;
};

/* defined in sys.c */
extern pid_t exa_sys_get_tid();

/* thread local trace logging state */
#define __trace_buffer_cap  1024
struct __trace_state
{
    int nest_level;
    const char *curr_func;
    bool in_handler;
    /* whether something is already flushed to trace log */
    bool started;
    /* temporary trace buffer */
    char buffer[__trace_buffer_cap];
    size_t buffer_size;
};
extern struct __trace_state __thread __trace_state;
#define __trace_nest_level  __trace_state.nest_level
#define __trace_curr_func   __trace_state.curr_func
#define __trace_in_handler  __trace_state.in_handler
#define __trace_buffer      __trace_state.buffer
#define __trace_buffer_size __trace_state.buffer_size
#define __trace_started     __trace_state.started

extern int __trace_enabled;

extern struct __trace_enum_table __trace_enum_errno[];
extern struct __trace_enum_table __trace_enum_family[];
extern struct __trace_enum_table __trace_enum_socktype[];
extern struct __trace_enum_table __trace_enum_socktype[];
extern struct __trace_enum_table __trace_enum_sockopt_proto[];
extern struct __trace_enum_table __trace_enum_sockopt[];
extern struct __trace_enum_table __trace_enum_fcntl[];
extern struct __trace_enum_table __trace_enum_ioctl[];
extern struct __trace_enum_table __trace_enum_epoll_op[];
extern struct __trace_enum_table __trace_bits_sock_flags[];
extern struct __trace_enum_table __trace_bits_file_flags[];
extern struct __trace_enum_table __trace_bits_msg_flags[];
extern struct __trace_enum_table __trace_bits_poll_events[];
extern struct __trace_enum_table __trace_bits_sigaction_flags[];
extern struct __trace_enum_table __trace_bits_epoll_flags[];

struct pollfd;

void __trace_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void __trace_flush(bool);
void __trace_print_enum(int n, struct __trace_enum_table *t);
void __trace_print_bits(int n, struct __trace_enum_table *t);
void __trace_print_error(void);
void __trace_print_sockaddr(const struct sockaddr *addr);
void __trace_print_sockopt(const void *optval, socklen_t optlen);
void __trace_print_buf(const void *buf, ssize_t len);
void __trace_print_msghdr(const struct msghdr *msg, ssize_t len);
#ifdef MSG_WAITFORONE
void __trace_print_mmsghdr(const struct mmsghdr *msg, ssize_t len);
#endif
void __trace_print_iovec(const struct iovec *iov, size_t iovcnt, ssize_t len);
void __trace_print_fdset(const fd_set *fds, int nfds);
void __trace_print_select_result(const fd_set *readfds, const fd_set *writefds,
                                 const fd_set *exceptfds, int nfds);
void __trace_print_timeval(const struct timeval *tv);
void __trace_print_timespec(const struct timespec *ts);
void __trace_print_pollfd(const struct pollfd *fds, int nfds, int in, int out);
void __trace_print_sigset(const sigset_t *set);
void __trace_print_sighandler(sighandler_t handler);
void __trace_print_sigaction(const struct sigaction *set);
void __trace_print_epoll_event(const struct epoll_event *e);
void __trace_print_epoll_events(const struct epoll_event *e, int n);

#define __TRACE_ENUM(n, t) __trace_print_enum(n, __trace_enum_##t)
#define __TRACE_BITS(n, t) __trace_print_bits(n, __trace_bits_##t)
#define __TRACE_INT(n) __trace_printf("%d", (n))
#define __TRACE_UNSIGNED(n) __trace_printf("%u", (n))
#define __TRACE_LONG(n) __trace_printf("%ld", (n))
#define __TRACE_INT_PTR(p)                                              \
    do {                                                                \
        if ((p) != NULL) __trace_printf("[%d]", *(p));                  \
        else __trace_printf("NULL");                                    \
    } while (0)
#define __TRACE_PTR(p)                                                  \
    do {                                                                \
        if ((p) != NULL) __trace_printf("%p", (p));                     \
        else __trace_printf("NULL");                                    \
    } while (0)
#define __TRACE_HEX(n) __trace_printf("0x%x", (n))
#define __TRACE_SOCKADDR_PTR(sa) __trace_print_sockaddr(sa)
#define __TRACE_SOCKOPT_PTR(p, l) __trace_print_sockopt((p), (l))
#define __TRACE_BUF(p, l) __trace_print_buf((p), (l))
#define __TRACE_MSG_PTR(m, l) __trace_print_msghdr((m), (l))
#define __TRACE_MMSG_PTR(m, l) __trace_print_mmsghdr((m), (l))
#define __TRACE_IOVEC_ARRAY(v, n, l) __trace_print_iovec((v), (n), (l))
#define __TRACE_FDSET_PTR(s, n) __trace_print_fdset((s), (n))
#define __TRACE_TIMEVAL_PTR(t) __trace_print_timeval(t)
#define __TRACE_TIMESPEC_PTR(t) __trace_print_timespec(t)
#define __TRACE_SELECT_RESULT(r, w, e, n)                               \
    __trace_print_select_result((r), (w), (e), (n))
#define __TRACE_POLLFD_ARRAY(p, n) __trace_print_pollfd((p), (n), 1, 0)
#define __TRACE_POLL_RESULT(p, n) __trace_print_pollfd((p), (n), 0, 1)
#define __TRACE_SIGSET_PTR(s) __trace_print_sigset(s)
#define __TRACE_SIGACTION_PTR(a) __trace_print_sigaction(a)
#define __TRACE_SIGHANDLER(h) __trace_print_sighandler(h)
#define __TRACE_EPOLL_EVENT_PTR(e) __trace_print_epoll_event(e)
#define __TRACE_EPOLL_EVENT_ARRAY(e, n) __trace_print_epoll_events(e, n)

/* Used in TRACE_RETURN() to determine if errno needs to be logged */
#define __ERROR_INT(n) ((n) == -1)
#define __ERROR_LONG(n) ((n) == -1)
#define __ERROR_SIGHANDLER(h) ((h) == SIG_ERR)

#define TRACE_UNFINISHED "<unfinished...>"
#define TRACE_PID        "[pid %d]"
#define TRACE_RESUMED    "<...%s resumed>"

#define TRACE_CALL(n)                                                   \
    do {                                                                \
        __trace_nest_level++;                                           \
        __trace_curr_func = (n);                                        \
        if (__trace_enabled) {                                          \
            __trace_printf("%s(", (n));                                 \
        }                                                               \
        assert(__trace_nest_level == 1);                                \
        assert(!override_disabled);                                     \
    } while (0)

#define TRACE_ARG(t, ...)                                               \
    do {                                                                \
        if (__trace_enabled) {                                          \
            __TRACE_##t(__VA_ARGS__);                                   \
            __trace_printf(", ");                                       \
        }                                                               \
    } while (0)

#define TRACE_LAST_ARG(t, ...)                                          \
    do {                                                                \
        if (__trace_enabled) {                                          \
            __TRACE_##t(__VA_ARGS__);                                   \
            __trace_flush(false);                                       \
        }                                                               \
    } while (0)

#define TRACE_RETURN(t, r)                                              \
    do {                                                                \
        if (__trace_enabled) {                                          \
            __trace_printf(") = ");                                     \
            __TRACE_##t(r);                                             \
            if (__ERROR_##t(r)) {                                       \
                __trace_print_error();                                  \
            }                                                           \
            __trace_printf("\n");                                       \
            __trace_flush(true);                                        \
        }                                                               \
        __trace_nest_level--;                                           \
        __trace_curr_func = NULL;                                       \
        __trace_started = false;                                        \
        assert(!override_disabled);                                     \
    } while (0)

#define TRACE_RETURN_ARG(t, r, ...)                                     \
    do {                                                                \
        if (__trace_enabled) {                                          \
            __trace_printf(") = ");                                     \
            __TRACE_##t(r);                                             \
            if (__ERROR_##t(r)) {                                       \
                __trace_print_error();                                  \
            } else {                                                    \
                __trace_printf(" (");                                   \
                __VA_ARGS__;                                            \
                __trace_printf(")");                                    \
            }                                                           \
            __trace_printf("\n");                                       \
            __trace_flush(true);                                        \
        }                                                               \
        __trace_nest_level--;                                           \
        __trace_curr_func = NULL;                                       \
        __trace_started = false;                                        \
        assert(!override_disabled);                                     \
    } while (0)

#define TRACE_FLUSH()                                                   \
    do {                                                                \
        if (__trace_enabled) {                                          \
            __trace_flush(false);                                       \
        }                                                               \
    } while (0)

#define TRACE_SIGNAL_ENTRY(tmp)                                         \
    do {                                                                \
        if (__trace_enabled && __trace_nest_level != 0) {               \
            __trace_printf(" <interrupted>\n");                         \
            __trace_flush(false);                                       \
        }                                                               \
        tmp = __trace_nest_level;                                       \
        __trace_nest_level = 0;                                         \
        __trace_in_handler = true;                                      \
    } while (0)

#define TRACE_SIGNAL_EXIT(tmp)                                          \
    do {                                                                \
        if (__trace_enabled && tmp != 0) {                              \
            __trace_printf("<restarted> ");                             \
            __trace_flush(false);                                       \
        }                                                               \
        __trace_nest_level = tmp;                                       \
        __trace_in_handler = false;                                     \
    } while (0)

#else

#define TRACE_CALL(...)
#define TRACE_ARG(...)
#define TRACE_LAST_ARG(...)
#define TRACE_RETURN(...)
#define TRACE_RETURN_ARG(...)
#define TRACE_FLUSH()
#define TRACE_SIGNAL_ENTRY(tmp) do { (void)tmp; } while (0)
#define TRACE_SIGNAL_EXIT(tmp)

#endif

#endif /* EXASOCK_SOCKET_TRACE_H */
