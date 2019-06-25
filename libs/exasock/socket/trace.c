#include "../common.h"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <sched.h>
#include <poll.h>
#include <assert.h>

#include "trace.h"
#include "../lock.h"

#ifndef NDEBUG

int __trace_enabled = 0;
static uint32_t trace_flush_lock;
/* the current tracing thread: initialize with -1 so that the code below doesn't
 * assume that the program was interrupted on first print.
 */
static pid_t __trace_thread = -1;

struct __trace_state __thread __trace_state;

__attribute__((constructor))
void
__trace_init()
{
    if (getenv("EXASOCK_TRACE"))
        __trace_enabled = 1;
}

struct __trace_enum_table __trace_enum_errno[] =
{
    {EPERM, "EPERM"},
    {ENOENT, "ENOENT"},
    {EINTR, "EINTR"},
    {EIO, "EIO"},
    {EBADF, "EBADF"},
    {ECHILD, "ECHILD"},
    {EAGAIN, "EAGAIN"},
    {ENOMEM, "ENOMEM"},
    {EACCES, "EACCES"},
    {EFAULT, "EFAULT"},
    {EBUSY, "EBUSY"},
    {EEXIST, "EEXIST"},
    {ENODEV, "ENODEV"},
    {ENOTDIR, "ENOTDIR"},
    {EISDIR, "EISDIR"},
    {EINVAL, "EINVAL"},
    {ENOSPC, "ENOSPC"},
    {EPIPE, "EPIPE"},
    {ENOTCONN, "ENOTCONN"},
    {EISCONN, "EISCONN"},
    {EOPNOTSUPP, "EOPNOTSUPP"},
    {EINPROGRESS, "EINPROGRESS"},
    {EADDRNOTAVAIL, "EADDRNOTAVAIL"},
    {0, NULL}
};

struct __trace_enum_table __trace_enum_family[] =
{
    {AF_UNIX, "AF_UNIX"},
    {AF_INET, "AF_INET"},
    {AF_INET6, "AF_INET6"},
    {AF_NETLINK, "AF_NETLINK"},
    {AF_PACKET, "AF_PACKET"},
    {0, NULL}
};

struct __trace_enum_table __trace_enum_socktype[] =
{
    {SOCK_STREAM, "SOCK_STREAM"},
    {SOCK_DGRAM, "SOCK_DGRAM"},
    {SOCK_RAW, "SOCK_RAW"},
    {SOCK_SEQPACKET, "SOCK_SEQPACKET"},
    {0, NULL}
};

struct __trace_enum_table __trace_enum_sockopt_proto[] =
{
    {SOL_SOCKET, "SOL_SOCKET"},
    {IPPROTO_IP, "IPPROTO_IP"},
    {IPPROTO_TCP, "IPPROTO_TCP"},
    {IPPROTO_TCP, "IPPROTO_UDP"},
    {0, NULL}
};

struct __trace_enum_table __trace_enum_sockopt[] =
{
    {SO_REUSEADDR, "SO_REUSEADDR"},
    {SO_TYPE, "SO_TYPE"},
    {SO_ERROR, "SO_ERROR"},
    {SO_BROADCAST, "SO_BROADCAST"},
    {SO_SNDBUF, "SO_SNDBUF"},
    {SO_RCVBUF, "SO_RCVBUF"},
    {SO_KEEPALIVE, "SO_KEEPALIVE"},
    {SO_OOBINLINE, "SO_OOBINLINE"},
    {SO_LINGER, "SO_LINGER"},
    {SO_TIMESTAMP, "SO_TIMESTAMP"},
    {SO_BINDTODEVICE, "SO_BINDTODEVICE"},
    {0, NULL}
};

struct __trace_enum_table __trace_enum_fcntl[] =
{
    {F_DUPFD, "F_DUPFD"},
    {F_GETFD, "F_GETFD"},
    {F_SETFD, "F_SETFD"},
    {F_GETFL, "F_GETFL"},
    {F_SETFL, "F_SETFL"},
    {F_SETLK, "F_SETLK"},
    {F_SETLKW, "F_SETLKW"},
    {F_GETLK, "F_GETLK"},
    {F_GETOWN, "F_GETOWN"},
    {F_SETOWN, "F_SETOWN"},
    {F_GETSIG, "F_GETSIG"},
    {F_SETSIG, "F_SETSIG"},
    {F_RDLCK, "F_RDLCK"},
    {F_WRLCK, "F_WRLCK"},
    {F_UNLCK, "F_UNLCK"},
    {F_GETLEASE, "F_GETLEASE"},
    {F_NOTIFY, "F_NOTIFY"},
    {0, NULL}
};

struct __trace_enum_table __trace_enum_ioctl[] =
{
    {FIONREAD, "FIONREAD"},
    {SIOCATMARK, "SIOCATMARK"},
    {TIOCOUTQ, "TIOCOUTQ"},
    {0, NULL}
};

struct __trace_enum_table __trace_enum_epoll_op[] =
{
    {EPOLL_CTL_ADD, "EPOLL_CTL_ADD"},
    {EPOLL_CTL_MOD, "EPOLL_CTL_MOD"},
    {EPOLL_CTL_DEL, "EPOLL_CTL_DEL"},
    {0, NULL}
};

struct __trace_enum_table __trace_bits_sock_flags[] =
{
    {SOCK_NONBLOCK, "SOCK_NONBLOCK"},
    {SOCK_CLOEXEC, "SOCK_CLOEXEC"},
    {0, NULL}
};

struct __trace_enum_table __trace_bits_file_flags[] =
{
    {O_APPEND, "O_APPEND"},
    {O_ASYNC, "O_ASYNC"},
    {O_DIRECT, "O_DIRECT"},
    {O_NOATIME, "O_NOATIME"},
    {O_NONBLOCK, "O_NONBLOCK"},
    {0, NULL}
};

struct __trace_enum_table __trace_bits_msg_flags[] =
{
    {MSG_OOB, "MSG_OOB"},
    {MSG_PEEK, "MSG_PEEK"},
    {MSG_CTRUNC, "MSG_CTRUNC"},
    {MSG_TRUNC, "MSG_TRUNC"},
    {MSG_DONTWAIT, "MSG_DONTWAIT"},
    {MSG_EOR, "MSG_EOR"},
    {MSG_WAITALL, "MSG_WAITALL"},
    {MSG_ERRQUEUE, "MSG_ERRQUEUE"},
    {MSG_NOSIGNAL, "MSG_NOSIGNAL"},
#ifdef MSG_WAITFORONE
    {MSG_WAITFORONE, "MSG_WAITFORONE"},
#endif
    {0, NULL}
};

struct __trace_enum_table __trace_bits_poll_events[] =
{
    {POLLIN, "POLLIN"},
    {POLLOUT, "POLLOUT"},
    {POLLERR, "POLLERR"},
    {POLLHUP, "POLLHUP"},
    {POLLNVAL, "POLLNVAL"},
    {0, NULL}
};

struct __trace_enum_table __trace_bits_sigaction_flags[] =
{
    {SA_NOCLDSTOP, "SA_NOCLDSTOP"},
    {SA_NOCLDWAIT, "SA_NOCLDWAIT"},
    {SA_NODEFER, "SA_NODEFER"},
    {SA_ONSTACK, "SA_ONSTACK"},
    {SA_RESETHAND, "SA_RESETHAND"},
    {SA_RESTART, "SA_RESTART"},
    {SA_SIGINFO, "SA_SIGINFO"},
    {0, NULL}
};

struct __trace_enum_table __trace_bits_epoll_flags[] =
{
    {EPOLL_CLOEXEC, "EPOLL_CLOEXEC"},
    {0, NULL}
};

struct __trace_enum_table __trace_bits_epoll_events[] =
{
    {EPOLLIN, "EPOLLIN"},
    {EPOLLOUT, "EPOLLOUT"},
    {EPOLLRDHUP, "EPOLLRDHUP"},
    {EPOLLPRI, "EPOLLPRI"},
    {EPOLLERR, "EPOLLERR"},
    {EPOLLHUP, "EPOLLHUP"},
    {EPOLLET, "EPOLLET"},
    {EPOLLONESHOT, "EPOLLONESHOT"},
    {0, NULL}
};

static void
__trace_vprintf_immediate(bool returning, const char *fmt, va_list args)
{
    exa_lock(&trace_flush_lock);
    pid_t curr_thread = exa_sys_get_tid(),
          last_thread = __trace_thread;

    /* we've interrupted someone */
    bool interrupting =
        (curr_thread != last_thread && last_thread != -1);
    /* someone interrupted us */
    bool resuming = (curr_thread != last_thread) && __trace_started;
    /* should prefix with thread ID */
    bool print_pid = resuming || interrupting || !__trace_started;

    if (interrupting)
        fprintf(stderr, " "TRACE_UNFINISHED"\n");

    if (print_pid)
        fprintf(stderr, TRACE_PID" ", curr_thread);

    if (resuming)
        fprintf(stderr, TRACE_RESUMED" ",
            __trace_in_handler ? "(sig handler)" :
                                 __trace_curr_func);
    vfprintf(stderr, fmt, args);
    if (returning)
        __trace_thread = -1;
    else
    {
        __trace_thread = curr_thread;
        __trace_started = true;
    }

    exa_unlock(&trace_flush_lock);
    fflush(stderr);
}

static void
__trace_printf_immediate(bool returning, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    __trace_vprintf_immediate(returning, fmt, ap);
    va_end(ap);
}

void
__trace_flush(bool returning)
{
    if (!__trace_buffer_size)
        return;

    __trace_printf_immediate(returning, "%.*s",
                             __trace_buffer_size, __trace_buffer);
    __trace_buffer_size = 0;
}

void
__trace_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    size_t len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    /* string too long to fit in temp buffer?
     * print immediately */
    if (len >= __trace_buffer_cap)
    {
        __trace_flush(false);
        va_start(ap, fmt);
        __trace_vprintf_immediate(false, fmt, ap);
        va_end(ap);
        return;
    }

    if (__trace_buffer_size + len >= __trace_buffer_cap)
        __trace_flush(false);

    va_start(ap, fmt);
    vsnprintf(__trace_buffer + __trace_buffer_size,
              __trace_buffer_cap - __trace_buffer_size - 1,
              fmt, ap);
    va_end(ap);

    __trace_buffer_size += len;
}

void
__trace_print_enum(int n, struct __trace_enum_table *t)
{
    for (; t->s != NULL; t++)
    {
        if (t->n == n)
        {
            __trace_printf("%s", t->s);
            return;
        }
    }
    __trace_printf("%d", n);
}

void
__trace_print_bits(int n, struct __trace_enum_table *t)
{
    int nbits = 0;

    for (; t->s != NULL; t++)
    {
        if ((t->n & n) == t->n)
        {
            n &= ~t->n;
            if (nbits > 0)
                __trace_printf("|");
            __trace_printf("%s", t->s);
            nbits++;
        }
    }

    if (n == 0 && nbits == 0)
        __trace_printf("0");
    else if (n != 0)
    {
        if (nbits > 0)
            __trace_printf("|");
        __trace_printf("0x%x", n);
    }
}

void
__trace_print_error(void)
{
    __trace_printf(" ");
    __trace_print_enum(errno, __trace_enum_errno);
    __trace_printf(" (%s)", strerror(errno));
}

void
__trace_print_sockaddr(const struct sockaddr *addr)
{
    if (addr == NULL)
    {
        __trace_printf("NULL");
        return;
    }

    __trace_printf("{sa_family=");
    __trace_print_enum(addr->sa_family, __trace_enum_family);

    if (addr->sa_family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        char buf[INET_ADDRSTRLEN];

        if (inet_ntop(AF_INET, &sin->sin_addr, buf, INET_ADDRSTRLEN) == NULL)
            buf[0] = '\0';

        __trace_printf(", sin_port=htons(%d), sin_addr=inet_addr(\"%s\")",
                       ntohs(sin->sin_port), buf);
    }

    __trace_printf("}");
}

void
__trace_print_sockopt(const void *optval, socklen_t optlen)
{
    if (optval == NULL)
        __trace_printf("NULL");
    else if (optlen >= sizeof(unsigned int))
        __trace_printf("[%d]", *(unsigned int *)optval);
    else if (optlen >= sizeof(unsigned char))
        __trace_printf("[%d]", *(unsigned char *)optval);
    else
        __trace_printf("%p", optval);
}

void
__trace_print_buf(const void *buf, ssize_t len)
{
    const uint8_t *p = buf;
    ssize_t i;

    if (len >= 0)
    {
        __trace_printf("\"");

        for (i = 0; i < len && i < 32; ++i)
        {
            switch (p[i])
            {
            case '\t': __trace_printf("\\t"); break;
            case '\n': __trace_printf("\\n"); break;
            case '\v': __trace_printf("\\v"); break;
            case '\f': __trace_printf("\\f"); break;
            case '\r': __trace_printf("\\r"); break;
            case '"': __trace_printf("\\\""); break;
            case '\\': __trace_printf("\\\\"); break;
            default:
                if (p[i] >= 32 && p[i] < 127)
                    __trace_printf("%c", p[i]);
                else
                    __trace_printf("\\%o", p[i]);
                break;
            }
        }

        if (i == len)
            __trace_printf("\"");
        else
            __trace_printf("\"...");
    }
    else
        __trace_printf("%p", buf);
}

void
__trace_print_msghdr(const struct msghdr *msg, ssize_t len)
{
    if (msg == NULL)
        __trace_printf("NULL");
    else if (len < 0)
        __trace_printf("%p", msg);
    else
    {
        __trace_printf("{msg_name(%d)=", msg->msg_namelen);
        __trace_print_sockaddr(msg->msg_name);
        __trace_printf(", msg_iov(%ld)=", msg->msg_iovlen);
        __trace_print_iovec(msg->msg_iov, msg->msg_iovlen, len);
        __trace_printf(", msg_control(%ld)=", msg->msg_controllen);
        if (msg->msg_control == NULL)
            __trace_printf("NULL");
        else
            __trace_printf("%p", msg->msg_control);
        __trace_printf(", msg_flags=");
        __trace_print_bits(msg->msg_flags, __trace_bits_msg_flags);
    }
}

#ifdef MSG_WAITFORONE
void
__trace_print_mmsghdr(const struct mmsghdr *msgs, ssize_t len)
{
    unsigned int i = 0;

    if (msgs == NULL)
        __trace_printf("NULL");
    else if (len < 0)
        __trace_printf("%p", msgs);
    else
    {
        __trace_printf("{");
        for (i = 0; i < len; i++)
        {
            __trace_printf("{msg_name(%d)=", msgs[i].msg_hdr.msg_namelen);
            __trace_print_sockaddr(msgs[i].msg_hdr.msg_name);
            __trace_printf(", msg_iov(%ld)=", msgs[i].msg_hdr.msg_iovlen);
            __trace_print_iovec(msgs[i].msg_hdr.msg_iov, msgs[i].msg_hdr.msg_iovlen, msgs[i].msg_len);
            __trace_printf(", msg_control(%ld)=", msgs[i].msg_hdr.msg_controllen);
            if (msgs[i].msg_hdr.msg_control == NULL)
                __trace_printf("NULL");
            else
                __trace_printf("%p", msgs[i].msg_hdr.msg_control);
            __trace_printf(", msg_flags=");
            __trace_print_bits(msgs[i].msg_hdr.msg_flags, __trace_bits_msg_flags);
            __trace_printf(i == len - 1 ? "}" : "}, ");
        }
        __trace_printf("}");
    }
}
#endif

void
__trace_print_iovec(const struct iovec *iov, size_t iovcnt, ssize_t len)
{
    if (len >= 0)
    {
        size_t i, l, pl;

        for (i = 0, l = 0; i < iovcnt; l += iov[i].iov_len, i++)
        {
            if (i > 0)
                __trace_printf(", ");
            __trace_printf("{");
            if (len < l)
                pl = 0;
            else if (len - l < iov[i].iov_len)
                pl = len - l;
            else
                pl = iov[i].iov_len;
            __trace_print_buf(iov[i].iov_base, pl);
            __trace_printf(", %ld}", iov[i].iov_len);
        }
    }
    else
        __trace_printf("%p", iov);
}

void
__trace_print_fdset(const fd_set *fds, int nfds)
{
    if (fds == NULL)
        __trace_printf("NULL");
    else
    {
        int i, n;
        __trace_printf("[");
        for (i = 0, n = 0; i < nfds; i++)
        {
            if (FD_ISSET(i, fds))
            {
                if (n > 0)
                    __trace_printf(" ");
                __trace_printf("%d", i);
                n++;
            }
        }
        __trace_printf("]");
    }
}

static int
fd_set_nonempty(const fd_set *fds, int nfds)
{
    int i;
    for (i = 0; i < nfds; i++)
        if (FD_ISSET(i, fds))
            return 1;
    return 0;
}

void
__trace_print_select_result(const fd_set *readfds, const fd_set *writefds,
                            const fd_set *exceptfds, int nfds)
{
    int n = 0;

    if (readfds != NULL && fd_set_nonempty(readfds, nfds))
    {
        __trace_printf("in ");
        __trace_print_fdset(readfds, nfds);
        n++;
    }
    if (writefds != NULL && fd_set_nonempty(writefds, nfds))
    {
        if (n > 0)
            __trace_printf(", ");
        __trace_printf("out ");
        __trace_print_fdset(writefds, nfds);
        n++;
    }
    if (exceptfds != NULL && fd_set_nonempty(exceptfds, nfds))
    {
        if (n > 0)
            __trace_printf(", ");
        __trace_printf("except ");
        __trace_print_fdset(exceptfds, nfds);
        n++;
    }
}

void
__trace_print_timeval(const struct timeval *tv)
{
    if (tv == NULL)
        __trace_printf("NULL");
    else
        __trace_printf("{%ld, %ld}", tv->tv_sec, tv->tv_usec);
}

void
__trace_print_timespec(const struct timespec *ts)
{
    if (ts == NULL)
        __trace_printf("NULL");
    else
        __trace_printf("{%ld, %ld}", ts->tv_sec, ts->tv_nsec);
}

void
__trace_print_pollfd(const struct pollfd *fds, int nfds, int in, int out)
{
    int i, n;

    if (fds == NULL)
    {
        __trace_printf("NULL");
        return;
    }

    __trace_printf("[");
    for (i = 0, n = 0; i < nfds; i++)
    {
        if (!in && out && fds[i].revents == 0)
            continue;
        if (n > 0)
            __trace_printf(", ");
        __trace_printf("{fd=%d", fds[i].fd);
        if (in)
        {
            __trace_printf(", events=");
            __trace_print_bits(fds[i].events, __trace_bits_poll_events);
        }
        if (out)
        {
            __trace_printf(", revents=");
            __trace_print_bits(fds[i].revents, __trace_bits_poll_events);
        }
        __trace_printf("}");
        n++;
    }
    __trace_printf("]");
}

void
__trace_print_sigset(const sigset_t *set)
{
    int i, nsig = 0;

    if (set == NULL)
    {
        __trace_printf("NULL");
        return;
    }

    __trace_printf("[");
    for (i = 1; i < NSIG; i++)
    {
        if (sigismember(set, i))
        {
            if (nsig > 0)
                __trace_printf(" ");
            __trace_printf("%d", i);
            nsig++;
        }
    }
    __trace_printf("]");
}

void
__trace_print_sighandler(sighandler_t handler)
{
    if (handler == SIG_DFL)
        __trace_printf("SIG_DFL");
    else if (handler == SIG_IGN)
        __trace_printf("SIG_IGN");
    else
        __trace_printf("%p", handler);
}

void
__trace_print_sigaction(const struct sigaction *act)
{
    if (act == NULL)
        __trace_printf("NULL");
    else
    {
        __trace_printf("{");
        if (act->sa_flags & SA_SIGINFO)
            __trace_print_sighandler((sighandler_t)act->sa_sigaction);
        else
            __trace_print_sighandler(act->sa_handler);
        __trace_printf(", ");
        __trace_print_sigset(&act->sa_mask);
        __trace_printf(", ");
        __trace_print_bits(act->sa_flags, __trace_bits_sigaction_flags);
        __trace_printf("}");
    }
}

void
__trace_print_epoll_event(const struct epoll_event *e)
{
    if (e == NULL)
        __trace_printf("NULL");
    else
    {
        __trace_printf("{events=");
        __trace_print_bits(e->events, __trace_bits_epoll_events);
        __trace_printf(", data=0x%lx}", e->data.u64);
    }
}

void
__trace_print_epoll_events(const struct epoll_event *e, int n)
{
    int i;

    if (e == NULL)
        __trace_printf("NULL");
    else if (n < 0)
        __trace_printf("%p", e);
    else
    {
        __trace_printf("[");
        for (i = 0; i < n; i++)
        {
            if (i > 0)
                __trace_printf(", ");
            __trace_print_epoll_event(&e[i]);
        }
        __trace_printf("]");
    }
}

#endif
