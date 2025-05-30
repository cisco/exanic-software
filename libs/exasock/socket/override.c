#include "../common.h"

#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sched.h>
#include <poll.h>

#include "../lock.h"
#include "../rwlock.h"
#include "../structs.h"
#include "../override.h"
#include "override.h"

int (*__libc_socket)(int, int, int);
int (*__libc_close)(int);
int (*__libc_bind)(int, const struct sockaddr *, socklen_t);
int (*__libc_listen)(int, int);
int (*__libc_accept)(int, struct sockaddr *, socklen_t *);
int (*__libc_accept4)(int, struct sockaddr *, socklen_t *, int);
int (*__libc_connect)(int, const struct sockaddr *, socklen_t);
int (*__libc_shutdown)(int, int);
int (*__libc_fcntl)(int, int, ...);
int (*__libc_ioctl)(int d, int request, void *argp);
int (*__libc_getsockname)(int, struct sockaddr *, socklen_t *);
int (*__libc_getpeername)(int, struct sockaddr *, socklen_t *);
int (*__libc_getsockopt)(int, int, int, void *, socklen_t *);
int (*__libc_setsockopt)(int, int, int, const void *, socklen_t);
ssize_t (*__libc_recv)(int, void *, size_t, int);
ssize_t (*__libc_recv_chk)(int, void *, size_t, size_t, int);
ssize_t (*__libc_recvfrom)(int, void *, size_t, int, struct sockaddr *,
                           socklen_t *);
ssize_t (*__libc_recvfrom_chk)(int, void *, size_t, size_t, int,
                               struct sockaddr *, socklen_t *);
ssize_t (*__libc_recvmsg)(int, struct msghdr *, int);
ssize_t (*__libc_send)(int, const void *, size_t, int);
ssize_t (*__libc_sendto)(int, const void *, size_t, int,
                         const struct sockaddr *, socklen_t);
ssize_t (*__libc_sendmsg)(int, const struct msghdr *, int);
int (*__libc_sendmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                       int flags);
ssize_t (*__libc_read)(int, void *, size_t);
ssize_t (*__libc_readv)(int, const struct iovec *iov, int iovcnt);
ssize_t (*__libc_read_chk)(int, void *, size_t, size_t);
ssize_t (*__libc_write)(int, const void *, size_t);
ssize_t (*__libc_writev)(int, const struct iovec *iov, int iovcnt);
int (*__libc_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int (*__libc_pselect)(int, fd_set *, fd_set *, fd_set *,
                      const struct timespec *, const sigset_t *);
int (*__libc_poll)(struct pollfd *, nfds_t, int);
int (*__libc_ppoll)(struct pollfd *, nfds_t, const struct timespec *,
                    const sigset_t *);
sighandler_t (*__libc_signal)(int, sighandler_t);
int (*__libc_sigaction)(int, const struct sigaction *, struct sigaction *);
int (*__libc_siginterrupt)(int, int);
int (*__libc_epoll_create)(int);
int (*__libc_epoll_create1)(int);
int (*__libc_epoll_ctl)(int, int, int, struct epoll_event *);
int (*__libc_epoll_wait)(int, struct epoll_event *, int, int);
int (*__libc_epoll_pwait)(int, struct epoll_event *, int, int,
                          const sigset_t *);
#ifdef HAVE_RECVMMSG
int (*__libc_recvmmsg)(int, struct mmsghdr *, unsigned int, int,
#if RECVMMSG_HAS_CONST_TIMESPEC
                       const
#endif
                       struct timespec *);
#endif

bool __thread override_disabled = false;
bool __override_initialized = false;

__attribute__((constructor))
void
__exasock_override_init()
{
    if (!__override_initialized)
    {
        __libc_socket = (int (*)(int, int, int)) dlsym(RTLD_NEXT, "socket");
        __libc_close = (int (*)(int)) dlsym(RTLD_NEXT, "close");
        __libc_bind = (int (*)(int, const struct sockaddr *, socklen_t))
                          dlsym(RTLD_NEXT, "bind");
        __libc_listen = (int (*)(int, int))
                          dlsym(RTLD_NEXT, "listen");
        __libc_accept = (int (*)(int, struct sockaddr *, socklen_t *))
                          dlsym(RTLD_NEXT, "accept");
        __libc_accept4 = (int (*)(int, struct sockaddr *, socklen_t *, int))
                          dlsym(RTLD_NEXT, "accept4");
        __libc_connect = (int (*)(int, const struct sockaddr *, socklen_t))
                          dlsym(RTLD_NEXT, "connect");
        __libc_shutdown = (int (*)(int, int))
                          dlsym(RTLD_NEXT, "shutdown");
        __libc_fcntl = (int (*)(int, int, ...))
                          dlsym(RTLD_NEXT, "fcntl");
        __libc_ioctl = (int (*)(int d, int request, void *argp))
                          dlsym(RTLD_NEXT, "ioctl");
        __libc_getsockname = (int (*)(int, struct sockaddr *, socklen_t *))
                          dlsym(RTLD_NEXT, "getsockname");
        __libc_getpeername = (int (*)(int, struct sockaddr *, socklen_t *))
                          dlsym(RTLD_NEXT, "getpeername");
        __libc_getsockopt = (int (*)(int, int, int, void *, socklen_t *))
                          dlsym(RTLD_NEXT, "getsockopt");
        __libc_setsockopt = (int (*)(int, int, int, const void *, socklen_t))
                          dlsym(RTLD_NEXT, "setsockopt");
        __libc_recv = (ssize_t (*)(int, void *, size_t, int))
                          dlsym(RTLD_NEXT, "recv");
        __libc_recv_chk = (ssize_t (*)(int, void *, size_t, size_t, int))
                          dlsym(RTLD_NEXT, "__recv_chk");
        __libc_recvfrom = (ssize_t (*)(int, void *, size_t, int,
                          struct sockaddr *, socklen_t *))
                          dlsym(RTLD_NEXT, "recvfrom");
        __libc_recvfrom_chk = (ssize_t (*)(int, void *, size_t, size_t, int,
                          struct sockaddr *, socklen_t *))
                          dlsym(RTLD_NEXT, "__recvfrom_chk");
        __libc_recvmsg = (ssize_t (*)(int, struct msghdr *, int))
                          dlsym(RTLD_NEXT, "recvmsg");
        __libc_send = (ssize_t (*)(int, const void *, size_t, int))
                          dlsym(RTLD_NEXT, "send");
        __libc_sendto = (ssize_t (*)(int, const void *, size_t, int,
                          const struct sockaddr *, socklen_t))
                          dlsym(RTLD_NEXT, "sendto");
        __libc_sendmsg = (ssize_t (*)(int, const struct msghdr *, int))
                          dlsym(RTLD_NEXT, "sendmsg");
        __libc_sendmmsg = (int (*)(int sockfd, struct mmsghdr *,
                          unsigned int , int )) dlsym(RTLD_NEXT, "sendmmsg");
        __libc_read = (ssize_t (*) (int, void *, size_t))
                          dlsym(RTLD_NEXT, "read");
        __libc_readv = (ssize_t (*) (int, const struct iovec *iov, int iovcnt))
                          dlsym(RTLD_NEXT, "readv");
        __libc_read_chk = (ssize_t (*) (int, void *, size_t, size_t))
                          dlsym(RTLD_NEXT, "__read_chk");
        __libc_write = (ssize_t (*) (int, const void *, size_t))
                          dlsym(RTLD_NEXT, "write");
        __libc_writev = (ssize_t (*) (int, const struct iovec *, int))
                          dlsym(RTLD_NEXT, "writev");
        __libc_select = (int (*) (int, fd_set *, fd_set *, fd_set *,
                          struct timeval *)) dlsym(RTLD_NEXT, "select");
        __libc_pselect = (int (*) (int, fd_set *, fd_set *, fd_set *,
                          const struct timespec *, const sigset_t *))
                          dlsym(RTLD_NEXT, "pselect");
        __libc_poll = (int (*) (struct pollfd *, nfds_t, int))
                          dlsym(RTLD_NEXT, "poll");
        __libc_ppoll = (int (*) (struct pollfd *, nfds_t,
                          const struct timespec *,
                          const sigset_t *)) dlsym(RTLD_NEXT, "ppoll");
        __libc_signal = (sighandler_t(*) (int, sighandler_t))
                          dlsym(RTLD_NEXT, "signal");
        __libc_sigaction = (int (*)(int, const struct sigaction *,
                          struct sigaction *)) dlsym(RTLD_NEXT, "sigaction");
        __libc_siginterrupt = (int (*)(int, int)) dlsym(RTLD_NEXT, "siginterrupt");
        __libc_epoll_create = (int (*)(int)) dlsym(RTLD_NEXT, "epoll_create");
        __libc_epoll_create1 = (int (*)(int)) dlsym(RTLD_NEXT, "epoll_create1");
        __libc_epoll_ctl = (int (*)(int, int, int, struct epoll_event *))
                          dlsym(RTLD_NEXT, "epoll_ctl");
        __libc_epoll_wait = (int (*)(int, struct epoll_event *, int, int))
                          dlsym(RTLD_NEXT, "epoll_wait");
        __libc_epoll_pwait = (int (*)(int, struct epoll_event *, int, int,
                          const sigset_t *)) dlsym(RTLD_NEXT, "epoll_pwait");
#ifdef HAVE_RECVMMSG
#if RECVMMSG_HAS_CONST_TIMESPEC
        __libc_recvmmsg = (int (*)(int, struct mmsghdr *, unsigned int, int,
                          const struct timespec *))
                          dlsym(RTLD_NEXT, "recvmmsg");
#else
        __libc_recvmmsg = (int (*)(int, struct mmsghdr *, unsigned int, int,
                          struct timespec *))
                          dlsym(RTLD_NEXT, "recvmmsg");
#endif
#endif

        __override_initialized = true;
    }
}

void
exasock_override_off(void)
{
    assert(!override_disabled);
    override_disabled = true;
}

void
exasock_override_on(void)
{
    assert(override_disabled);
    override_disabled = false;
}

bool
exasock_override_is_off(void)
{
    return override_disabled;
}

ssize_t
exasock_libc_read(int fd, void *buf, size_t count)
{
    return LIBC(read, fd, buf, count);
}
