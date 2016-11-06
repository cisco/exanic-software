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

int (*libc_socket)(int, int, int);
int (*libc_close)(int);
int (*libc_bind)(int, const struct sockaddr *, socklen_t);
int (*libc_listen)(int, int);
int (*libc_accept)(int, struct sockaddr *, socklen_t *);
int (*libc_accept4)(int, struct sockaddr *, socklen_t *, int);
int (*libc_connect)(int, const struct sockaddr *, socklen_t);
int (*libc_shutdown)(int, int);
int (*libc_fcntl)(int, int, ...);
int (*libc_ioctl)(int d, int request, void *argp);
int (*libc_getsockname)(int, struct sockaddr *, socklen_t *);
int (*libc_getpeername)(int, struct sockaddr *, socklen_t *);
int (*libc_getsockopt)(int, int, int, void *, socklen_t *);
int (*libc_setsockopt)(int, int, int, const void *, socklen_t);
ssize_t (*libc_recv)(int, void *, size_t, int);
ssize_t (*libc_recv_chk)(int, void *, size_t, size_t, int);
ssize_t (*libc_recvfrom)(int, void *, size_t, int, struct sockaddr *,
                         socklen_t *);
ssize_t (*libc_recvfrom_chk)(int, void *, size_t, size_t, int,
                             struct sockaddr *, socklen_t *);
ssize_t (*libc_recvmsg)(int, struct msghdr *, int);
ssize_t (*libc_send)(int, const void *, size_t, int);
ssize_t (*libc_sendto)(int, const void *, size_t, int,
                       const struct sockaddr *, socklen_t);
ssize_t (*libc_sendmsg)(int, const struct msghdr *, int);
ssize_t (*libc_read)(int, void *, size_t);
ssize_t (*libc_readv)(int, const struct iovec *iov, int iovcnt);
ssize_t (*libc_read_chk)(int, void *, size_t, size_t);
ssize_t (*libc_write)(int, const void *, size_t);
ssize_t (*libc_writev)(int, const struct iovec *iov, int iovcnt);
int (*libc_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int (*libc_pselect)(int, fd_set *, fd_set *, fd_set *,
                    const struct timespec *, const sigset_t *);
int (*libc_poll)(struct pollfd *, nfds_t, int);
int (*libc_ppoll)(struct pollfd *, nfds_t, const struct timespec *,
                         const sigset_t *);
sighandler_t (*libc_signal)(int, sighandler_t);
int (*libc_sigaction)(int, const struct sigaction *, struct sigaction *);
int (*libc_siginterrupt)(int, int);
int (*libc_epoll_create)(int);
int (*libc_epoll_create1)(int);
int (*libc_epoll_ctl)(int, int, int, struct epoll_event *);
int (*libc_epoll_wait)(int, struct epoll_event *, int, int);
int (*libc_epoll_pwait)(int, struct epoll_event *, int, int, const sigset_t *);

bool __thread override_disabled = false;

__attribute__((constructor))
void
__exasock_override_init()
{
    libc_socket = dlsym(RTLD_NEXT, "socket");
    libc_close = dlsym(RTLD_NEXT, "close");
    libc_bind = dlsym(RTLD_NEXT, "bind");
    libc_listen = dlsym(RTLD_NEXT, "listen");
    libc_accept = dlsym(RTLD_NEXT, "accept");
    libc_accept4 = dlsym(RTLD_NEXT, "accept4");
    libc_connect = dlsym(RTLD_NEXT, "connect");
    libc_shutdown = dlsym(RTLD_NEXT, "shutdown");
    libc_fcntl = dlsym(RTLD_NEXT, "fcntl");
    libc_ioctl = dlsym(RTLD_NEXT, "ioctl");
    libc_getsockname = dlsym(RTLD_NEXT, "getsockname");
    libc_getpeername = dlsym(RTLD_NEXT, "getpeername");
    libc_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    libc_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    libc_recv = dlsym(RTLD_NEXT, "recv");
    libc_recv_chk = dlsym(RTLD_NEXT, "__recv_chk");
    libc_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    libc_recvfrom_chk = dlsym(RTLD_NEXT, "__recvfrom_chk");
    libc_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    libc_send = dlsym(RTLD_NEXT, "send");
    libc_sendto = dlsym(RTLD_NEXT, "sendto");
    libc_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    libc_read = dlsym(RTLD_NEXT, "read");
    libc_readv = dlsym(RTLD_NEXT, "readv");
    libc_read_chk = dlsym(RTLD_NEXT, "__read_chk");
    libc_write = dlsym(RTLD_NEXT, "write");
    libc_writev = dlsym(RTLD_NEXT, "writev");
    libc_select = dlsym(RTLD_NEXT, "select");
    libc_pselect = dlsym(RTLD_NEXT, "pselect");
    libc_poll = dlsym(RTLD_NEXT, "poll");
    libc_ppoll = dlsym(RTLD_NEXT, "ppoll");
    libc_signal = dlsym(RTLD_NEXT, "signal");
    libc_sigaction = dlsym(RTLD_NEXT, "sigaction");
    libc_siginterrupt = dlsym(RTLD_NEXT, "siginterrupt");
    libc_epoll_create = dlsym(RTLD_NEXT, "epoll_create");
    libc_epoll_create1 = dlsym(RTLD_NEXT, "epoll_create1");
    libc_epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl");
    libc_epoll_wait = dlsym(RTLD_NEXT, "epoll_wait");
    libc_epoll_pwait = dlsym(RTLD_NEXT, "epoll_pwait");
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
